"""Publication uses an isolated test key; no project signing secret enters tests."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from test_distribution import builder, packaged  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("repository_publisher", ROOT / "tools/publish-repositories.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


@pytest.fixture
def raw(tmp_path):
    directory = tmp_path / "raw"
    directory.mkdir()
    names = ["test.deb", "test.rpm", "test.tar.gz"]
    for name in names:
        (directory / name).write_bytes(b"plan-only fixture")
    (directory / "release.json").write_text(json.dumps({"version": "1.0.0-beta.1", "revision": "a" * 40, "artifacts": names}))
    paths = sorted(directory.iterdir())
    (directory / "SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in paths))
    return directory


def test_plan_does_not_require_or_access_private_key(raw, tmp_path):
    report = publisher.prepare(raw, tmp_path / "new", tmp_path / "missing-key", tmp_path / "missing-public",
                               "A" * 40, "https://packages.example.invalid/project")
    assert report["mode"] == "plan" and not report["uploaded"]
    assert not (tmp_path / "new").exists()


def test_tampering_and_stable_prerelease_are_refused(raw, tmp_path):
    arguments = (raw, tmp_path / "new", tmp_path / "home", tmp_path / "public", "A" * 40,
                 "https://packages.example.invalid/project")
    with pytest.raises(ValueError, match="prerelease"):
        publisher.prepare(*arguments, suite="stable")
    (raw / "test.deb").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="checksum"):
        publisher.prepare(*arguments)
    assert not (tmp_path / "new").exists()


@pytest.mark.skipif(any(not shutil.which(tool) for tool in
                   ("gpg", "gpgv", "rpmbuild", "rpmsign", "rpmkeys", "dpkg-deb", "apt-ftparchive", "createrepo_c")),
                   reason="native signing and repository tools required")
def test_real_release_signatures_and_repository_metadata(packaged, tmp_path):
    source, *_ = packaged
    artifacts = tmp_path / "artifacts"
    builder.build(source, artifacts, ["deb", "rpm"])
    home = tmp_path / "test-key"
    home.mkdir(mode=0o700)
    gpg = ["gpg", "--no-options", "--homedir", str(home), "--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0"]
    password = b"temporary-test-key-only\n"
    try:
        publisher.run(gpg + ["--quick-generate-key", "Repository signature fixture", "rsa2048", "cert", "1d"], password=password)
        info = publisher.run(gpg + ["--with-colons", "--list-keys"]).decode()
        fingerprint = next(line.split(":")[9] for line in info.splitlines() if line.startswith("fpr:"))
        publisher.run(gpg + ["--quick-add-key", fingerprint, "rsa2048", "sign", "1d"], password=password)
        public = tmp_path / "public.asc"
        public.write_bytes(publisher.run(gpg + ["--armor", "--export", fingerprint]))
        output = tmp_path / "publication"
        report = publisher.prepare(artifacts, output, home, public, fingerprint,
                                   "https://packages.example.invalid/project", password=password, apply=True)
        assert report["signed"] and not report["uploaded"]
        keyring = tmp_path / "trusted.gpg"
        publisher.run(["gpg", "--batch", "--dearmor", "--output", str(keyring), str(public)])
        release = output / "signed-release"
        for signature in release.glob("*.asc"):
            publisher.run(["gpgv", "--keyring", str(keyring), str(signature), str(signature.with_suffix(""))])
        publisher.run(["gpgv", "--keyring", str(keyring), str(output / "site/apt/dists/testing/InRelease")])
        publisher.run(["gpgv", "--keyring", str(keyring), str(output / "site/dnf/testing/repodata/repomd.xml.asc"),
                       str(output / "site/dnf/testing/repodata/repomd.xml")])
        for line in (release / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split("  ")
            assert hashlib.sha256((release / name).read_bytes()).hexdigest() == digest
        before = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in release.iterdir()}
        renewed = tmp_path / "renewed"
        renewed_report = publisher.refresh(release, renewed, home, public, fingerprint,
                                          "https://packages.example.invalid/project", password=password, apply=True)
        assert renewed_report["release_bytes_preserved"]
        assert {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (renewed / "signed-release").iterdir()} == before
        publisher.run(["gpgv", "--keyring", str(keyring), str(renewed / "site/apt/dists/testing/InRelease")])
        database = tmp_path / "rpmdb"
        publisher.run(["rpm", "--dbpath", str(database), "--initdb"])
        publisher.run(["rpmkeys", "--dbpath", str(database), "--import", str(public)])
        publisher.run(["rpmkeys", "--dbpath", str(database), "--checksig", str(next(release.glob("*.rpm")))])
        if os.environ.get("OMNI_TEST_DNF") == "1":
            # CI explicitly enables this: Docker/image/network failures fail the job.
            publisher.run(["docker", "run", "--rm", "-v", str(output / "site") + ":/repo:ro",
                "rockylinux/rockylinux:9", "bash", "-ec",
                "printf '[omni-test]\\nname=OMNI signature test\\nbaseurl=file:///repo/dnf/testing\\n"
                "enabled=1\\ngpgcheck=1\\nrepo_gpgcheck=1\\ngpgkey=file:///repo/keys/omni-siem-release.asc\\n' "
                "> /etc/yum.repos.d/omni-test.repo; dnf -y install omni-siem; rpm -q omni-siem"])
        if shutil.which("apt-get"):
            sources = tmp_path / "repository.sources"
            sources.write_text("Types: deb\nURIs: " + (output / "site/apt").as_uri()
                               + "\nSuites: testing\nComponents: main\nArchitectures: amd64\nSigned-By: " + str(public) + "\n")
            lists = tmp_path / "apt-lists"
            lists.mkdir()
            apt = ["apt-get", "-o", "Dir::Etc::sourcelist=" + str(sources), "-o", "Dir::Etc::sourceparts=-",
                   "-o", "Dir::State::lists=" + str(lists), "-o", "Dir::Cache=" + str(tmp_path / "apt-cache"),
                   "-o", "APT::Sandbox::User=" + str(os.getuid()),
                   "-o", "Debug::NoLocking=true", "-o", "APT::Update::Error-Mode=any", "update"]
            publisher.run(apt)
            # A valid signed catalogue must reject a changed package index.
            packages = output / "site/apt/dists/testing/main/binary-amd64/Packages.gz"
            packages.write_bytes(packages.read_bytes() + b"tampered-index")
            shutil.rmtree(lists)
            lists.mkdir()
            rejected_index = subprocess.run(apt, capture_output=True)
            assert rejected_index.returncode != 0
        original = next(release.glob("*.deb"))
        original.write_bytes(original.read_bytes() + b"tampered")
        rejected = subprocess.run(["gpgv", "--keyring", str(keyring), str(original) + ".asc", str(original)], capture_output=True)
        assert rejected.returncode != 0
        assert "gpgcheck=1\nrepo_gpgcheck=1" in (output / "site/omni-siem.repo").read_text()
        assert "Signed-By:" in (output / "site/omni-siem.sources").read_text()
        # Appending an unrelated certificate must never expand the pinned trust root.
        publisher.run(gpg + ["--quick-generate-key", "Unrelated public fixture", "rsa2048", "sign", "1d"], password=password)
        combined = tmp_path / "combined.asc"
        combined.write_bytes(publisher.run(gpg + ["--armor", "--export"]))
        with pytest.raises(ValueError, match="exactly one public certificate"):
            publisher.verify_signed(renewed / "signed-release", combined, fingerprint)
        private = publisher.run(gpg + ["--armor", "--export-secret-keys", fingerprint], password=password)
        mixed = tmp_path / "mixed-key.asc"
        mixed.write_bytes(public.read_bytes() + private)
        with pytest.raises(ValueError, match="private material is forbidden"):
            publisher.verify_signed(renewed / "signed-release", mixed, fingerprint)
        mixed.write_bytes(private)
        with pytest.raises(ValueError, match="private material is forbidden"):
            publisher.verify_signed(renewed / "signed-release", mixed, fingerprint)
    finally:
        subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], capture_output=True)
