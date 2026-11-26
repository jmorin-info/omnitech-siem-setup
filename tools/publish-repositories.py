#!/usr/bin/env python3
"""Prepare signed release files and APT/DNF repositories. Never upload anything."""
from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import gzip
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def run(argv, *, password=None, cwd=None, env=None):
    result = subprocess.run(argv, input=password, capture_output=True, cwd=cwd, env=env, timeout=300)
    if result.returncode:
        # GPG/rpm/pip may print credentials from environment configuration.
        raise ValueError("publication command failed: " + Path(argv[0]).name + " (exit " + str(result.returncode) + ")")
    return result.stdout


def checked_inputs(directory, signed=False):
    if directory.is_symlink():
        raise ValueError("linked artifact directory is refused")
    metadata = json.loads((directory / "release.json").read_text())
    version = metadata.get("version", "")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-(?:rc|beta)\.[0-9]+)?", version):
        raise ValueError("unsupported release version")
    if not re.fullmatch(r"[0-9a-f]{40}", metadata.get("revision", "")):
        raise ValueError("pinned source revision required")
    files = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match[2] in files:
            raise ValueError("invalid or duplicate checksum entry")
        path = directory / match[2]
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != match[1]:
            raise ValueError("artifact checksum mismatch")
        files[path.name] = path
    expected = set(metadata.get("artifacts", [])) | {"release.json"}
    if signed:
        expected |= {name + ".asc" for name in tuple(expected)}
    if expected != set(files) or set(p.name for p in directory.iterdir()) != expected | {"SHA256SUMS"}:
        raise ValueError("artifact manifest is incomplete or contains unexpected files")
    for suffix in (".deb", ".rpm", ".tar.gz"):
        if len([name for name in files if name.endswith(suffix)]) != 1:
            raise ValueError("exactly one artifact of each supported format is required")
    return metadata, files


def verify_public_key(home, public_key, fingerprint):
    info = run(["gpg", "--no-options", "--homedir", str(home), "--batch", "--with-colons", "--show-keys", str(public_key)]).decode()
    records = [line.split(":") for line in info.splitlines()]
    if len([row for row in records if row[0] == "pub"]) != 1:
        raise ValueError("exactly one public certificate is required")
    actual = next((row[9] for row in records if row[0] == "fpr"), "")
    if actual != fingerprint:
        raise ValueError("public key does not match the pinned release fingerprint")


def signing_args(home, fingerprint):
    return ["gpg", "--no-options", "--homedir", str(home), "--batch", "--yes", "--pinentry-mode", "loopback",
            "--passphrase-fd", "0", "--local-user", fingerprint, "--digest-algo", "SHA256", "--armor"]


def release_file(distribution, suite, version, now):
    lines = ["Origin: OMNI SIEM", "Label: OMNI SIEM", "Suite: " + suite, "Codename: " + suite,
             "Version: " + version, "Date: " + email.utils.format_datetime(now, usegmt=True),
             "Valid-Until: " + email.utils.format_datetime(now + dt.timedelta(days=30), usegmt=True),
             "Architectures: amd64", "Components: main", "Description: OMNI SIEM signed project distribution"]
    for algorithm in ("sha256", "sha512"):
        lines.append(algorithm.upper() + ":")
        for path in sorted(distribution.rglob("Packages*")):
            data = path.read_bytes()
            lines.append(" " + hashlib.new(algorithm, data).hexdigest() + " " + str(len(data)) + " " + path.relative_to(distribution).as_posix())
    return ("\n".join(lines) + "\n").encode()


def prepare(source, output, home, public_key, fingerprint, base_url, *, suite="testing", password=None, apply=False):
    source, output, home, public_key = map(Path, (source, output, home, public_key))
    if output.exists() or output.is_symlink() or output.resolve() == source.resolve() or source.resolve() in output.resolve().parents:
        raise ValueError("choose a new output directory outside the input artifacts")
    if not re.fullmatch(r"[A-F0-9]{40,64}", fingerprint):
        raise ValueError("full uppercase public fingerprint required")
    parsed = urlsplit(base_url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or any(c.isspace() for c in base_url)):
        raise ValueError("publication URL must use HTTPS without credentials")
    if suite not in ("testing", "stable"):
        raise ValueError("unsupported repository suite")
    metadata, files = checked_inputs(source)
    if suite == "stable" and "-" in metadata["version"]:
        raise ValueError("a prerelease cannot enter the stable repository")
    report = {"mode": "apply" if apply else "plan", "version": metadata["version"], "revision": metadata["revision"],
              "fingerprint": fingerprint, "base_url": base_url.rstrip("/"), "suite": suite,
              "outputs": ["signed-release", "site/apt", "site/dnf", "site/keys"], "uploaded": False}
    if not apply:
        return report
    for tool in ("gpg", "rpmsign", "apt-ftparchive", "createrepo_c"):
        if not shutil.which(tool):
            raise ValueError("missing publication tool: " + tool)
    if not home.is_dir() or home.is_symlink():
        raise ValueError("private GPG home is missing or linked")
    password = password or b"\n"
    verify_public_key(home, public_key, fingerprint)
    secret = run(["gpg", "--no-options", "--homedir", str(home), "--batch", "--with-colons", "--list-secret-keys", fingerprint]).decode()
    if fingerprint not in secret:
        raise ValueError("matching signing key is not available")
    output.mkdir(parents=True)
    signed, site = output / "signed-release", output / "site"
    signed.mkdir()
    for name, path in files.items():
        shutil.copyfile(path, signed / name)
    args = signing_args(home, fingerprint)
    # Unlock only the signing subkey in the private agent. rpmsign then uses the
    # cached key; its argv never contains a passphrase or private-key material.
    with tempfile.TemporaryDirectory(prefix="omni-sign-") as temporary:
        probe = Path(temporary) / "probe"
        probe.write_bytes(b"OMNI SIEM signing-key availability probe\n")
        run(args + ["--detach-sign", str(probe)], password=password)
    rpm = next(signed.glob("*.rpm"))
    env = {**os.environ, "GNUPGHOME": str(home)}
    run(["rpmsign", "--define", "__gpg " + shutil.which("gpg"),
         "--define", "_gpg_name " + fingerprint, "--define", "_gpg_path " + str(home),
         "--define", "_gpg_digest_algo sha256", "--addsign", str(rpm)], env=env)
    metadata["signing"] = {"fingerprint": fingerprint, "suite": suite, "digest": "SHA256"}
    (signed / "release.json").write_text(json.dumps(metadata, indent=2) + "\n")
    for path in sorted(signed.iterdir()):
        run(args + ["--detach-sign", str(path)], password=password)
    checksums = "".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in sorted(signed.iterdir()))
    (signed / "SHA256SUMS").write_text(checksums)
    run(args + ["--detach-sign", str(signed / "SHA256SUMS")], password=password)
    render_site(signed, site, metadata, home, public_key, fingerprint, base_url, suite, password)
    report.update(signed=True, site_bytes=sum(p.stat().st_size for p in site.rglob("*") if p.is_file()))
    (output / "publication.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def render_site(signed, site, metadata, home, public_key, fingerprint, base_url, suite, password):
    args = signing_args(home, fingerprint)
    keys = site / "keys"
    keys.mkdir(parents=True)
    shutil.copyfile(public_key, keys / "omni-siem-release.asc")
    apt = site / "apt"
    pool = apt / "pool/main/o/omni-siem"
    pool.mkdir(parents=True)
    shutil.copyfile(next(signed.glob("*.deb")), pool / next(signed.glob("*.deb")).name)
    dist = apt / "dists" / suite
    package_dir = dist / "main/binary-amd64"
    package_dir.mkdir(parents=True)
    packages = run(["apt-ftparchive", "packages", "pool"], cwd=apt)
    (package_dir / "Packages").write_bytes(packages)
    (package_dir / "Packages.gz").write_bytes(gzip.compress(packages, mtime=0))
    (dist / "Release").write_bytes(release_file(dist, suite, metadata["version"], dt.datetime.now(dt.timezone.utc)))
    run(args + ["--clearsign", "--output", str(dist / "InRelease"), str(dist / "Release")], password=password)
    dnf = site / "dnf" / suite
    dnf.mkdir(parents=True)
    rpm = next(signed.glob("*.rpm"))
    shutil.copyfile(rpm, dnf / rpm.name)
    run(["createrepo_c", "--checksum", "sha256", str(dnf)])
    run(args + ["--detach-sign", str(dnf / "repodata/repomd.xml")], password=password)
    url = base_url.rstrip("/")
    (site / "omni-siem.repo").write_text(
        "[omni-siem-" + suite + "]\nname=OMNI SIEM " + suite + "\nbaseurl=" + url + "/dnf/" + suite
        + "\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\nsslverify=1\ngpgkey=" + url + "/keys/omni-siem-release.asc\n")
    (site / "omni-siem.sources").write_text("Types: deb\nURIs: " + url + "/apt\nSuites: " + suite
        + "\nComponents: main\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/omni-siem.asc\n")
    (site / "index.html").write_text('<!doctype html><html lang="fr"><meta charset="utf-8"><title>OMNI SIEM — paquets signés</title>'
        '<h1>OMNI SIEM</h1><p>Version ' + html.escape(metadata["version"]) + ' · canal ' + suite
        + '</p><p>Empreinte : <code>' + fingerprint + '</code></p>'
        '<p><a href="keys/omni-siem-release.asc">Clé publique</a> · <a href="omni-siem.sources">Source APT</a>'
        ' · <a href="omni-siem.repo">Dépôt DNF</a></p><p>Importer la clé après vérification indépendante de son empreinte.</p></html>\n')


def verify_signed(source, public_key, fingerprint):
    source, public_key = Path(source), Path(public_key)
    if source.is_symlink() or any(p.is_symlink() for p in source.iterdir()):
        raise ValueError("linked release data is refused")
    with tempfile.TemporaryDirectory(prefix="omni-verify-") as directory:
        home = Path(directory)
        verify_public_key(home, public_key, fingerprint)
        keyring = home / "trusted.gpg"
        run(["gpg", "--batch", "--dearmor", "--output", str(keyring), str(public_key)])
        # Authenticate the checksum manifest before trusting its filenames/data.
        run(["gpgv", "--homedir", str(home), "--keyring", str(keyring),
             str(source / "SHA256SUMS.asc"), str(source / "SHA256SUMS")])
        # SHA256SUMS.asc is outside the checksum manifest itself.
        metadata, files = checked_inputs_signed(source)
        for name in metadata["artifacts"] + ["release.json"]:
            run(["gpgv", "--homedir", str(home), "--keyring", str(keyring),
                 str(source / (name + ".asc")), str(source / name)])
        if metadata.get("signing", {}).get("fingerprint") != fingerprint:
            raise ValueError("release signing identity mismatch")
    return metadata, files


def checked_inputs_signed(source):
    # Reuse the bounded manifest validation without removing or rewriting inputs.
    with tempfile.TemporaryDirectory(prefix="omni-release-check-") as directory:
        view = Path(directory)
        for path in source.iterdir():
            if path.name != "SHA256SUMS.asc":
                # Real copies avoid accepting linked or disappearing input files.
                shutil.copyfile(path, view / path.name)
        metadata, _ = checked_inputs(view, signed=True)
    names = metadata["artifacts"] + ["release.json"]
    files = {name:source / name for name in names + [n + ".asc" for n in names] + ["SHA256SUMS", "SHA256SUMS.asc"]}
    return metadata, files


def refresh(source, output, home, public_key, fingerprint, base_url, *, suite="testing", password=None, apply=False):
    source, output, home, public_key = map(Path, (source, output, home, public_key))
    if output.exists() or output.is_symlink() or source.resolve() in output.resolve().parents:
        raise ValueError("choose a new output directory outside the release")
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("public HTTPS repository URL required")
    if suite not in ("testing", "stable") or not re.fullmatch(r"[A-F0-9]{40,64}", fingerprint):
        raise ValueError("unsupported suite or fingerprint")
    metadata, files = verify_signed(source, public_key, fingerprint)
    if metadata["signing"].get("suite") != suite or (suite == "stable" and "-" in metadata["version"]):
        raise ValueError("release suite mismatch")
    report = {"mode":"apply" if apply else "plan", "version":metadata["version"], "revision":metadata["revision"],
              "fingerprint":fingerprint, "suite":suite, "uploaded":False, "refresh":True}
    if not apply:
        return report
    output.mkdir(parents=True)
    signed = output / "signed-release"
    signed.mkdir()
    for name, path in files.items():
        shutil.copyfile(path, signed / name)
    render_site(signed, output / "site", metadata, home, public_key, fingerprint, base_url, suite, password or b"\n")
    report.update(signed=True, release_bytes_preserved=True)
    (output / "publication.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gpg-home", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, default=ROOT / "distribution/keys/omni-siem-release.asc")
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--suite", choices=("testing", "stable"), default="testing")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--refresh", action="store_true", help="renew catalogues from an already signed release, preserving its bytes")
    args = parser.parse_args()
    try:
        secret_file = os.environ.get("OMNI_SIGNING_PASSPHRASE_FILE")
        password = None
        if args.apply and secret_file:
            path = Path(secret_file)
            if path.is_symlink() or path.stat().st_mode & 0o077:
                raise ValueError("passphrase file must be private and not linked")
            password = path.read_bytes().rstrip(b"\r\n") + b"\n"
        operation = refresh if args.refresh else prepare
        print(json.dumps(operation(args.artifacts, args.output, args.gpg_home, args.public_key, args.fingerprint,
                                 args.base_url, suite=args.suite, password=password, apply=args.apply), indent=2))
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit("Signed publication refused; verify artifacts, private key access and repository tools. No upload performed.")
