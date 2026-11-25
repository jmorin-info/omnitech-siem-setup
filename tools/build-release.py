#!/usr/bin/env python3
"""Build full-project native distribution artifacts from a pinned, clean Git commit."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REMOTE = "https://github.com/jmorin-info/omnitech-siem-setup.git"


def run(args, **kwargs):
    return subprocess.check_output(args, umask=0o022, **kwargs)


def git(root, *args):
    return run(["git", "-C", str(root), *args])


def snapshot(source, destination, revision):
    """Include every tracked file and just this commit/tree, no local Git config/history."""
    destination.mkdir(parents=True)
    destination.chmod(0o755)
    entries = git(source, "ls-tree", "-rz", revision).split(b"\0")
    count = 0
    for entry in filter(None, entries):
        metadata, name = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        relative = name.decode("utf-8")
        if mode not in {"100644", "100755"} or kind != "blob" or ".." in Path(relative).parts or relative.startswith("/"):
            raise ValueError("unsupported tracked entry: " + relative)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git(source, "cat-file", "blob", oid))
        target.chmod(0o755 if mode == "100755" else 0o644)
        count += 1
    git(destination, "init", "--quiet", "--template=", "--initial-branch=main")
    objects = [revision.encode(), *(line.split(b" ", 1)[0] for line in git(source, "rev-list", "--objects", revision + "^{tree}").splitlines())]
    pack = subprocess.run(["git", "-C", str(source), "pack-objects", "--stdout"],
                          input=b"\n".join(objects) + b"\n", capture_output=True, check=True).stdout
    subprocess.run(["git", "-C", str(destination), "index-pack", "--stdin"], input=pack,
                   stdout=subprocess.DEVNULL, check=True, umask=0o022)
    (destination / ".git/shallow").write_text(revision + "\n")
    git(destination, "update-ref", "refs/heads/main", revision)
    git(destination, "read-tree", revision)
    git(destination, "config", "core.autocrlf", "false")
    git(destination, "remote", "add", "origin", REMOTE)
    if git(destination, "status", "--porcelain").strip():
        raise ValueError("distribution snapshot differs from its commit")
    for path in destination.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file() and ".git" in path.relative_to(destination).parts:
            path.chmod(0o644)
    return count


def archive(source, output, prefix, epoch):
    with output.open("wb") as file, gzip.GzipFile(filename="", mode="wb", fileobj=file, mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|") as tar:
            for path in sorted(source.rglob("*")):
                info = tar.gettarinfo(str(path), arcname=prefix + "/" + path.relative_to(source).as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = epoch
                if path.is_file():
                    with path.open("rb") as stream:
                        tar.addfile(info, stream)
                else:
                    tar.addfile(info)


def payload(snapshot_root, root):
    target = root / "usr/share/omni-siem/source"
    shutil.copytree(snapshot_root, target)
    launcher = root / "usr/lib/omni-siem/launcher.py"
    launcher.parent.mkdir(parents=True)
    shutil.copyfile(snapshot_root / "distribution/launcher.py", launcher)
    launcher.chmod(0o755)
    entry = root / "usr/bin/omni-siem"
    entry.parent.mkdir(parents=True)
    entry.write_text('#!/bin/sh\nexec /usr/bin/python3 /usr/lib/omni-siem/launcher.py "$@"\n')
    entry.chmod(0o755)
    docs = root / "usr/share/doc/omni-siem"
    docs.mkdir(parents=True)
    shutil.copyfile(snapshot_root / "LICENSE", docs / "copyright")
    for directory in root.rglob("*"):
        if directory.is_dir():
            directory.chmod(0o755)


def build(source, out, formats):
    if os.name != "posix":
        raise ValueError("build on Linux, with dpkg-deb and/or rpmbuild")
    if git(source, "status", "--porcelain").strip():
        raise ValueError("commit all release files before building; dirty/untracked source is refused")
    revision = git(source, "rev-parse", "HEAD").decode().strip()
    version = json.loads((source / "distribution/version.json").read_text())["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[0-9]+)?", version):
        raise ValueError("invalid release version")
    epoch = int(git(source, "show", "-s", "--format=%ct", revision))
    out.mkdir(parents=True, exist_ok=False)
    artifacts = []
    with tempfile.TemporaryDirectory(prefix="omni-build-") as temporary:
        work = Path(temporary)
        snap = work / "source"
        count = snapshot(source, snap, revision)
        tarball = out / ("omni-siem-" + version + ".tar.gz")
        archive(snap, tarball, "omni-siem-" + version, epoch)
        artifacts.append(tarball)
        root = work / "payload"
        payload(snap, root)
        env = {**os.environ, "SOURCE_DATE_EPOCH": str(epoch)}
        if "deb" in formats:
            control = root / "DEBIAN"
            control.mkdir()
            debversion = version.replace("-rc.", "~rc.")
            (control / "control").write_text(
                "Package: omni-siem\nVersion: " + debversion + "\nArchitecture: all\n"
                "Maintainer: jmorin-info <jmorin-info@users.noreply.github.com>\n"
                "Section: admin\nPriority: optional\nDepends: python3 (>= 3.9), git, bash, ca-certificates\n"
                "Homepage: https://github.com/jmorin-info/omnitech-siem-setup\n"
                "Description: Complete OMNI SIEM project and explicit deployment tools\n"
                " Full source, console, modules, collectors and administration catalogue.\n"
                " Server deployment is explicit and separate from package installation.\n")
            artifact = out / ("omni-siem_" + debversion + "_all.deb")
            subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(artifact)], check=True, env=env)
            artifacts.append(artifact)
            shutil.rmtree(control)
        if "rpm" in formats:
            top = work / "rpm"
            top.mkdir()
            spec = top / "omni-siem.spec"
            base, _, candidate = version.partition("-rc.")
            release = "0." + candidate + ".rc" if candidate else "1"
            spec.write_text(
                "Name: omni-siem\nVersion: " + base + "\nRelease: " + release + "\n"
                "Summary: Complete OMNI SIEM project and administration tools\nLicense: GPL-3.0-only\n"
                "URL: https://github.com/jmorin-info/omnitech-siem-setup\nBuildArch: noarch\n"
                "Requires: python3 >= 3.9, git, bash, ca-certificates\n"
                "%description\nFull project distribution. Native SIEM server provisioning on RPM OSes is not qualified.\n"
                "%install\nmkdir -p %{buildroot}\ncp -a " + str(root) + "/. %{buildroot}/\n"
                "%files\n/usr/bin/omni-siem\n/usr/lib/omni-siem\n/usr/share/omni-siem\n/usr/share/doc/omni-siem\n")
            subprocess.run(["rpmbuild", "-bb", "--define", "_topdir " + str(top), "--define", "_build_id_links none",
                            "--define", "__os_install_post %{nil}", str(spec)], check=True, env=env)
            built = list((top / "RPMS/noarch").glob("*.rpm"))
            if len(built) != 1:
                raise ValueError("RPM artifact missing")
            artifact = out / built[0].name
            shutil.copyfile(built[0], artifact)
            artifacts.append(artifact)
        metadata = out / "release.json"
        metadata.write_text(json.dumps({"version": version, "revision": revision, "tracked_files": count,
                                       "source_date_epoch": epoch, "package_side_effects": "none; explicit site configuration and apply required",
                                       "artifacts": [p.name for p in artifacts]}, indent=2) + "\n")
        artifacts.append(metadata)
        (out / "SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n" for p in artifacts))
    return {"version": version, "revision": revision, "artifacts": [p.name for p in artifacts], "tracked_files": count}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True, help="new directory outside the checkout")
    parser.add_argument("--format", choices=("deb", "rpm"), action="append", dest="formats")
    args = parser.parse_args()
    try:
        source, output = args.source.resolve(), args.output.resolve()
        if source == output or source in output.parents:
            raise ValueError("output must be outside the source checkout")
        print(json.dumps(build(source, output, args.formats or ["deb", "rpm"]), indent=2))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit("Release build refused: " + str(error))
