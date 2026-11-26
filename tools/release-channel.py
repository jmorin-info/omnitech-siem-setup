#!/usr/bin/env python3
"""Download an approved release; refuse publication without matching CI/VM proofs."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPO = "jmorin-info/omnitech-siem-setup"


def api(path):
    raw = subprocess.check_output(["gh", "api", "repos/" + REPO + path], stderr=subprocess.DEVNULL, timeout=90)
    return json.loads(raw)


def validate_receipt(receipt, revision):
    if (receipt.get("passed") is not True or receipt.get("distribution_package") is not True
            or receipt.get("adoption", {}).get("passed") is not True
            or receipt.get("integrations", {}).get("passed") is not True
            or receipt.get("source_revision") != revision):
        raise ValueError("full package VM acceptance, integrations and adoption proof required")


def qualified(revision, vm_run):
    # Only GitHub Actions from this repository count; job/check names alone can be forged.
    runs = api("/actions/runs?head_sha=" + revision + "&per_page=100")["workflow_runs"]
    evidence = {}
    for workflow in ("check.yml", "distribution.yml"):
        matches = [r for r in runs if r.get("path") == ".github/workflows/" + workflow
                   and r.get("head_sha") == revision and r.get("conclusion") == "success"
                   and r.get("event") in ("push", "workflow_dispatch")]
        if not matches:
            raise ValueError("successful source and package checks required on the exact release revision")
        evidence[workflow] = matches[0]["id"]
    if not re.fullmatch(r"[0-9]+", str(vm_run)):
        raise ValueError("a successful VM run identifier is required")
    run = api("/actions/runs/" + str(vm_run))
    if (run.get("path") != ".github/workflows/ubuntu-vm.yml" or run.get("head_sha") != revision
            or run.get("conclusion") != "success" or run.get("event") != "workflow_dispatch"):
        raise ValueError("VM proof must qualify this exact source revision")
    artifacts = api("/actions/runs/" + str(vm_run) + "/artifacts")["artifacts"]
    matches = [a for a in artifacts if a["name"] == "ubuntu-2604-acceptance" and not a["expired"]]
    if len(matches) != 1:
        raise ValueError("unique unexpired VM receipt required")
    # gh follows the signed blob redirect without forwarding its API credential.
    archive = subprocess.check_output(["gh", "api", "repos/" + REPO + "/actions/artifacts/"
                                      + str(matches[0]["id"]) + "/zip"], timeout=90)
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        member = z.getinfo("ubuntu-vm-report.json")
        if member.file_size > 5000000:
            raise ValueError("oversized VM receipt")
        receipt = json.loads(z.read(member))
    validate_receipt(receipt, revision)
    evidence.update(vm_run=int(vm_run), vm_report_sha256=hashlib.sha256(z_bytes(receipt)).hexdigest(),
                    stable_qualified=False, server_rpm_qualified=False, ubuntu_2604="experimental")
    return evidence


def z_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def compare_build_archive(directory, archive):
    """Bind draft bytes to the successful build artifact, not just its claimed SHA."""
    local = {p.name:p for p in directory.iterdir()}
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        members = [member for member in z.infolist() if not member.is_dir()]
        if len(members) != len(local) or {m.filename for m in members} != set(local):
            raise ValueError("draft differs from the qualified build inventory")
        for member in members:
            path = local[member.filename]
            if member.file_size != path.stat().st_size:
                raise ValueError("draft differs from the qualified build size")
            with z.open(member) as stream:
                digest = hashlib.sha256()
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            if digest.hexdigest() != hashlib.sha256(path.read_bytes()).hexdigest():
                raise ValueError("draft differs from the qualified build bytes")


def prove_build_bytes(directory, run_id):
    artifacts = api("/actions/runs/" + str(run_id) + "/artifacts")["artifacts"]
    matches = [a for a in artifacts if a["name"] == "omni-siem-distribution" and not a["expired"]]
    if len(matches) != 1 or matches[0].get("size_in_bytes", 0) > 512 * 1024 * 1024:
        raise ValueError("unique unexpired package build artifact required")
    archive = subprocess.check_output(["gh", "api", "repos/" + REPO + "/actions/artifacts/"
                                      + str(matches[0]["id"]) + "/zip"], timeout=180)
    compare_build_archive(directory, archive)


def download(mode, output, vm_run=""):
    policy = json.loads((ROOT / "distribution/repository.json").read_text())
    tag = policy["tag"]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+-(rc|beta)\.[0-9]+", tag):
        raise ValueError("this publication chain is limited to explicit testing prereleases")
    # The tag must be reachable from the current checked-out main, never a feature branch.
    subprocess.run(["git", "fetch", "--no-tags", "origin", "tag", tag], check=True, capture_output=True, timeout=90)
    revision = subprocess.check_output(["git", "rev-list", "-1", tag], text=True).strip()
    subprocess.run(["git", "merge-base", "--is-ancestor", revision, "HEAD"], check=True, capture_output=True)
    releases = api("/releases?per_page=100")
    release = next((r for r in releases if r["tag_name"] == tag), None)
    if not release or (mode == "publish" and not release["draft"]) or (mode == "refresh" and release["draft"]):
        raise ValueError("publish requires a new draft; refresh requires an already published release")
    proofs = qualified(revision, vm_run) if mode == "publish" else None
    if output.exists():
        raise ValueError("download destination must be new")
    output.mkdir(parents=True)
    for asset in release["assets"]:
        name = asset["name"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or asset["size"] > 512 * 1024 * 1024:
            raise ValueError("unexpected release asset")
        # gh writes binary stdout directly to the destination; no shell interpolation.
        with (output / name).open("wb") as target:
            subprocess.run(["gh", "api", "-H", "Accept: application/octet-stream", "repos/" + REPO
                            + "/releases/assets/" + str(asset["id"])], stdout=target,
                           stderr=subprocess.DEVNULL, check=True, timeout=180)
        data = (output / name).read_bytes()
        if len(data) != asset["size"] or asset.get("digest") != "sha256:" + hashlib.sha256(data).hexdigest():
            raise ValueError("downloaded asset differs from GitHub's published digest")
    metadata_path = output / "release.json"
    metadata = json.loads(metadata_path.read_text())
    if metadata.get("revision") != revision or metadata.get("version") != tag[1:]:
        raise ValueError("downloaded source does not match the pinned tag")
    if mode == "publish":
        prove_build_bytes(output, proofs["distribution.yml"])
        # Validate the original manifest before adding signed qualification metadata.
        import importlib.util
        spec = importlib.util.spec_from_file_location("publication", ROOT / "tools/publish-repositories.py")
        publication = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(publication)
        publication.checked_inputs(output)
        metadata["qualification"] = proofs
        metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
        names = metadata["artifacts"] + ["release.json"]
        (output / "SHA256SUMS").write_text("".join(hashlib.sha256((output / n).read_bytes()).hexdigest()
                                                  + "  " + n + "\n" for n in names))
    else:
        if not metadata.get("qualification", {}).get("vm_run"):
            raise ValueError("published signed qualification record required")
    report = {"release_id":release["id"], "tag":tag, "revision":revision, "mode":mode}
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
            for key, value in report.items():
                stream.write(key + "=" + str(value) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("publish", "refresh"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--vm-run", default="")
    args = parser.parse_args()
    try:
        print(json.dumps(download(args.mode, args.output, args.vm_run), indent=2))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile):
        raise SystemExit("Release qualification or download refused. No release or repository was published.")
