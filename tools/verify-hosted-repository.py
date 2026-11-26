#!/usr/bin/env python3
"""Verify hosted bytes against the signed build before publishing a new prerelease."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def verify(site, release):
    policy = json.loads((ROOT / "distribution/repository.json").read_text())
    url = policy["base_url"]
    files = [p for p in site.rglob("*") if p.is_file()]
    for attempt in range(8):
        try:
            for path in files:
                request = urllib.request.Request(url + "/" + path.relative_to(site).as_posix(),
                                                 headers={"Cache-Control":"no-cache"})
                with urllib.request.urlopen(request, timeout=30) as response:
                    digest = hashlib.sha256()
                    size = 0
                    while chunk := response.read(1024 * 1024):
                        size += len(chunk)
                        if size > path.stat().st_size:
                            raise ValueError("hosted file size mismatch")
                        digest.update(chunk)
                if size != path.stat().st_size or digest.hexdigest() != hashlib.sha256(path.read_bytes()).hexdigest():
                    raise ValueError("hosted file digest mismatch")
            break
        except (OSError, ValueError, urllib.error.URLError):
            if attempt == 7:
                raise ValueError("hosted repository differs from the signed build") from None
            time.sleep(10)
    endpoint = "repos/jmorin-info/omnitech-siem-setup/releases/" + os.environ["RELEASE_ID"]
    remote = json.loads(subprocess.check_output(["gh", "api", endpoint], timeout=60))
    expected = {p.name:p for p in release.iterdir()}
    assets = {a["name"]:a for a in remote["assets"]}
    if set(expected) != set(assets):
        raise ValueError("release assets differ from the signed manifest")
    for name, path in expected.items():
        if (assets[name].get("state") != "uploaded" or assets[name]["size"] != path.stat().st_size
                or assets[name].get("digest") != "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()):
            raise ValueError("release asset digest mismatch")
    if os.environ["MODE"] == "publish":
        if not remote["draft"] or remote["tag_name"] != policy["tag"]:
            raise ValueError("only the configured unpublished draft can be published")
        data = {"draft":False, "prerelease":True, "tag_name":policy["tag"],
                "target_commitish":os.environ["RELEASE_REVISION"]}
        subprocess.run(["gh", "api", "--method", "PATCH", endpoint, "--input", "-"],
                       input=json.dumps(data), text=True, capture_output=True, check=True, timeout=60)
    return {"hosted_files_verified":len(files), "release_assets_verified":len(assets),
            "tag":policy["tag"], "stable":False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, required=True)
    parser.add_argument("--release", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.site, args.release), indent=2))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        raise SystemExit("Hosted verification refused; no release was published by this step.")
