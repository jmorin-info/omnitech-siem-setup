#!/usr/bin/env python3
"""Import only the encrypted release signing subkey into an ephemeral CI home."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess


def main(cleanup=False):
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve()
    home = temporary / "omni-release-key"
    if home.parent != temporary or home.is_symlink():
        raise ValueError("invalid private key directory")
    if cleanup:
        if home.is_dir():
            subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"], capture_output=True)
            shutil.rmtree(home)
        return
    if home.exists():
        raise ValueError("private key directory already exists")
    home.mkdir(mode=0o700)
    secret = os.environ.pop("OMNI_RELEASE_SUBKEY", "").encode()
    password = os.environ.pop("OMNI_RELEASE_PASSPHRASE", "").encode()
    # GnuPG validates the actual packet structure; an armor header alone proves nothing.
    if not secret or len(secret) > 32768 or len(password) < 32:
        raise ValueError("encrypted signing subkey and its password are required")
    result = subprocess.run(["gpg", "--no-options", "--homedir", str(home), "--batch", "--import"],
                            input=secret, capture_output=True, timeout=60)
    if result.returncode:
        raise ValueError("signing subkey import failed")
    info = subprocess.run(["gpg", "--no-options", "--homedir", str(home), "--batch", "--with-colons", "--list-secret-keys"],
                          capture_output=True, text=True, check=True, timeout=30).stdout
    records = [line.split(":") for line in info.splitlines()]
    primary = [row for row in records if row[0] == "sec"]
    subkeys = [row for row in records if row[0] == "ssb"]
    policy = json.loads((Path(__file__).resolve().parents[1] / "distribution/keys/policy.json").read_text())
    actual = next(row[9] for row in records if row[0] == "fpr")
    # '#' is the GnuPG stub marker. A real private primary key is forbidden in CI.
    if (actual != policy["fingerprint"] or len(primary) != 1 or len(primary[0]) < 15
            or primary[0][14] != "#" or not any("s" in row[11] and row[14] == "+" for row in subkeys)):
        raise ValueError("CI must receive only the pinned signing subkey, never the private primary key")
    phrase = home / "unlock"
    phrase.write_bytes(password + b"\n")
    phrase.chmod(0o600)
    with open(os.environ["GITHUB_ENV"], "a") as stream:
        stream.write("GNUPGHOME=" + str(home) + "\nOMNI_SIGNING_PASSPHRASE_FILE=" + str(phrase) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()
    try:
        main(args.cleanup)
    except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError):
        raise SystemExit("Release key setup refused. No private diagnostic is printed.")
