"""Only a signing subkey, never the private primary key, may enter the CI home."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(not shutil.which("gpg"), reason="GnuPG required")
def test_import_refuses_primary_and_accepts_subkey(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("key_setup", ROOT / "tools/import-release-key.py")
    setup = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(setup)
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    password = b"temporary-signing-test-password-with-32-characters\n"
    base = ["gpg", "--homedir", str(source), "--batch", "--pinentry-mode", "loopback", "--passphrase-fd", "0"]
    def gpg(*args):
        return subprocess.run(base + list(args), input=password, capture_output=True, check=True).stdout
    try:
        gpg("--quick-generate-key", "CI isolated fixture", "rsa2048", "cert", "1d")
        fingerprint = next(line.split(":")[9] for line in gpg("--with-colons", "--list-keys").decode().splitlines() if line.startswith("fpr:"))
        gpg("--quick-add-key", fingerprint, "rsa2048", "sign", "1d")
        policy = tmp_path / "distribution/keys"
        policy.mkdir(parents=True)
        (policy / "policy.json").write_text(json.dumps({"fingerprint":fingerprint}))
        monkeypatch.setattr(setup, "__file__", str(tmp_path / "tools/import-release-key.py"))
        runner = tmp_path / "runner"
        runner.mkdir()
        envfile = tmp_path / "job-env"
        monkeypatch.setenv("RUNNER_TEMP", str(runner))
        monkeypatch.setenv("GITHUB_ENV", str(envfile))
        for export, allowed in (("--export-secret-keys", False), ("--export-secret-subkeys", True)):
            monkeypatch.setenv("OMNI_RELEASE_SUBKEY", gpg("--armor", export, fingerprint).decode())
            monkeypatch.setenv("OMNI_RELEASE_PASSPHRASE", password.decode().strip())
            try:
                if allowed:
                    setup.main()
                    secret_file = runner / "omni-release-key/unlock"
                    assert secret_file.stat().st_mode & 0o777 == 0o600
                    assert "OMNI_SIGNING_PASSPHRASE_FILE=" in envfile.read_text()
                    assert password.decode().strip() not in envfile.read_text()
                else:
                    with pytest.raises(ValueError, match="never the private primary key"):
                        setup.main()
                    assert not envfile.exists()
            finally:
                setup.main(cleanup=True)
            assert not (runner / "omni-release-key").exists()
    finally:
        subprocess.run(["gpgconf", "--homedir", str(source), "--kill", "gpg-agent"], capture_output=True)
