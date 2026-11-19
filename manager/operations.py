"""Fixed administration commands, private journals and redacted terminal output."""
from __future__ import annotations
import datetime as dt
import base64
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import uuid
from urllib.parse import quote

from .configuration import parse
from .modules import build_module_command
from .storage import lock, write_private

ACTIONS = {
    "install_plan": {"triage"}, "install_apply": {"triage"}, "install_resume": {"triage"},
    "update_fetch": {"ref"}, "update_plan": {"target"}, "update_stage": {"target"},
    "update_apply": {"target"}, "update_rollback": {"transaction"}, "update_recover": {"transaction"},
    "update_status": set(), "console_publish": set(),
    "module_plan": {"module", "api", "port", "bind", "ca", "api_token"},
    "module_install": {"module", "api", "port", "bind", "ca", "api_token"},
    "module_uninstall": {"module", "api", "installation_id", "ca", "api_token"},
    "module_uninstall_plan": {"module", "api", "installation_id", "ca", "api_token"},
}
WRITES = {"install_apply", "install_resume", "update_apply", "update_rollback", "update_recover", "console_publish", "module_install", "module_uninstall"}


def redact(text, secrets):
    variants = {str(s) for s in secrets if s}
    variants.update(quote(secret, safe="") for secret in list(variants))
    variants.update(base64.b64encode((secret + ":token").encode()).decode() for secret in list(variants))
    for secret in sorted(variants, key=len, reverse=True):
        text = text.replace(secret, "[masqué]")
    text = re.sub(r"(?i)(authorization\s*:\s*(?:basic|bearer)\s+)\S+", r"\1[masqué]", text)
    text = re.sub(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+:[^/@\s]+@", r"\1[masqué]@", text)
    # Child tools may emit terminal control sequences; journals are plain text.
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = "".join(c for c in text if ord(c) >= 32 or c == "\t")
    return text


class Manager:
    def __init__(self, source: Path, state: Path, updater_state: Path | None = None):
        self.source, self.state = Path(source).resolve(), Path(state).resolve()
        if self.source == self.state or self.source in self.state.parents or self.state in self.source.parents:
            raise ValueError("Le code et les états doivent être dans des répertoires séparés.")
        self.updater_state = Path(updater_state or "/var/lib/omni-siem-updater").resolve()
        if self.source == self.updater_state or self.source in self.updater_state.parents or self.updater_state in self.source.parents:
            raise ValueError("L'état des mises à jour doit rester hors du code.")

    def command(self, action, params):
        if action not in ACTIONS or not isinstance(params, dict) or set(params) - ACTIONS[action]:
            raise ValueError("Action ou paramètres non autorisés.")
        argv, env = [sys.executable], {}
        if action.startswith("install_"):
            if not isinstance(params.get("triage", False), bool):
                raise ValueError("Option triage invalide.")
            argv += [str(self.source / "tools/install-platform.py"), "--plan" if action == "install_plan" else "--apply"]
            if action == "install_resume":
                argv.append("--resume")
            if params.get("triage"):
                argv += ["--with", "triage"]
        elif action.startswith("update_"):
            name = {"update_apply": "apply-code"}.get(action, action.removeprefix("update_"))
            argv += [str(self.source / "tools/omni-update.py"), name,
                     "--source", str(self.source), "--state-dir", str(self.updater_state)]
            if action == "update_fetch":
                ref = params.get("ref", "main")
                if not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,200}", ref):
                    raise ValueError("Référence Git invalide.")
                argv += ["--ref", ref]
            if action in ("update_plan", "update_stage", "update_apply"):
                target = params.get("target", "")
                if not isinstance(target, str) or not re.fullmatch(r"[a-f0-9]{40}", target):
                    raise ValueError("Un SHA Git complet de 40 caractères est requis.")
                argv += ["--target", target]
            if action in ("update_rollback", "update_recover"):
                transaction = params.get("transaction", "")
                if not isinstance(transaction, str) or not re.fullmatch(r"[a-f0-9]{32}", transaction):
                    raise ValueError("Identifiant de transaction invalide.")
                argv += ["--transaction", transaction]
        elif action == "console_publish":
            argv = ["bash", str(self.source / "71-soc-console.sh")]
        elif action.startswith("module_"):
            token = params.get("api_token", "")
            if not isinstance(token, str) or not token or any(ord(c) < 32 for c in token):
                raise ValueError("Jeton API requis, sans caractères de contrôle.")
            module_action = "uninstall" if action == "module_uninstall_plan" else action.removeprefix("module_")
            argv = build_module_command(self.source, module_action, params.get("module"), params.get("api"),
                                        port=params.get("port"), bind=params.get("bind", "127.0.0.1"),
                                        installation_id=params.get("installation_id"),
                                        apply=action in WRITES, ca=params.get("ca"))
            env["GRAYLOG_API_TOKEN"] = token
        return argv, env

    def _secrets(self, overlay):
        secrets = list(overlay.values())
        secrets.extend(value for key, value in os.environ.items()
                       if any(word in key.upper() for word in ("PASSWORD", "SECRET", "TOKEN", "API_KEY")))
        path = self.source / "00-vars.env"
        if path.is_symlink():
            raise ValueError("Fichier de configuration symbolique refusé.")
        if path.exists():
            for key, value in parse(path.read_text(encoding="utf-8")).items():
                if any(word in key for word in ("PASS", "SECRET", "TOKEN", "KEY", "CRED", "WEBHOOK")) and value and value != "CHANGEME":
                    secrets.append(value)
        return secrets

    def run(self, action, params, *, confirmed=False, emit=None):
        argv, overlay = self.command(action, params)
        if action in WRITES and confirmed is not True:
            raise ValueError("Cette opération exige une confirmation explicite.")
        with lock(self.state):
            secrets = self._secrets(overlay)
            job_id = uuid.uuid4().hex
            path = self.state / "jobs" / (job_id + ".json")
            if path.parent.is_symlink():
                raise ValueError("Répertoire de journaux symbolique refusé.")
            job = {"id": job_id, "action": action, "status": "running", "lines": [], "result": None,
                   "created_at": dt.datetime.now(dt.timezone.utc).isoformat()}
            write_private(path, job)
            process = None
            try:
                process = subprocess.Popen(argv, cwd=self.source, env={**os.environ, **overlay, "PYTHONUNBUFFERED": "1"},
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                           start_new_session=os.name == "posix", encoding="utf-8", errors="replace")
                output = []
                for line in process.stdout:
                    safe = redact(line.rstrip(), secrets)
                    output.append(safe)
                    job["lines"].append(safe[:4096])
                    job["lines"] = job["lines"][-1000:]
                    write_private(path, job)
                    if emit:
                        emit(safe)
                code = process.wait()
                job["status"], job["returncode"] = ("success" if code == 0 else "failed"), code
                try:
                    job["result"] = json.loads("\n".join(output))
                except (ValueError, TypeError):
                    pass
            except BaseException:
                if process is not None and process.poll() is None:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGTERM)
                    else:
                        process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        if os.name == "posix":
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                        process.wait()
                job["status"] = "interrupted"
                write_private(path, job)
                raise
            finally:
                if process is not None and process.stdout is not None:
                    process.stdout.close()
            job["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
            write_private(path, job)
            return job

    def history(self):
        directory = self.state / "jobs"
        if directory.is_symlink():
            raise ValueError("Répertoire de journal symbolique refusé.")
        entries = [json.loads(path.read_text(encoding="utf-8")) for path in directory.glob("*.json") if not path.is_symlink()]
        return sorted(entries, key=lambda job: job["created_at"], reverse=True)[:30]
