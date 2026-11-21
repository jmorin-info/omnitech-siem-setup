"""Thin, injectable access to the host so that every decision can be tested offline.

Every method is read-only except Runner.run when the caller explicitly executes
a mutating command (only omni_update.stack does so, after confirmation).
"""
from __future__ import annotations

import glob
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.request

C_LOCALE = {"LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"}
LOOPBACK = ("127.0.0.1", "localhost", "::1", "[::1]")


class System:
    """Real host access. Tests replace it with a fake exposing the same methods."""

    def run(self, argv, timeout=120, env=None):
        try:
            process = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                                     env={**os.environ, **C_LOCALE, **(env or {})}, stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            return 127, "", "command not found: " + argv[0]
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"
        return process.returncode, process.stdout, process.stderr

    def read(self, path):
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def read_bytes(self, path):
        try:
            return Path(path).read_bytes()
        except OSError:
            return None

    def exists(self, path):
        return Path(path).exists()

    def mtime(self, path):
        try:
            return Path(path).stat().st_mtime
        except OSError:
            return None

    def glob(self, pattern):
        return sorted(glob.glob(pattern, recursive=True))

    def disk_free(self, path):
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            return None
        return {"free": usage.free, "total": usage.total}

    def now(self):
        return time.time()

    def hostname(self):
        return os.uname().nodename if hasattr(os, "uname") else "inconnu"

    def http_get(self, url, headers=None, timeout=10):
        """GET only. TLS verification is disabled solely for loopback addresses,
        as the existing maintenance scripts do (curl -k on 127.0.0.1)."""
        request = urllib.request.Request(url, headers=headers or {}, method="GET")
        context = None
        if url.startswith("https://"):
            host = url.split("/")[2].rsplit(":", 1)[0]
            context = ssl.create_default_context()
            if host in LOOPBACK:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                return response.status, response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as error:
            return error.code, ""
        except (urllib.error.URLError, OSError, ValueError):
            return None, ""


def json_or_none(text):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def read_simple_env(text, keys):
    """Read literal KEY=value / KEY="value" assignments; no shell evaluation."""
    values = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        key = key.strip().removeprefix("export ").strip()
        if key not in keys:
            continue
        raw = raw.strip()
        if raw[:1] in {'"', "'"}:
            quote = raw[0]
            end = raw.find(quote, 1)
            value = raw[1:end] if end > 0 else raw[1:]
        else:
            value = raw.split("#", 1)[0].strip()
        if "$" not in value and "`" not in value:
            values[key] = value
    return values
