"""Offline stand-in for omni_update.system.System (no host, no network)."""
from __future__ import annotations

import fnmatch
from pathlib import Path

NOW = 1_800_000_000.0  # fixed clock


class FakeSystem:
    def __init__(self):
        self.commands = {}      # tuple(argv) or argv prefix tuple -> (rc, stdout, stderr)
        self.files = {}         # str(path) -> str or bytes
        self.mtimes = {}        # str(path) -> epoch
        self.disks = {}         # path -> {"free":, "total":}
        self.http = {}          # url (or url prefix ending with *) -> (status, body)
        self.calls = []
        self.http_calls = []
        self.clock = NOW

    # commands -------------------------------------------------------------
    def on(self, argv, stdout="", rc=0, stderr=""):
        self.commands[tuple(argv)] = (rc, stdout, stderr)
        return self

    def run(self, argv, timeout=120, env=None):
        self.calls.append(list(argv))
        key = tuple(argv)
        if key in self.commands:
            return self.commands[key]
        for length in range(len(key) - 1, 0, -1):
            prefix = key[:length] + ("*",)
            if prefix in self.commands:
                return self.commands[prefix]
        return 127, "", "unexpected command in test: " + " ".join(argv)

    # files ----------------------------------------------------------------
    def put(self, path, content, mtime=None):
        self.files[str(path)] = content
        if mtime is not None:
            self.mtimes[str(path)] = mtime
        return self

    def read(self, path):
        value = self.files.get(str(path))
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    def read_bytes(self, path):
        value = self.files.get(str(path))
        if value is None:
            return None
        return value if isinstance(value, bytes) else value.encode()

    def exists(self, path):
        path = str(path)
        return path in self.files or path in self.mtimes or any(f.startswith(path.rstrip("/") + "/") for f in self.files)

    def mtime(self, path):
        return self.mtimes.get(str(path))

    def glob(self, pattern):
        names = set(self.files) | set(self.mtimes)
        return sorted(n for n in names if fnmatch.fnmatchcase(n, pattern.replace("**/", "*")))

    def disk_free(self, path):
        return self.disks.get(str(path))

    def now(self):
        return self.clock

    def hostname(self):
        return "siem-test"

    def http_get(self, url, headers=None, timeout=10):
        self.http_calls.append((url, headers))
        if url in self.http:
            return self.http[url]
        for key, value in self.http.items():
            if key.endswith("*") and url.startswith(key[:-1]):
                return value
        return None, ""


def policy(installed, candidate, table):
    lines = ["pkg:", f"  Installed: {installed or '(none)'}", f"  Candidate: {candidate or '(none)'}", "  Version table:"]
    for version, priority in table:
        marker = " *** " if version == installed else "     "
        lines.append(f"{marker}{version} {priority}")
        lines.append("        500 https://repo.example.invalid stable/main amd64 Packages")
    return "\n".join(lines) + "\n"


PREFERENCES = """# test
Package: graylog-server
Pin: version 7.2.*
Pin-Priority: 500

Package: opensearch
Pin: version 2.19.*
Pin-Priority: 500

Package: mongodb-org*
Pin: version 8.0.*
Pin-Priority: 500

Package: graylog-server opensearch mongodb-org*
Pin: version *
Pin-Priority: -1
"""


def write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
