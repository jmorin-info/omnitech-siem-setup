#!/usr/bin/env python3
"""Offline repository inventory; never runs provisioning or reads untracked secrets.

Usage: python3 tools/audit-portability.py > audit.json
Run on Linux for additional bash syntax checks. No runtime files are written.
"""
from __future__ import annotations

import ast
import collections
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "site_network": re.compile(r"\b10\.(?:33|13|94)\.\d+\.\d+"),
    "site_hostname": re.compile(r"bx-it-graylog|omnitech\.security|omnitech-security\.fr", re.I),
    "literal_object_id": re.compile(r"[\"'][0-9a-f]{24}[\"']"),
    "tls_verification_disabled": re.compile(r"_create_unverified_context|verify\s*=\s*False|curl\s+[^\n]*\s--insecure\b|curl\s+-[a-zA-Z]*k\b"),
    "disk_operation": re.compile(r"\b(?:mkfs(?:\.\w+)?|wipefs|luksFormat|parted)\b"),
}


def main():
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    names = [n for n in names if n]
    result = {
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
        "scope": "tracked files only; static findings are candidates for manual review",
        "files": [], "syntax": [], "broken_document_links": [],
        "numbered_script_prefixes": {}, "checks": {"python": 0, "shell": 0, "json": 0},
    }
    groups = collections.defaultdict(list)
    for name in names:
        path = ROOT / name
        data = path.read_bytes()
        record = {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        result["files"].append(record)
        if m := re.match(r"^(\d{2})-[^/]+\.sh$", name):
            groups[m[1]].append(name)
        if b"\0" in data:
            record["binary"] = True
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            record["encoding"] = "not UTF-8"
            continue
        text = text.replace("\r\n", "\n")
        record["lines"] = len(text.splitlines())
        # Record locations, never the matching lines (they may contain local details).
        record["findings"] = {
            key: [i for i, line in enumerate(text.splitlines(), 1) if rx.search(line)]
            for key, rx in PATTERNS.items() if rx.search(text)
        }
        if "\ufffd" in text:
            record["replacement_characters"] = text.count("\ufffd")
        if name.endswith(".py") or re.match(r"^#![^\n]*python", text):
            result["checks"]["python"] += 1
            try:
                ast.parse(text, filename=name)
            except SyntaxError as exc:
                result["syntax"].append({"path": name, "line": exc.lineno, "error": exc.msg})
        elif (name.endswith(".sh") or re.match(r"^#![^\n]*(?:bash|/sh)\b", text)) and shutil.which("bash"):
            result["checks"]["shell"] += 1
            proc = subprocess.run(["bash", "-n"], input=text, text=True, capture_output=True)
            if proc.returncode:
                result["syntax"].append({"path": name, "error": proc.stderr.strip()})
        if name.endswith((".json", ".webmanifest")):
            result["checks"]["json"] += 1
            try:
                json.loads(text)
            except ValueError as exc:
                result["syntax"].append({"path": name, "error": str(exc)})
        if name.endswith(".md"):
            # Inline relative file links only; anchors and external URLs are excluded.
            for match in re.finditer(r"\]\(([^\s)]+)(?:\s+\"[^\"]*\")?\)", text):
                target = unquote(match[1].strip("<>").split("#", 1)[0])
                if not target or re.match(r"^[a-zA-Z]+:|^/", target) or any(c in target for c in "{}*$"):
                    continue
                if not (path.parent / target).exists():
                    result["broken_document_links"].append({
                        "path": name, "line": text[:match.start()].count("\n") + 1, "target": target,
                    })
    result["numbered_script_prefixes"] = {k: v for k, v in groups.items() if len(v) > 1}
    result["summary"] = {
        "tracked_files": len(names),
        "bytes": sum(f["bytes"] for f in result["files"]),
        "syntax_errors": len(result["syntax"]),
        "broken_relative_links": len(result["broken_document_links"]),
        "finding_files": {k: sum(k in f.get("findings", {}) for f in result["files"]) for k in PATTERNS},
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
