"""Debian package version comparison (dpkg algorithm) and apt metadata parsing.

Pure Python so that decisions are testable without dpkg. Matches
"dpkg --compare-versions": epoch, upstream version and revision, with "~"
sorting before anything, letters before other characters.
"""
from __future__ import annotations

import fnmatch
import re

PRERELEASE_PATTERN = re.compile(r"(alpha|beta|rc|snapshot)", re.IGNORECASE)


def _order(character):
    if not character or character.isdigit():
        return 0
    if character.isalpha():
        return ord(character)
    if character == "~":
        return -1
    return ord(character) + 256


def _compare_part(a, b):
    while a or b:
        while (a and not a[0].isdigit()) or (b and not b[0].isdigit()):
            first, second = _order(a[:1]), _order(b[:1])
            if first != second:
                return -1 if first < second else 1
            a, b = a[1:], b[1:]
        digits_a = re.match(r"\d*", a).group()
        digits_b = re.match(r"\d*", b).group()
        a, b = a[len(digits_a):], b[len(digits_b):]
        number_a, number_b = int(digits_a or 0), int(digits_b or 0)
        if number_a != number_b:
            return -1 if number_a < number_b else 1
    return 0


def split_version(version):
    version = (version or "").strip()
    epoch, _, rest = version.partition(":") if ":" in version else ("0", "", version)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch or 0), upstream, revision


def compare(first, second):
    """Return -1, 0 or 1 like dpkg --compare-versions."""
    epoch_a, upstream_a, revision_a = split_version(first)
    epoch_b, upstream_b, revision_b = split_version(second)
    if epoch_a != epoch_b:
        return -1 if epoch_a < epoch_b else 1
    return _compare_part(upstream_a, upstream_b) or _compare_part(revision_a, revision_b)


def series(version, depth=2):
    """'1:8.19.25-1' -> '8.19' ; '7.2.2-1' -> '7.2'."""
    _, upstream, _ = split_version(version)
    return ".".join(upstream.split(".")[:depth])


def major(version):
    return series(version, 1)


def parse_policy(text):
    """apt-cache policy output (C locale) -> installed, candidate, versions list."""
    installed = candidate = None
    versions = []
    in_table = False
    for line in (text or "").splitlines():
        match = re.match(r"\s*Installed:\s*(\S+)", line)
        if match:
            installed = None if match.group(1) == "(none)" else match.group(1)
            continue
        match = re.match(r"\s*Candidate:\s*(\S+)", line)
        if match:
            candidate = None if match.group(1) == "(none)" else match.group(1)
            continue
        if re.match(r"\s*Version table:", line):
            in_table = True
            continue
        match = re.match(r"\s*(?:\*\*\*\s+)?(\S+)\s+(-?\d+)\s*$", line) if in_table else None
        if match and not line.strip().startswith(("http", "/")):
            versions.append({"version": match.group(1), "priority": int(match.group(2))})
    return {"installed": installed, "candidate": candidate, "versions": versions}


def parse_preferences(text):
    """apt preferences -> list of stanzas {packages, pin, priority} in file order."""
    stanzas, current = [], {}
    for line in (text or "").splitlines() + [""]:
        line = line.strip()
        if line.startswith("#"):
            continue
        if not line:
            if current.get("packages"):
                stanzas.append(current)
            current = {}
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "package":
            current["packages"] = value.split()
        elif key == "pin":
            current["pin"] = value
        elif key == "pin-priority":
            try:
                current["priority"] = int(value)
            except ValueError:
                current["priority"] = 0
    return stanzas


def pinned_pattern(stanzas, package):
    """First stanza matching the package with a positive priority: its version glob."""
    for stanza in stanzas:
        if any(fnmatch.fnmatchcase(package, pattern) for pattern in stanza["packages"]):
            pin = stanza.get("pin", "")
            if stanza.get("priority", 0) > 0 and pin.startswith("version "):
                return pin.removeprefix("version ").strip()
            if stanza.get("priority", 0) < 0:
                return None
    return None


def allowed_by_pin(stanzas, package, version):
    """True/False when a preferences file governs the package, None otherwise."""
    governed = any(any(fnmatch.fnmatchcase(package, p) for p in s["packages"]) for s in stanzas)
    if not governed:
        return None
    for stanza in stanzas:
        if not any(fnmatch.fnmatchcase(package, p) for p in stanza["packages"]):
            continue
        pin = stanza.get("pin", "")
        if pin.startswith("version ") and fnmatch.fnmatchcase(version, pin.removeprefix("version ").strip()):
            return stanza.get("priority", 0) > 0
    return False


def parse_upgradable(text):
    """'apt list --upgradable' (C locale) -> [{package, suite, version, from}]."""
    result = []
    for line in (text or "").splitlines():
        match = re.match(r"^([^/\s]+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from:\s*([^\]]+)\]", line)
        if match:
            result.append({"package": match.group(1), "suite": match.group(2), "version": match.group(3),
                           "from": match.group(4).strip(),
                           "security": "-security" in match.group(2) or "security" in match.group(2).split(",")})
    return result
