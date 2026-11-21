#!/usr/bin/env python3
"""Contrôle des liens internes de la documentation Markdown.

Parcourt les fichiers .md suivis par Git (ou, à défaut, présents sur disque),
extrait les liens relatifs (syntaxe inline, références et balises HTML
href/src) et vérifie que la cible existe dans le dépôt. Les liens externes
(http, https, mailto...) et les ancres seules sont ignorés ; le contenu des
blocs de code est exclu.

Contrôle complémentaire : les chemins textuels de la forme « docs/....md » ou
« docs/....json » cités dans les fichiers suivis (scripts, code, Markdown) doivent
exister, résolus depuis la racine du dépôt ou depuis un dossier parent du
fichier (sous-projets seal/, oms-xdr/...). Le miroir deploye/ est exclu : il
reflète la production et n'est pas réécrit à la main.

Usage : python3 tools/check-doc-links.py [--root DIR] [--quiet]
Code de sortie : 0 si aucun lien cassé, 1 sinon.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFDEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$", re.M)
HTML = re.compile(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", re.I)
FENCE = re.compile(r"^(\s*)(```|~~~)")
INLINE_CODE = re.compile(r"`[^`\n]*`")
EXTERNAL = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//)", re.I)
# Répertoires exclus : dépendances, environnements virtuels, copies déployées.
EXCLUDED_PARTS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}


def markdown_files(root: Path) -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
             "--exclude-standard", "*.md"],
            capture_output=True, check=True,
        ).stdout.decode("utf-8")
        files = [root / p for p in out.split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        files = list(root.rglob("*.md"))
    return sorted(p for p in files
                  if p.is_file() and not EXCLUDED_PARTS.intersection(p.relative_to(root).parts))


def strip_code(text: str) -> str:
    """Masque blocs et extraits de code par des espaces (positions conservées)."""
    lines, in_fence, marker = [], False, ""
    for line in text.split("\n"):
        m = FENCE.match(line)
        if m:
            if not in_fence:
                in_fence, marker = True, m.group(2)
            elif m.group(2) == marker:
                in_fence = False
            lines.append(" " * len(line))
            continue
        if in_fence:
            lines.append(" " * len(line))
        else:
            lines.append(INLINE_CODE.sub(lambda c: " " * len(c.group(0)), line))
    return "\n".join(lines)


def targets(text: str):
    body = strip_code(text)
    for rx in (INLINE, REFDEF, HTML):
        for m in rx.finditer(body):
            yield body.count("\n", 0, m.start()) + 1, m.group(1)


def check(root: Path) -> list[tuple[str, int, str]]:
    broken = []
    for md in markdown_files(root):
        text = md.read_text(encoding="utf-8", errors="replace")
        for lineno, raw in targets(text):
            target = raw.strip()
            if not target or target.startswith("#") or EXTERNAL.match(target):
                continue
            path = unquote(target.split("#", 1)[0].split("?", 1)[0])
            if not path:
                continue
            resolved = (root / path.lstrip("/")) if path.startswith("/") else (md.parent / path)
            if not resolved.exists():
                broken.append((str(md.relative_to(root)), lineno, target))
    return broken


TEXT_REF = re.compile(r"(?<![\w./-])docs/[A-Za-z0-9_./-]+\.(?:md|json)")
TEXT_EXCLUDED_PREFIXES = ("deploye/",)
# Ce contrôleur et son test citent volontairement des chemins fictifs.
TEXT_EXCLUDED_FILES = {"tools/check-doc-links.py", "tests/test_doc_links.py"}
# Gabarits documentés (noms générés à date) : pas de fichier attendu.
PLACEHOLDER = re.compile(r"YYYY|AAAA|<date>")


def tracked_files(root: Path) -> list[str]:
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                             capture_output=True, check=True).stdout.decode("utf-8")
        return [p for p in out.split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        return [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()
                and not EXCLUDED_PARTS.intersection(p.relative_to(root).parts)]


def check_text_refs(root: Path) -> list[tuple[str, int, str]]:
    broken = []
    for rel in tracked_files(root):
        if rel.startswith(TEXT_EXCLUDED_PREFIXES) or rel in TEXT_EXCLUDED_FILES:
            continue
        path = root / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for m in TEXT_REF.finditer(text):
            ref = m.group(0).rstrip(".")
            if PLACEHOLDER.search(ref):
                continue
            bases = [root] + [p for p in path.parents if root in p.parents or p == root]
            if not any((b / ref).exists() for b in bases):
                broken.append((rel, text.count("\n", 0, m.start()) + 1, ref))
    return broken


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    broken = check(root)
    refs = check_text_refs(root)
    for f, line, target in broken:
        print(f"{f}:{line}: lien cassé -> {target}")
    for f, line, target in refs:
        print(f"{f}:{line}: référence textuelle introuvable -> {target}")
    if not args.quiet:
        print(f"{len(markdown_files(root))} fichiers Markdown contrôlés : "
              f"{len(broken)} lien(s) cassé(s), {len(refs)} référence(s) textuelle(s) introuvable(s).")
    return 1 if broken or refs else 0


if __name__ == "__main__":
    sys.exit(main())
