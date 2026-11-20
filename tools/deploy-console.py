#!/usr/bin/env python3
"""Publish every console asset and add missing nginx routes. Default: plan only.

--apply validates nginx before reload and restores its configuration on failure.
No Graylog API writes. Existing local nginx locations and ACLs are preserved.
"""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BEGIN, END = "# BEGIN OMNI CONSOLE ROUTES", "# END OMNI CONSOLE ROUTES"


def add_routes(text: str, soc: Path, mobile: Path) -> str:
    if any(not p.is_absolute() or re.search(r"[^/A-Za-z0-9_.-]", str(p)) for p in (soc, mobile)):
        raise ValueError("nginx roots must be absolute paths without special characters")
    if BEGIN in text:
        if END not in text:
            raise ValueError("incomplete managed nginx block")
        return text
    routes = []
    has = lambda expr: re.search(expr, text, re.M) is not None
    if not has(r"^\s*location\s+=\s+/soc\s*\{"):
        routes.append("location = /soc { return 308 /soc/; }")
    if not has(r"^\s*location\s+(?:\^~\s+)?/soc/\s*\{"):
        routes.extend(["location /soc/ {", f"    alias {soc.as_posix()}/;", "    index index.html;",
                       "    add_header X-Content-Type-Options nosniff always;",
                       "    add_header X-Frame-Options DENY always;",
                       "    add_header Referrer-Policy no-referrer always;",
                       "    add_header Cache-Control no-cache;",
                       '''    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; worker-src 'self'; manifest-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;''',
                       "}"])
        if not has(r"^\s*location\s+=\s+/soc/sw\.js\s*\{"):
            routes.append(f"location = /soc/sw.js {{ alias {soc.as_posix()}/sw.js; add_header Cache-Control 'no-store'; }}")
    if not has(r"^\s*location\s+(?:\^~\s+)?/m/api/\s*\{"):
        if not has(r"^\s*location\s+=\s+/m/api/push\s*\{"):
            routes.append("location = /m/api/push { return 404; }")
        routes.extend(["location /m/api/ {", "    proxy_pass http://127.0.0.1:8090;",
                       "    proxy_set_header Host $host;", "    proxy_set_header X-Real-IP $remote_addr;",
                       "    proxy_read_timeout 120s;", "}"])
    if not has(r"^\s*location\s+(?:\^~\s+)?/m/\s*\{"):
        routes.append(f"location /m/ {{ alias {mobile.as_posix()}/; index index.html; }}")
    if not routes:
        return text
    anchors = list(re.finditer(r"(?m)^([ \t]*)location\s+/\s*\{", text))
    if len(anchors) != 1:
        raise ValueError("expected one 'location / {' in the selected Graylog vhost; check --site")
    anchor = anchors[0]
    block = "\n".join(anchor[1] + line for line in [BEGIN, *routes, END]) + "\n"
    return text[:anchor.start()] + block + text[anchor.start():]


def asset_files(source: Path) -> list[Path]:
    allowed = {".html", ".js", ".css", ".json", ".webmanifest", ".png", ".jpg", ".jpeg", ".svg", ".geojson", ".woff", ".woff2"}
    return sorted(p for p in source.rglob("*") if p.is_file() and p.suffix in allowed and not p.is_symlink())


def check_assets(source: Path):
    required = ["index.html", "app-boot.js", "app-csp.js", "app-loader.js", "app.js", "app-v3.js", "chart.min.js", "sw.js", "manifest.webmanifest", "icons/icon-192.png"]
    missing = [name for name in required if not (source / name).is_file()]
    if missing:
        raise ValueError("console source is incomplete: " + ", ".join(missing))
    html = (source / "index.html").read_text(encoding="utf-8")
    for url in re.findall(r'(?:src|href)="(/soc/[^"?#]+)', html):
        if not (source / url.removeprefix("/soc/")).is_file():
            raise ValueError("missing referenced console asset: " + url)


def publish(source: Path, destination: Path):
    if destination.is_symlink():
        raise ValueError("refusing a symlink for the public asset directory")
    destination.mkdir(parents=True, exist_ok=True)
    destination.chmod(0o755)
    # The new page and service worker must only become visible after their assets.
    files = sorted(asset_files(source), key=lambda p: (
        2 if p.name == "sw.js" else 1 if p.name == "index.html" else 0, p.as_posix()))
    for path in files:
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        parent = target.parent
        while parent != destination:
            if parent.is_symlink():
                raise ValueError("refusing a symlink in the public asset directory")
            parent.chmod(0o755)
            parent = parent.parent
        with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
            tmp.write(path.read_bytes())
            temporary = Path(tmp.name)
        temporary.chmod(0o644)
        os.replace(temporary, target)


def apply_site(site: Path, content: str, nginx="nginx", reload_command=None) -> Path | None:
    site = site.resolve(strict=True)  # preserve sites-enabled symlinks
    if site.read_text(encoding="utf-8") == content:
        subprocess.run([nginx, "-t"], check=True)
        return None
    backup_dir = site.parent.parent / "omni-console-backups"
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = backup_dir / (site.name + "." + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    shutil.copy2(site, backup)
    try:
        site.write_text(content, encoding="utf-8")
        subprocess.run([nginx, "-t"], check=True)
        subprocess.run(reload_command or ["systemctl", "reload", "nginx"], check=True)
    except BaseException:
        shutil.copy2(backup, site)
        raise
    return backup


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, default=Path("/etc/nginx/sites-enabled/graylog"))
    parser.add_argument("--soc-root", type=Path, default=Path("/var/www/siem-soc"))
    parser.add_argument("--mobile-root", type=Path, default=Path("/var/www/siem-mobile"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    check_assets(ROOT / "mobile/soc")
    original = args.site.read_text(encoding="utf-8")
    updated = add_routes(original, args.soc_root, args.mobile_root)
    print(json.dumps({"site": str(args.site.resolve()), "routing_change": original != updated,
                      "soc_assets": len(asset_files(ROOT / "mobile/soc")), "mode": "apply" if args.apply else "plan"}, indent=2))
    if args.apply:
        publish(ROOT / "mobile/soc", args.soc_root)
        publish(ROOT / "mobile/www", args.mobile_root)
        shutil.copyfile(ROOT / "mobile/soc/chart.min.js", args.mobile_root / "chart.min.js")
        (args.mobile_root / "chart.min.js").chmod(0o644)
        backup = apply_site(args.site, updated)
        if backup:
            print("nginx backup: " + str(backup))
        print("Console assets published; nginx configuration validated.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        raise SystemExit("Console deployment failed: " + str(exc))
