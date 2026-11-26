#!/usr/bin/env python3
"""Generate private offline previews. Never sends mail or contacts the SIEM."""
import argparse
import importlib.util
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("alert_context_preview", ROOT / "triage/omni_alert_context.py")
context = importlib.util.module_from_spec(spec)
spec.loader.exec_module(context)


def preview(source, destination):
    source, destination = Path(source), Path(destination)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 5 * 1024 * 1024:
        raise ValueError("regular JSON payload of at most 5 MiB required")
    if destination.exists() or destination.is_symlink():
        raise ValueError("choose a new private preview directory")
    result = context.build_context(json.loads(source.read_text(encoding="utf-8")))
    destination.mkdir(mode=0o700)
    outputs = {"context.json":json.dumps(result, ensure_ascii=False, indent=2),
               "alert.txt":context.render_text(result), "alert.html":'<!doctype html><html lang="fr"><meta charset="utf-8">'
               + '<meta name="viewport" content="width=device-width,initial-scale=1"><title>Aperçu hors ligne</title>'
               + context.render_html(result) + '</html>'}
    for name, value in outputs.items():
        with (destination / name).open("x", encoding="utf-8") as stream:
            stream.write(value)
        (destination / name).chmod(0o600)
    return {"mode":"offline-preview", "output_files":sorted(outputs), "included_records":result["coverage"]["included"],
            "omitted_records":result["coverage"]["omitted"], "delivery_performed":False, "production_changed":False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    previous = os.umask(0o077)
    try:
        print(json.dumps(preview(args.payload, args.output), indent=2))
    except (OSError, ValueError, TypeError):
        raise SystemExit("Offline preview refused; check the payload and choose a new output directory.") from None
    finally:
        os.umask(previous)
