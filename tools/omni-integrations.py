#!/usr/bin/env python3
"""List, validate, export and explicitly install independent Graylog content packs."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from omni_integrations.core import catalog, load_module, build_pack, validate_module
from omni_integrations.client import Graylog, parameters, install, uninstall


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    validate = commands.add_parser("validate")
    validate.add_argument("module", nargs="?")
    export = commands.add_parser("export")
    export.add_argument("module")
    export.add_argument("--output", type=Path)
    for name in ("plan", "install", "uninstall"):
        command = commands.add_parser(name)
        command.add_argument("module")
        command.add_argument("--api", required=True, help="Graylog API URL ending in /api")
        command.add_argument("--ca", help="Trusted CA certificate file (optional when system trust is sufficient)")
        command.add_argument("--token-env", default="GRAYLOG_API_TOKEN")
        command.add_argument("--apply", action="store_true", help="Explicitly perform writes (install/uninstall only)")
        if name == "uninstall":
            command.add_argument("--installation-id", required=True)
        else:
            command.add_argument("--port", type=int)
            command.add_argument("--bind", default="127.0.0.1")
    args = parser.parse_args(argv)
    if args.command == "list":
        result = [{key: module[key] for key in ("id", "name", "revision", "status", "default_port", "supported_format")} for module in catalog()]
    elif args.command == "validate":
        result = [validate_module(module) for module in ([load_module(args.module)] if args.module else catalog())]
    elif args.command == "export":
        module = load_module(args.module)
        validate_module(module)
        result = build_pack(module)
        if args.output:
            # Refuse silent overwrite of an exported or locally modified artifact.
            with args.output.open("x", encoding="utf-8") as output:
                json.dump(result, output, indent=2, ensure_ascii=False)
                output.write("\n")
            result = {"exported": str(args.output), "module": args.module, "revision": module["revision"]}
    else:
        module = load_module(args.module)
        validate_module(module)
        if args.command == "plan" and args.apply:
            parser.error("plan is read-only; use install --apply for an explicit installation")
        client = Graylog(args.api, os.environ.get(args.token_env), args.ca)
        if args.command == "uninstall":
            result = uninstall(client, module, args.installation_id, apply=args.apply)
        else:
            result = install(client, module, parameters(module, args.port, args.bind), apply=args.command == "install" and args.apply)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit("Integration operation failed: " + str(exc))
