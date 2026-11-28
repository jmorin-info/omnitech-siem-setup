#!/usr/bin/env python3
"""List, validate, export and explicitly install independent Graylog content packs."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from omni_integrations.core import catalog, load_module, build_pack, build_existing_input_pack, validate_module
from omni_integrations.client import (Graylog, parameters, install, uninstall, load_site_config, install_existing_input,
                                      deploy_dashboards, restore_dashboards, check_dashboards)
from omni_integrations.socle import (validate_socle, load_site_profile, deploy_socle, check_socle_site,
                                     discover_sources)

SITE_CONFIG = "/etc/omni-siem/integrations.json"


def run_modules(args, parser):
    """Contrat de module (docs/MODULES.md) : activation par la configuration de site et cycle de vie."""
    from omni_integrations import modules as mod
    if args.apply and args.action in ("list", "validate", "plan", "verify"):
        parser.error(args.action + " est en lecture seule")
    if args.action in ("rollback", "uninstall") and not args.target:
        parser.error(args.action + " attend " + ("une transaction" if args.action == "rollback" else "un module"))
    code = 0
    if args.action == "list":
        result = mod.list_modules(args.site_config, root=args.root)
    elif args.action == "validate":
        result = mod.validate_all()
        code = 1 if result["problems"] else 0
    elif args.action == "plan":
        result = mod.plan(args.site_config, root=args.root)
        code = 1 if result["blockers"] else 0
    elif args.action == "apply":
        result = mod.apply(args.site_config, root=args.root, state_dir=args.state_dir, apply=args.apply)
        code = 1 if result.get("refused") else 0
    elif args.action == "verify":
        client = Graylog(args.api, os.environ.get(args.token_env), args.ca, args.username) if args.api else None
        result = mod.verify(args.site_config, root=args.root, client=client)
        code = 1 if result["failures"] else 0
    elif args.action == "rollback":
        result = mod.rollback(args.target, root=args.root, state_dir=args.state_dir, apply=args.apply)
    else:
        result = mod.uninstall(args.target, args.site_config, root=args.root, state_dir=args.state_dir, apply=args.apply)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    validate = commands.add_parser("validate")
    validate.add_argument("module", nargs="?")
    export = commands.add_parser("export")
    export.add_argument("module")
    export.add_argument("--output", type=Path)
    export.add_argument("--existing-input", action="store_true", help="Export the variant for an existing site input")
    for name in ("plan", "install", "uninstall", "adopt", "dashboards", "restore-dashboards", "check"):
        command = commands.add_parser(name)
        command.add_argument("module")
        command.add_argument("--api", required=True, help="Graylog API URL ending in /api")
        command.add_argument("--ca", help="Trusted CA certificate file (optional when system trust is sufficient)")
        command.add_argument("--token-env", default="GRAYLOG_API_TOKEN")
        command.add_argument("--username", help="Account whose password is in --token-env (loopback administration)")
        if name != "check":
            command.add_argument("--apply", action="store_true", help="Explicitly perform writes (never with plan)")
        if name == "uninstall":
            command.add_argument("--installation-id", required=True)
            command.add_argument("--existing-input", action="store_true")
        elif name in ("plan", "install"):
            command.add_argument("--port", type=int)
            command.add_argument("--bind", default="127.0.0.1")
        elif name in ("adopt", "dashboards", "check"):
            command.add_argument("--site-config", default=SITE_CONFIG, type=Path)
        if name in ("dashboards", "restore-dashboards"):
            command.add_argument("--backup-dir", type=Path, required=name == "restore-dashboards")
        if name == "check":
            command.add_argument("--days", type=int, default=1)
    # Socle SOC : dashboards génériques filtrés par les sources que le site active.
    commands.add_parser("soc-validate", help="Offline contract of the socle dashboards and console capabilities")
    for name in ("soc-sources", "soc-dashboards", "soc-check"):
        command = commands.add_parser(name)
        command.add_argument("--api", required=True, help="Graylog API URL ending in /api")
        command.add_argument("--ca", help="Trusted CA certificate file (optional when system trust is sufficient)")
        command.add_argument("--token-env", default="GRAYLOG_API_TOKEN")
        command.add_argument("--username", help="Account whose password is in --token-env (loopback administration)")
        command.add_argument("--site-config", default=SITE_CONFIG, type=Path)
        if name == "soc-dashboards":
            command.add_argument("--apply", action="store_true", help="Explicitly publish (backup required)")
            command.add_argument("--backup-dir", type=Path)
        if name == "soc-sources":
            command.add_argument("--days", type=int, default=7)
    # Contrat de module (docs/MODULES.md) : activation par site et cycle de vie.
    modules_cmd = commands.add_parser("modules", help="Modules : list, validate, plan, apply, verify, rollback, uninstall")
    modules_cmd.add_argument("action", choices=("list", "validate", "plan", "apply", "verify", "rollback", "uninstall"))
    modules_cmd.add_argument("target", nargs="?", help="transaction (rollback) ou module (uninstall)")
    modules_cmd.add_argument("--site-config", default=SITE_CONFIG, type=Path)
    modules_cmd.add_argument("--root", default="/", help="Racine factice pour un déploiement à blanc")
    modules_cmd.add_argument("--state-dir", type=Path)
    modules_cmd.add_argument("--apply", action="store_true", help="Écrire réellement (jamais par défaut)")
    modules_cmd.add_argument("--api", help="API Graylog (verify seulement, facultatif)")
    modules_cmd.add_argument("--ca", help="Trusted CA certificate file")
    modules_cmd.add_argument("--token-env", default="GRAYLOG_API_TOKEN")
    modules_cmd.add_argument("--username", help="Account whose password is in --token-env")
    args = parser.parse_args(argv)
    if args.command == "modules":
        return run_modules(args, parser)
    if args.command == "soc-validate":
        result = validate_socle()
    elif args.command in ("soc-sources", "soc-dashboards", "soc-check"):
        validate_socle()
        client = Graylog(args.api, os.environ.get(args.token_env), args.ca, args.username)
        if args.command == "soc-sources":
            result = discover_sources(client, days=args.days)
        else:
            profile = load_site_profile(args.site_config)
            if args.command == "soc-dashboards":
                result = deploy_socle(client, profile, apply=args.apply, backup_dir=args.backup_dir)
            else:
                result = check_socle_site(client, profile)
                print(json.dumps(result, indent=2, ensure_ascii=False))
                return 1 if result["failures"] else 0
    elif args.command == "restore-dashboards" and args.module == "socle":
        result = restore_dashboards(Graylog(args.api, os.environ.get(args.token_env), args.ca, args.username),
                                    args.backup_dir, apply=args.apply)
    elif args.command == "list":
        result = [{key: module[key] for key in ("id", "name", "revision", "status", "default_port", "supported_format")} for module in catalog()]
    elif args.command == "validate":
        result = [validate_module(module) for module in ([load_module(args.module)] if args.module else catalog())]
        if not args.module:
            result.append(validate_socle())
            from omni_integrations.modules import validate_all
            contract = validate_all()
            if contract["problems"]:
                raise ValueError("module contract: " + "; ".join(contract["problems"]))
            result.append({"modules": contract["modules"]})
    elif args.command == "export":
        module = load_module(args.module)
        validate_module(module)
        result = build_existing_input_pack(module) if args.existing_input else build_pack(module)
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
        client = Graylog(args.api, os.environ.get(args.token_env), args.ca, args.username)
        apply = getattr(args, "apply", False)
        if args.command == "uninstall":
            result = uninstall(client, module, args.installation_id, apply=apply, existing_input=args.existing_input)
        elif args.command == "adopt":
            result = install_existing_input(client, module, load_site_config(args.site_config, module["id"]), apply=apply)
        elif args.command == "dashboards":
            result = deploy_dashboards(client, module, load_site_config(args.site_config, module["id"]),
                                       apply=apply, backup_dir=args.backup_dir)
        elif args.command == "restore-dashboards":
            result = restore_dashboards(client, args.backup_dir, apply=apply)
        elif args.command == "check":
            result = check_dashboards(client, module, load_site_config(args.site_config, module["id"]), days=args.days)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 1 if result["failures"] else 0
        else:
            result = install(client, module, parameters(module, args.port, args.bind), apply=args.command == "install" and apply)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit("Integration operation failed: " + str(exc))
