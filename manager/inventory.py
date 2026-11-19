"""Account for every tracked project file; separate visibility from automation."""
from pathlib import Path
import subprocess

GROUPS = {
    "core": ("Socle Graylog / OpenSearch / MongoDB", "Installation neuve automatisée", "docs/INSTALLATION.md"),
    "console": ("Console SOC, PWA et backend", "Publication et réparation automatisées", "docs/CONSOLE-DEPLOIEMENT.md"),
    "modules": ("WatchGuard / UniFi / Palo Alto", "Plan et installation explicite ; préversion", "docs/INTEGRATIONS-MODULAIRES.md"),
    "updates": ("Versions et mises à jour", "Code seulement ; migrations séparées", "docs/UPDATES.md"),
    "analytics": ("ML, XDR, graphe et triage", "Configuration et recette du site nécessaires", "docs/ALERTING-AND-TRIAGE.md"),
    "collectors": ("Agents, pare-feu et collecteurs", "Identifiants et configuration côté sources nécessaires", "docs/DATA-SOURCES.md"),
    "seal": ("Contrôle d'accès physique SEAL", "SQL et droits du site nécessaires", "seal/README.md"),
    "runtime": ("Robots, services et état déployé", "Inventaire ; aucune activation globale implicite", "docs/OPERATIONS.md"),
    "maintenance": ("Scripts de provisioning et maintenance", "Actions historiques : revue individuelle", "docs/AUDIT-PORTABILITE-2026-11-19.md"),
    "reference": ("Documentation, tests et ressources communes", "Référence et qualification", "docs/00-INDEX.md"),
}


def group(path):
    if path.startswith("seal/") or path == "seal_graylog_setup.py":
        return "seal"
    if path.startswith(("manager/", "omni_integrations/", "integrations/")) or path == "tools/omni-integrations.py":
        return "modules" if not path.startswith("manager/") else "updates"
    if path.startswith(("mobile/", "docker/console", "tools/deploy-console", "tools/install-console", "tools/manage-console")) or path == "71-soc-console.sh":
        return "console"
    if path.startswith(("oms-ml/", "oms-xdr/", "oms-graph/", "triage/", "soar-v2/")):
        return "analytics"
    if path.startswith(("windows/", "kit/", "fortigate/")):
        return "collectors"
    if path.startswith("deploye/") or path == "manifeste-deploye.txt":
        return "runtime"
    if path in {"00-preflight.sh", "00-vars.env.example", "lib-graylog.sh", "lib-platform.sh", "stack-versions.env", "install.sh", "tools/install-platform.py", "tools/render-firewall.py"} or path.startswith("docker/") or path[:3] in {"01-", "02-", "03-", "04-", "05-", "06-", "07-", "08-", "10-", "11-", "12-", "13-", "14-"}:
        return "core"
    if path == "tools/omni-update.py" or path == "tools/omni-manager.py":
        return "updates"
    if path.endswith(".sh") or path.startswith("tools/"):
        return "maintenance"
    return "reference"


def inventory(source: Path):
    files = [name for name in subprocess.check_output(["git", "-C", str(source), "ls-files", "-z"], env=None).decode().split("\0") if name]
    components = []
    for key, (name, automation, documentation) in GROUPS.items():
        members = [path for path in files if group(path) == key]
        components.append({"id": key, "name": name, "automation": automation,
                           "documentation": documentation, "files": members, "file_count": len(members)})
    scripts = [{"path": path, "policy": "maintenance destructive : hors installation et mises à jour" if any(token in Path(path).name for token in ("purge", "reclaim", "revert")) else "revue individuelle ; aucune exécution depuis le catalogue"}
               for path in files if "/" not in path and path.endswith(".sh")]
    return {"tracked_files": len(files), "components": components, "scripts": scripts,
            "scope": "Inventaire du dépôt ; ne prouve pas l'activation ni la bonne santé des services."}
