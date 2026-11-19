"""French, dependency-free menus for administration over an SSH terminal."""
from __future__ import annotations
import argparse
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys

from .configuration import Configuration, FIELDS, SECRETS
from .inventory import inventory
from .modules import catalogue
from .operations import Manager, WRITES

ROOT = Path(__file__).resolve().parents[1]
CONFIG_GROUPS = {
    "Identité et API": ["SIEM_HOSTNAME", "SIEM_DOMAIN", "SIEM_FQDN", "SIEM_TIMEZONE", "GRAYLOG_API_URL", "GRAYLOG_API_CA"],
    "Réseau et accès": ["SIEM_IP", "SIEM_PREFIX", "SIEM_GW", "SIEM_IFACE", "DNS1", "DNS2", "NTP1", "NTP2", "NET_ADMIN", "WEB_NET", "NET_BEATS", "VSPHERE_NET", "NET_ARUBA", "IP_FAZ", "IP_CENTREON", "IP_FORTIMANAGER"],
    "Mémoire et stockage": ["OS_HEAP", "GL_HEAP", "MONGO_CACHE_GB", "JOURNAL_SIZE", "DATA_MOUNT", "BACKUP_DIR", "RETENTION_DAYS"],
    "Notifications SMTP": ["SMTP_RELAY", "SMTP_PORT", "SMTP_FROM", "ALERT_EMAIL"],
}
ACTION_LABELS = {
    "install_secrets": "Générer les secrets MongoDB/OpenSearch manquants pour une instance neuve",
    "install_plan": "Afficher le plan d'installation", "install_apply": "Installer le socle et la console sur cet hôte",
    "install_resume": "Reprendre l'installation enregistrée", "update_fetch": "Télécharger une révision dans le cache",
    "update_plan": "Afficher les différences de code", "update_stage": "Préparer le candidat",
    "update_apply": "Remplacer le code autorisé avec sauvegarde", "update_rollback": "Restaurer le code d'une transaction",
    "update_recover": "Récupérer une transaction de code interrompue", "update_status": "État des mises à jour",
    "console_publish": "Publier les fichiers de /soc/ et activer le backend géré",
    "module_plan": "Préparer l'installation du module", "module_install": "Installer le Content Pack et reprendre son stream",
    "module_uninstall_plan": "Examiner les entités à désinstaller", "module_uninstall": "Désinstaller le Content Pack sélectionné",
}


def prompt(label, default=""):
    value = input(label + (f" [{default}]" if default else "") + " : ").strip()
    return "" if value == "-" else value or default


def confirm(label):
    print("\n" + label)
    return input("Taper OUI pour appliquer, Entrée pour annuler : ").strip() == "OUI"


def menu(title, labels):
    print("\n" + "=" * 64 + "\n" + title + "\n" + "=" * 64)
    for index, label in enumerate(labels, 1):
        print(f" {index}. {label}")
    print(" 0. Retour / quitter")
    choice = input("Choix : ").strip()
    return int(choice) if choice.isdigit() and 0 <= int(choice) <= len(labels) else -1


class Terminal:
    def __init__(self, source, state, updater_state=None):
        self.manager = Manager(source, state, updater_state=updater_state)
        self.config = Configuration(source, state)
        self.target = ""
        self.transaction = ""
        self.triage = False
        self.experimental_ubuntu_2604 = False
        self.allow_local_changes = False
        previous_install = Path("/var/lib/omni-siem/install-state.json")
        if previous_install.is_file():
            recorded = json.loads(previous_install.read_text())
            if recorded.get("source_root") == str(self.manager.source):
                self.triage = "triage" in recorded.get("extras", [])
                self.experimental_ubuntu_2604 = recorded.get("experimental_ubuntu_2604", False)
                self.allow_local_changes = recorded.get("allow_local_changes", False)

    def run(self, action, params=None):
        params = params or {}
        label = ACTION_LABELS[action]
        details = ", ".join(str(params[key]) for key in ("module", "api", "target", "transaction", "installation_id") if key in params)
        if action in WRITES and not confirm(label + (" — " + details if details else "") + ". Lire le plan avant de confirmer."):
            print("Annulé.")
            return None
        job = self.manager.run(action, params, confirmed=action in WRITES, emit=print)
        print("\nRésultat : " + job["status"] + " — journal " + job["id"])
        result = job.get("result")
        if job["status"] == "success" and isinstance(result, dict):
            self.target = result.get("target", self.target)
            self.transaction = result.get("transaction", self.transaction)
        return job

    def configure(self):
        while True:
            data = self.config.read()
            choice = menu("Configuration du site (les secrets ne sont pas affichés)",
                          [*CONFIG_GROUPS, "Secrets", "Voir les paramètres non secrets"])
            if choice == 0:
                return
            if 1 <= choice <= len(CONFIG_GROUPS):
                keys = list(CONFIG_GROUPS.values())[choice - 1]
                updates = {}
                print("Entrée conserve la valeur ; '-' vide un champ facultatif.")
                for key in keys:
                    updates[key] = prompt(FIELDS[key][0] + " (" + key + ")", data["values"].get(key, ""))
                if choice == 1 and (updates["SIEM_HOSTNAME"], updates["SIEM_DOMAIN"]) != (data["values"]["SIEM_HOSTNAME"], data["values"]["SIEM_DOMAIN"]) and updates["SIEM_FQDN"] == data["values"]["SIEM_FQDN"]:
                    updates.pop("SIEM_FQDN")
                if confirm("Enregistrer ces paramètres dans 00-vars.env ?"):
                    self.config.save(updates, {})
                    print("Configuration enregistrée ; les services ne sont pas reconfigurés.")
            elif choice == len(CONFIG_GROUPS) + 1:
                updates = {}
                for key, label in SECRETS.items():
                    state = "configuré" if data["secret_status"][key] else "absent"
                    updates[key] = getpass.getpass(f"{label} ({state}, vide = conserver) : ")
                if confirm("Enregistrer les secrets localement, sans les afficher ?"):
                    self.config.save({}, updates)
                    print("Secrets enregistrés. Conserver les passphrases au coffre.")
            elif choice == len(CONFIG_GROUPS) + 2:
                print(json.dumps(data, indent=2, ensure_ascii=False))

    def installation(self):
        while True:
            choice = menu("Installation neuve / reprise — aucune boucle sur les scripts", [
                "Configurer l'instance", f"Option triage mail : {'activée' if self.triage else 'désactivée'}",
                "Afficher le plan", "Installer le socle et la console", "Reprendre une installation interrompue",
                "Générer les secrets techniques manquants (instance neuve)",
                f"Ubuntu 26.04 expérimental : {'activé' if self.experimental_ubuntu_2604 else 'désactivé'}",
                f"Sources locales modifiées et examinées : {'autorisées' if self.allow_local_changes else 'refusées'}"])
            if choice == 0:
                return
            if choice == 1:
                self.configure()
            elif choice == 2:
                self.triage = not self.triage
            elif choice in (3, 4, 5):
                action = {3: "install_plan", 4: "install_apply", 5: "install_resume"}[choice]
                self.run(action, {"triage": self.triage, "experimental_ubuntu_2604": self.experimental_ubuntu_2604,
                                  "allow_local_changes": self.allow_local_changes})
            elif choice == 6:
                self.run("install_secrets")
            elif choice == 7:
                print("Ubuntu 26.04 : paquets MongoDB noble, hors support officiel ; contrôle du noyau maintenu.")
                self.experimental_ubuntu_2604 = not self.experimental_ubuntu_2604
            elif choice == 8:
                print("Examiner git diff avant d'autoriser : les sources seront conservées et leur empreinte enregistrée.")
                self.allow_local_changes = not self.allow_local_changes

    def updates(self):
        while True:
            print("\nRévision cible : " + (self.target or "non sélectionnée"))
            choice = menu("Mises à jour du code — bases et configuration préservées", [
                "Télécharger main / un tag dans le cache", "Choisir un SHA complet", "Afficher le plan",
                "Préparer le candidat", "Appliquer le code préparé", "Publier / réparer la console",
                "Afficher l'état des mises à jour", "Annuler une transaction de code", "Récupérer une transaction interrompue"])
            if choice == 0:
                return
            if choice == 1:
                self.run("update_fetch", {"ref": prompt("Branche ou tag", "main")})
            elif choice == 2:
                self.target = prompt("SHA Git complet", self.target)
            elif choice in (3, 4, 5):
                self.run({3: "update_plan", 4: "update_stage", 5: "update_apply"}[choice], {"target": self.target})
            elif choice == 6:
                self.run("console_publish")
            elif choice == 7:
                self.run("update_status")
            elif choice in (8, 9):
                print("Le retour de code ne restaure pas une base ni des fichiers publiés séparément.")
                transaction = prompt("Identifiant de transaction", self.transaction)
                self.run("update_rollback" if choice == 8 else "update_recover", {"transaction": transaction})

    def modules(self):
        modules = catalogue()
        choice = menu("Intégrations Graylog — préversion, recette sur logs réels requise", [item["name"] for item in modules])
        if not 1 <= choice <= len(modules):
            return
        module = modules[choice - 1]
        print(module["supported_format"])
        print("Input, parsing, stream et dashboard ; pas de notification ni de réponse SOAR automatique.")
        action = menu("Module : " + module["name"], ["Plan d'installation", "Installer après lecture du plan", "Plan de désinstallation (entités concernées)", "Désinstaller après lecture du plan"])
        if action not in (1, 2, 3, 4):
            return
        cfg = self.config.read()["values"]
        api = prompt("URL API Graylog", cfg.get("GRAYLOG_API_URL") or "http://127.0.0.1:9000/api")
        ca = prompt("Fichier CA (vide ou '-' : confiance système)", cfg.get("GRAYLOG_API_CA", "") if api.startswith("https://") else "")
        params = {"module": module["id"], "api": api, "api_token": getpass.getpass("Jeton API Graylog (non enregistré) : ")}
        if ca:
            params["ca"] = ca
        if action in (3, 4):
            params["installation_id"] = prompt("Identifiant exact d'installation du Content Pack")
        else:
            params["port"] = int(prompt("Port UDP dédié", str(module["default_port"])))
            params["bind"] = prompt("Adresse d'écoute (choisir l'interface de collecte)", "127.0.0.1")
        self.run({1: "module_plan", 2: "module_install", 3: "module_uninstall_plan", 4: "module_uninstall"}[action], params)

    def overview(self):
        revision = subprocess.check_output(["git", "-C", str(self.manager.source), "rev-parse", "--short", "HEAD"], text=True).strip()
        print(f"\nDépôt : {self.manager.source}\nRévision : {revision}\nÉtat privé : {self.manager.state}")
        print("Configuration du site : " + ("présente" if self.config.path.exists() else "à préparer"))
        print("État des mises à jour : " + str(self.manager.updater_state))
        for file in (Path("/var/lib/omni-siem/install-state.json"), Path("/etc/omni-siem/instance.json")):
            if file.exists():
                state = json.loads(file.read_text())
                print(file.name + " : " + json.dumps({key: state.get(key) for key in ("profile", "source_revision", "extras", "completed_phases", "current_phase", "finished_at") if key in state}, ensure_ascii=False))

    def catalogue(self):
        data = inventory(self.manager.source)
        print(f"\n{data['tracked_files']} fichiers suivis ; inventaire complet par composant.")
        for item in data["components"]:
            print(f"\n[{item['id']}] {item['name']} ({item['file_count']} fichiers)\n  {item['automation']}\n  Documentation : {item['documentation']}")
        choice = prompt("Voir tous les fichiers d'un composant (identifiant) ou 'scripts'", "")
        if choice == "scripts":
            for item in data["scripts"]:
                print(item["path"] + " : " + item["policy"])
        else:
            for item in data["components"]:
                if item["id"] == choice:
                    print("\n".join(item["files"]))
        print(data["scope"])

    def history(self):
        jobs = self.manager.history()
        if not jobs:
            print("Aucune opération enregistrée.")
            return
        choice = menu("Historique (journaux masqués)", [f"{j['created_at']} — {ACTION_LABELS.get(j['action'], j['action'])} — {j['status']}" for j in jobs])
        if 1 <= choice <= len(jobs):
            print("\n".join(jobs[choice - 1]["lines"]))

    def main(self):
        while True:
            choice = menu("OMNI SIEM — Administration locale SSH", [
                "État et révision", "Configurer le site et les secrets", "Installer / reprendre une instance neuve",
                "Préparer et appliquer une mise à jour", "WatchGuard / UniFi / Palo Alto", "Publier / réparer /soc/",
                "Catalogue de tous les composants et scripts", "Historique des opérations"])
            if choice == 0:
                return 0
            action = {1: self.overview, 2: self.configure, 3: self.installation, 4: self.updates, 5: self.modules,
                      6: lambda: self.run("console_publish"), 7: self.catalogue, 8: self.history}.get(choice)
            if action:
                try:
                    action()
                except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
                    print("\nOpération refusée ou en échec : " + str(exc))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Administration OMNI SIEM depuis un terminal SSH, sans serveur web.")
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/omni-siem-manager"))
    parser.add_argument("--updater-state-dir", type=Path, default=Path("/var/lib/omni-siem-updater"), help="état existant de l'outil de mise à jour")
    parser.add_argument("--inventory", action="store_true", help="inventaire JSON en lecture seule, sans menu")
    args = parser.parse_args(argv)
    if args.inventory:
        print(json.dumps(inventory(ROOT), indent=2, ensure_ascii=False))
        return 0
    if not sys.stdin.isatty():
        parser.error("un terminal interactif est requis (SSH avec TTY) ; utiliser --inventory pour l'inventaire JSON")
    if os.name != "posix":
        parser.error("l'administration s'exécute sur le serveur Linux cible")
    if os.geteuid() != 0:
        print("Mode sans privilèges : les opérations système pourront être refusées ; utiliser sudo pour installer.")
    try:
        return Terminal(ROOT, args.state_dir, args.updater_state_dir).main()
    except (EOFError, KeyboardInterrupt):
        print("\nSession terminée. Examiner les journaux et l'état avant une reprise.")
        return 130
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print("Gestionnaire indisponible : " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
