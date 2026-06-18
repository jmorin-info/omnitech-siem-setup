"""Playbooks de remédiation OMS-XDR.

Associe chaque règle / technique à des actions concrètes adaptées à
l'infrastructure OMNITECH (FortiGate, AD, NinjaOne, Entra, Vaultwarden).
Sortie : texte d'aide à la décision + actions automatisables (clé 'action').
"""
from __future__ import annotations

from typing import Any

# Chaque entrée : liste d'étapes. step.action (optionnel) = action automatisable
#   block_fortigate | disable_ad_account | force_pwd_reset | isolate_ninjaone
PLAYBOOKS: dict[str, dict[str, Any]] = {
    "CR_RECON_TO_ACCESS": {
        "summary": "Scan de reconnaissance puis tentative d'accès par force brute.",
        "steps": [
            {"text": "Bloquer l'IP source au niveau FortiGate (groupe OMS-XDR-Blocklist + policy deny en tête).",
             "action": "block_fortigate"},
            {"text": "Vérifier si l'IP est interne (poste compromis) ou externe (exposition). "
                     "Si interne : isoler l'hôte via NinjaOne et lancer un scan ESET EDR.",
             "action": "isolate_ninjaone"},
            {"text": "Contrôler l'exposition des services scannés (RDP/SMB/SSL-VPN) et restreindre par trusthost/geo-IP."},
            {"text": "Corréler avec les logs SSL-VPN FortiGate : confirmer absence d'authentification réussie."},
        ],
    },
    "CR_CRED_ABUSE": {
        "summary": "Force brute aboutie sur un compte : connexion réussie après échecs massifs.",
        "steps": [
            {"text": "Forcer la réinitialisation du mot de passe du compte et révoquer les sessions Kerberos/refresh tokens.",
             "action": "force_pwd_reset"},
            {"text": "Désactiver temporairement le compte si activité hors plage horaire / source inhabituelle.",
             "action": "disable_ad_account"},
            {"text": "Vérifier l'inscription MFA Entra ID (Conditional Access) ; sortir le compte de CA-Exclusion-ComptesService si présent à tort."},
            {"text": "Rechercher les connexions latérales (4624 LogonType 3/10) depuis la même source dans les 24 h."},
        ],
    },
    "CR_PRIV_ESCALATION": {
        "summary": "Création de compte ou ajout à un groupe privilégié sans changement validé.",
        "steps": [
            {"text": "Croiser avec le registre des changements : si non autorisé, retirer immédiatement l'appartenance au groupe."},
            {"text": "Auditer l'auteur (SubjectUserName) : compte légitime compromis ou attaquant ?"},
            {"text": "Réinitialiser le compte auteur si compromission confirmée.",
             "action": "force_pwd_reset"},
            {"text": "Activer une alerte renforcée sur Domain Admins / Enterprise Admins (event 4732/4756)."},
        ],
    },
    "CR_AD_CREDENTIAL_THEFT": {
        "summary": "Vol d'identifiants AD (Kerberoasting ou DCSync) — incident critique.",
        "steps": [
            {"text": "DCSync : isoler le poste source, déclencher la procédure IR. Double rotation du compte krbtgt (2x avec délai de réplication)."},
            {"text": "Kerberoasting : réinitialiser les mots de passe des comptes de service ciblés (escrow Vaultwarden), forcer le chiffrement AES, auditer les SPN."},
            {"text": "Désactiver les comptes de service exposés et passer en gMSA si possible.",
             "action": "disable_ad_account"},
            {"text": "Rechercher persistance : tâches planifiées, services, golden ticket (durée de vie TGT anormale)."},
        ],
    },
    "CR_EXECUTION_C2": {
        "summary": "Exécution PowerShell offensive corrélée à des flux sortants suspects (C2).",
        "steps": [
            {"text": "Isoler immédiatement l'hôte via NinjaOne (containment réseau).",
             "action": "isolate_ninjaone"},
            {"text": "Bloquer les destinations sortantes au FortiGate et extraire les IOC (IP/domaines/hashes).",
             "action": "block_fortigate"},
            {"text": "Collecter le ScriptBlock complet (4104) et l'arborescence de processus (Sysmon 1 / 4688)."},
            {"text": "Lancer une analyse ESET EDR + recherche rétro-active des mêmes IOC sur tout le parc."},
        ],
    },
    "CR_LATERAL_FROM_SCAN": {
        "summary": "Scan interne depuis un hôte du parc : mouvement latéral probable.",
        "steps": [
            {"text": "Identifier l'hôte source du delta de ports et vérifier sa légitimité (outil d'admin vs activité anormale)."},
            {"text": "Isoler l'hôte si non autorisé et analyser les connexions vers les nouveaux ports détectés.",
             "action": "isolate_ninjaone"},
            {"text": "Confirmer que le delta n'est pas un changement légitime (déploiement, nouveau service) avant d'escalader."},
        ],
    },
    "CR_LSASS_THEFT": {
        "summary": "Accès à la mémoire LSASS : vol probable d'identifiants (dump type mimikatz).",
        "steps": [
            {"text": "Isoler immédiatement l'hôte (NinjaOne, containment réseau).",
             "action": "isolate_ninjaone"},
            {"text": "Réinitialiser les comptes connectés sur cet hôte + révoquer les sessions Kerberos.",
             "action": "force_pwd_reset"},
            {"text": "Analyse ESET EDR, capture mémoire, recherche d'outils de credential dumping."},
        ],
    },
    "CR_RANSOMWARE": {
        "summary": "Indicateur de rançongiciel : destruction des clichés/sauvegardes (vssadmin/wbadmin/bcdedit).",
        "steps": [
            {"text": "Isoler l'hôte IMMÉDIATEMENT (NinjaOne) et couper ses accès aux partages.",
             "action": "isolate_ninjaone"},
            {"text": "Bloquer les destinations sortantes suspectes (feed SOAR) et extraire les IOC.",
             "action": "block_fortigate"},
            {"text": "Déclencher le plan rançongiciel : vérifier l'intégrité des sauvegardes Veeam (3-2-1-1), évaluer le périmètre chiffré."},
        ],
    },
    "CR_AD_CERT_PERSIST": {
        "summary": "Persistance AD par certificat (ESC) ou shadow credentials (msDS-KeyCredentialLink).",
        "steps": [
            {"text": "Désactiver le compte concerné et retirer la clé/credential ajouté (KeyCredentialLink).",
             "action": "disable_ad_account"},
            {"text": "Révoquer les certificats illégitimes (AD CS), corriger les gabarits vulnérables (ESC1/ESC8).",
             "action": "force_pwd_reset"},
            {"text": "Rechercher la compromission amont (qui a écrit l'attribut / demandé le certificat ?)."},
        ],
    },
    "CR_DEFENSE_NEUTRALIZED": {
        "summary": "Neutralisation des défenses : sabotage de l'audit, désactivation Defender ou arrêt d'un service de sécurité.",
        "steps": [
            {"text": "Isoler l'hôte (NinjaOne) — la coupure des défenses précède souvent une action destructive.",
             "action": "isolate_ninjaone"},
            {"text": "Restaurer l'audit / réactiver Defender, identifier l'auteur et le processus à l'origine."},
            {"text": "Analyse ESET EDR + recherche rétro-active des mêmes TTP sur le parc."},
        ],
    },
    "CR_LATERAL_MOVEMENT": {
        "summary": "Mouvement latéral confirmé : un compte ouvre des sessions sur plusieurs hôtes ou exécute via WMI.",
        "steps": [
            {"text": "Réinitialiser le compte utilisé et isoler les hôtes pivots si compromission confirmée.",
             "action": "force_pwd_reset"},
            {"text": "Tracer le chemin (hôte source -> cibles), rechercher l'origine (vol d'identifiants amont)."},
            {"text": "Vérifier l'absence de persistance déposée sur les hôtes atteints."},
        ],
    },
    "CR_EXPOSED_SERVICE": {
        "summary": "Service interne exposé sur Internet : surface d'attaque à réduire.",
        "steps": [
            {"text": "Confirmer la légitimité de l'exposition ; sinon restreindre/fermer la règle FortiGate."},
            {"text": "Durcir le service exposé (MFA, géo-IP, trusthost), vérifier son niveau de patch (KEV)."},
        ],
    },
}

# Fiches techniques MITRE (contexte court ajouté à la narration)
MITRE_CONTEXT: dict[str, str] = {
    "T1046": "Network Service Discovery — scan de services pour cartographier la cible.",
    "T1110": "Brute Force — devinette d'identifiants par essais répétés.",
    "T1078": "Valid Accounts — usage d'identifiants légitimes compromis.",
    "T1078.002": "Valid Accounts: Domain Accounts.",
    "T1136": "Create Account — création de compte pour persistance.",
    "T1098": "Account Manipulation — modification de droits/groupes.",
    "T1558.003": "Kerberoasting — extraction de tickets TGS pour crack offline.",
    "T1003.006": "DCSync — réplication AD abusive pour extraire les secrets.",
    "T1059.001": "PowerShell — exécution de commandes/scripts offensifs.",
    "T1071": "Application Layer Protocol — C2 sur protocole applicatif.",
    "T1021": "Remote Services — mouvement latéral via services distants.",
    "T1003.001": "LSASS Memory — extraction d'identifiants depuis la mémoire de LSASS.",
    "T1486": "Data Encrypted for Impact — chiffrement des données (rançongiciel).",
    "T1490": "Inhibit System Recovery — destruction des sauvegardes/clichés.",
    "T1649": "Steal or Forge Authentication Certificates — abus AD CS (ESC).",
    "T1556.005": "Modify Authentication Process — shadow credentials (KeyCredentialLink).",
    "T1562.001": "Impair Defenses: Disable or Modify Tools.",
    "T1562.002": "Impair Defenses: Disable Windows Event Logging.",
    "T1047": "Windows Management Instrumentation — exécution / mouvement latéral via WMI.",
    "T1190": "Exploit Public-Facing Application — exploitation d'un service exposé.",
}


def build_remediation(rule_id: str, mitre: list[str]) -> dict[str, Any]:
    pb = PLAYBOOKS.get(rule_id, {"summary": "Investigation manuelle requise.", "steps": []})
    lines = [f"Résumé : {pb['summary']}", ""]
    for tech in mitre:
        if tech in MITRE_CONTEXT:
            lines.append(f"• {tech} — {MITRE_CONTEXT[tech]}")
    if mitre:
        lines.append("")
    lines.append("Actions recommandées :")
    actions: list[str] = []
    for i, step in enumerate(pb["steps"], 1):
        tag = f" [auto:{step['action']}]" if step.get("action") else ""
        lines.append(f"  {i}. {step['text']}{tag}")
        if step.get("action"):
            actions.append(step["action"])
    return {"text": "\n".join(lines), "actions": actions}
