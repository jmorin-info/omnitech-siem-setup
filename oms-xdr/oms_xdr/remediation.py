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
    "CR_DECEPTION_TRIGGERED": {
        "summary": "Un leurre (honeytoken OMNI Sentinel) a été touché : aucun usage légitime "
                   "possible → compromission quasi-certaine, à traiter comme une intrusion confirmée.",
        "steps": [
            {"text": "Identifier la SOURCE (hôte/IP à l'origine du contact avec le leurre) et l'isoler "
                     "immédiatement (NinjaOne). Le compte/SPN/canari touché n'est qu'un appât.",
             "action": "isolate_ninjaone"},
            {"text": "Croiser avec le jumeau d'attaque (console → Jumeau) : si la source est un chokepoint "
                     "ou à courte distance d'un joyau, escalader en priorité maximale."},
            {"text": "Réinitialiser le compte réel utilisé par l'attaquant + révoquer ses tickets Kerberos.",
             "action": "force_pwd_reset"},
            {"text": "Chasser le mouvement latéral, la persistance et les autres leurres touchés (vue Entités). "
                     "Préserver les preuves. Remonter au RSSI sans délai."},
        ],
    },
    "CR_ENDPOINT_MALWARE": {
        "summary": "Malware détecté par l'AV FortiClient sur un poste (éventuellement avec la "
                   "protection désactivée/altérée = signe d'attaquant actif).",
        "steps": [
            {"text": "Isoler le poste (NinjaOne) si la protection a été désactivée ou si le malware "
                     "n'est pas en quarantaine (échec de nettoyage).",
             "action": "isolate_ninjaone"},
            {"text": "Vérifier dans FortiClient EMS l'action (quarantine/blocked vs detected-only), le "
                     "chemin du fichier et l'utilisateur ; lancer un scan complet EDR."},
            {"text": "Si la protection temps-réel a été désactivée : traiter comme intrusion (l'attaquant "
                     "a désarmé l'AV) — réinitialiser le compte de l'utilisateur, chasser persistance + latéral."},
            {"text": "Identifier la source (pièce jointe, téléchargement, clé USB) et bloquer le vecteur."},
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
    "CR_CREDDUMP_PERSIST": {
        "summary": "Vol d'identifiants LSASS suivi immédiatement d'un mécanisme de persistance (service/tâche) sur le même hôte.",
        "steps": [
            {"text": "Isoler l'hôte IMMÉDIATEMENT (NinjaOne, containment réseau) — séquence dump+persistance = compromission active.",
             "action": "isolate_ninjaone"},
            {"text": "Réinitialiser tous les comptes connectés récemment sur cet hôte + révoquer les sessions Kerberos.",
             "action": "force_pwd_reset"},
            {"text": "Identifier et supprimer le service (4697) / la tâche planifiée (4698) déposés ; capturer le binaire/ScriptBlock associé."},
            {"text": "Analyse ESET EDR + recherche rétro-active du même outil de dump et de la même persistance sur tout le parc."},
        ],
    },
    "CR_OFFENSIVE_PS_PERSIST": {
        "summary": "PowerShell offensif suivi d'un dépôt de persistance (autorun/service/tâche) sur le même hôte.",
        "steps": [
            {"text": "Isoler l'hôte (NinjaOne) et geler l'état (mémoire/processus) avant nettoyage.",
             "action": "isolate_ninjaone"},
            {"text": "Collecter le ScriptBlock complet (4104) et l'arborescence Sysmon (1/13) ; extraire les IOC."},
            {"text": "Supprimer la persistance déposée (clé Run/autorun, service, tâche) après preuve ; vérifier l'absence d'autres ancrages."},
            {"text": "Recherche rétro-active des mêmes TTP (PS offensif + persistance) sur le parc via le SIEM."},
        ],
    },
    "CR_CREDUSE_ADMINSHARE": {
        "summary": "Usage d'identifiants explicites (4648) suivi d'un accès à un partage administratif (5140) sur le même hôte.",
        "steps": [
            {"text": "Qualifier l'usage 4648 : outil d'admin légitime (PsExec/RunAs planifié) ou détournement d'identifiants ?"},
            {"text": "Vérifier la cible du partage admin (C$/ADMIN$) et l'IP source ; tracer le compte employé."},
            {"text": "Si non légitime : réinitialiser le compte utilisé et isoler l'hôte source.",
             "action": "force_pwd_reset"},
            {"text": "Rechercher la propagation : mêmes identifiants utilisés vers d'autres hôtes (4648/5140) dans les 24 h."},
        ],
    },
    "CR_CREDDUMP_LATERAL": {
        "summary": "Vol d'identifiants LSASS puis accès à un partage administratif sur le même hôte (fenêtre 6 h) — amorce de mouvement latéral.",
        "steps": [
            {"text": "Isoler l'hôte (NinjaOne) et réinitialiser les comptes exposés (les identifiants volés servent déjà à se déplacer).",
             "action": "isolate_ninjaone"},
            {"text": "Révoquer les sessions Kerberos des comptes connectés ; forcer la rotation.",
             "action": "force_pwd_reset"},
            {"text": "Tracer les accès partage admin (5140) consécutifs : cartographier les hôtes atteints, chercher la persistance déposée."},
            {"text": "Analyse ESET EDR + chasse aux outils de credential dumping et au pass-the-hash sur le segment."},
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
    "T1543.003": "Create or Modify System Process: Windows Service — persistance par service.",
    "T1053.005": "Scheduled Task — persistance/exécution par tâche planifiée.",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder.",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares — accès C$/ADMIN$ (mouvement latéral).",
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
