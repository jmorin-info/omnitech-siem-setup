# Dossier de preuves — Audit ISO/IEC 27001:2022 (généré le 2026-06-18)

Document **généré automatiquement** depuis la plateforme SIEM/XDR en production
(`68-iso-evidence.sh`). Preuve **datée et reproductible** pour le Stage 2 (nov. 2026).
Chaque section référence le ou les contrôles de l'Annexe A qu'elle atteste.

## A.8.15 — Journalisation (collecte centralisée et inviolable)
- Streams OMNI actifs : **11**. Cluster OpenSearch : **green**. Échecs d'indexation : **20**.
- Sources émettant sur 24 h : fortigate(12126308), windows_security(4731742), sysmon(4549619), windows(1183827), vsphere(955081), bunkerweb(96579), m365(71688), vaultwarden(55865), inventory(30384), forti_dhcp(19164), veeam(415), eset(85), cert_parc(56), adcs(30), xdr_incident(7), siem_integrity(1)
- Rétention par paliers documentée (`docs/POLITIQUE-RETENTION.md`) ; intégrité par chaîne HMAC (`omni-integrity`, `docs/PROCEDURE-INTEGRITE-PREUVE.md`).

## A.8.16 — Surveillance des activités
- Définitions d'événements (détections) actives : **101**.
- Tags de détection distincts : **69**, mappés MITRE ATT&CK.
- Volume de détections : **38800** sur 7 j, **38800** sur 30 j.
- Incidents corrélés (oms-xdr) sur 30 j : **7**.
- Tableau de bord temps réel « OMNI - SOC » + page « OMS-XDR » ; UEBA/NDR comportemental.

## A.5.7 — Renseignement sur les menaces
- Couverture MITRE ATT&CK : **48 techniques** sur **12 tactiques** (calque `docs/mitre-navigator-layer.json`).
- Threat intel IOC (abuse.ch, refresh quotidien) : **5 IP de C2** (Feodo), **2504 domaines malveillants** (URLhaus) ; + Tor/Spamhaus, CISA KEV.

## A.5.24 / A.5.25 / A.5.26 — Gestion, appréciation et réponse aux incidents
- Corrélation kill-chain (oms-xdr) + scoring de risque (MITRE + UEBA 0-100).
- Réponse : SOAR-light (blocage IP via feed FortiGate, sans creds) ; actionneurs ESET/AD en dry-run (human-in-the-loop) ; notification 2-tiers + **app mobile PWA** (alertes/push, VPN-only).
- Procédures : `docs/PROCEDURE-INCIDENT.md`, `docs/REPONSE-AUTOMATISEE.md`.

## A.8.32 — Gestion du changement / A.5.37 — Procédures d'exploitation
- Tout le provisioning sous Git (dépôt privé) ; scripts idempotents ; procédures `docs/PRO-EXPLOITATION-SIEM.md`.
- **Clause 10** : registre d'amélioration continue daté & vérifié — `docs/REGISTRE-AMELIORATION-CONTINUE.md`.

## A.8.13 — Sauvegarde / A.8.8 — Vulnérabilités
- Sauvegarde config quotidienne chiffrée + export NAS (`30-backup-config.sh`), PRA `docs/PRA-RECONSTRUCTION-SIEM.md`.
- Vulnérabilités : corrélation CISA KEV + ancienneté de patch (`38-vuln-scan.sh`).

---
*Services de supervision continue actifs : active
active. Pour régénérer : `bash 68-iso-evidence.sh`.*
