# Dossier de preuves — Audit ISO/IEC 27001:2022 (généré le 2026-07-02)

Document **généré automatiquement** depuis la plateforme SIEM/XDR en production
(`68-iso-evidence.sh`). Preuve **datée et reproductible** pour le Stage 2 (nov. 2026).
Chaque section référence le ou les contrôles de l'Annexe A qu'elle atteste.

## A.8.15 — Journalisation (collecte centralisée et inviolable)
- Streams OMNI actifs : **16**. Cluster OpenSearch : **green**. Échecs d'indexation : **23**.
- Sources émettant sur 24 h : fortigate(14693860), windows_security(5791474), sysmon(5380797), windows(1392892), vsphere(1101882), m365(311393), bunkerweb(214370), vaultwarden(55265), inventory(32946), forti_dhcp(19743), vuln(2004), ueba_score(1446), alert_triage(944), fortimanager(857), aruba(842), ml_anomaly(720), veeam(561), ndr_scan(316), dns(277), collecte_sla(185)
- Rétention par paliers documentée (`docs/POLITIQUE-RETENTION.md`) ; intégrité par chaîne HMAC (`omni-integrity`, `docs/PROCEDURE-INTEGRITE-PREUVE.md`).

## A.8.16 — Surveillance des activités
- Définitions d'événements (détections) actives : **145**.
- Tags de détection distincts : **127**, mappés MITRE ATT&CK.
- Volume de détections : **96397** sur 7 j, **96402** sur 30 j.
- Incidents corrélés (oms-xdr) sur 30 j : **54**.
- Tableau de bord temps réel « OMNI - SOC » + page « OMS-XDR » ; UEBA/NDR comportemental.

## A.5.7 — Renseignement sur les menaces
- Couverture MITRE ATT&CK : **74 techniques** sur **19 tactiques** (calque `docs/mitre-navigator-layer.json`).
- Threat intel IOC (abuse.ch, refresh quotidien) : **5 IP de C2** (Feodo), **2205 domaines malveillants** (URLhaus) ; + Tor/Spamhaus, CISA KEV.

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
