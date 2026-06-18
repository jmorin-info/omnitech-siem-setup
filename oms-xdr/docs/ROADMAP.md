# ROADMAP OMS-XDR — tâches actionnables

Chaque tâche est autonome et testable. Respecter les conventions de `BRIEF.md`
(français en sortie, dry-run par défaut, détection pilotée par `rules.yaml`,
un test par ajout).

## T1 — Runbooks AD signés (priorité haute)
Rendre `responder._disable_ad_account` / `_force_pwd_reset` réellement exécutables.
- Implémenter un appel NinjaOne (script PowerShell signé) ou WinRM vers `10.33.50.250`.
- PowerShell : `Disable-ADAccount` / `Set-ADAccountPassword -Reset` + `Revoke-AzureADUserAllRefreshToken` (Entra).
- Garder le double verrou `dry_run`/`auto_disable_ad_account`.
- Tester l'échec d'API (compte introuvable, droits insuffisants) sans crash.
- **DoD** : test mockant l'appel + log WARNING tracé.

## T2 — Threat intelligence
Nouveau signal `S_C2_IOC` croisant les flux sortants FortiGate avec des IOC.
- Créer/alimenter une lookup table Graylog (abuse.ch Feodo, OTX) — script de sync dans `deploy/`.
- Pipeline rule Graylog taguant `threat_intel:true` sur match.
- Ajouter `S_C2_IOC` dans `rules.yaml` + l'intégrer à `CR_EXECUTION_C2` (any_of).
- **DoD** : test de corrélation avec IOC simulé.

## T3 — Signaux Sysmon
Une fois Sysmon déployé via NinjaOne :
- Signaux : `S_PROC_INJECTION` (Sysmon 8/10, T1055), `S_LSASS_ACCESS` (Sysmon 10 sur lsass, T1003.001), `S_SUSP_PARENT_CHILD` (office→cmd/powershell).
- Nouvelle règle `CR_ENDPOINT_COMPROMISE` reliant injection + accès LSASS.
- **DoD** : règles + tests + entrées MITRE_CONTEXT dans `remediation.py`.

## T4 — Détection d'anomalies (EWMA)
Remplacer les seuils fixes par une baseline adaptative par entité.
- Stocker moyennes/écarts mobiles dans `state_dir` (EWMA, α≈0.3).
- Déclencher si valeur > moyenne + k·σ (k configurable).
- Conserver un mode `static`/`ewma` par signal dans `rules.yaml`.
- **DoD** : module `anomaly.py` + tests sur séries synthétiques.

## T5 — Corrélation vulnérabilités
Croiser les ports découverts par `netscan` avec la matrice CVSS (POL_018).
- Mapper service/port → CVE connues (source : Graylog lookup ou fichier local).
- Prioriser les deltas `new_open_port` exposant un service vulnérable.
- **DoD** : signal `S_VULN_EXPOSED` + test.

## T6 — Dashboard & reporting
- Provisionner via API un dashboard « OMS-XDR Incidents » (widgets : incidents par sévérité,
  top techniques MITRE, top entités) — script dans `deploy/`.
- Rapport hebdomadaire (HTML/PDF) des incidents — réutiliser le pipeline docx SEAL
  (navy #004469, orange #F68D2E, taupe #837274, Arial).
- **DoD** : script de provisionnement + exemple de rapport généré.
