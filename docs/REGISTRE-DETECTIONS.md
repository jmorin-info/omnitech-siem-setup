# Registre des règles de détection — SIEM OMNITECH

> Catalogue **exhaustif** des **88 définitions d'événements** actives (alertes
> Graylog ; 87 règles d'agrégation + 1 événement système), classées par domaine.
> Sert de preuve de couverture de surveillance (ISO 27001 **A.8.16**) et de
> référence d'exploitation. *Dernière revue : 2026-06-14 (recoupé live).*
>
> **Priorités** : **P3 = critique** (action immédiate) · **P2 = important** (à
> traiter rapidement). **Tier** de notification : **M** = e-mail « réveille-moi »
> (compromission confirmée / santé SIEM) · **T** = Teams (firehose, toutes les
> alertes). Anti-tempête par entité (`group_by`), grâce ≥ 60 min sur le tier mail.
>
> Source de vérité : définitions Graylog (`13-graylog-alerts.sh`, `16-m365-input.sh`,
> `21-alert-hygiene.sh`, `36-soar.sh`, `47-detections-extra.sh`, `48`, modules 37-46,
> `59-file-audit.sh`, `60-integrity.sh`). Tag MITRE via `lookups/mitre-attack.csv`.

## Répartition

| Priorité | Nombre | Tier mail | Tier Teams |
|----------|--------|-----------|------------|
| P3 (critique) | 54 | — | — |
| P2 (important) | 33 | — | — |
| **Total agrégation** | **87** | **26 (mail)** | **87 (Teams)** |

> Toutes les alertes vont à **Teams** (firehose) ; **26** critiques vont **aussi**
> au mail (cf. `KEEP[]` de `22-alert-routing.sh`). Au-delà des définitions, des
> **tags d'enrichissement** posés au pipeline n'ont pas d'alerte dédiée (anti-bruit) :
> `persistence_autorun` (T1547.001), `remote_discovery` (T1018), `service_stop_securite`
> (T1489), `threat_intel`, `explicit_cred_use` — visibles en investigation/dashboards.

---

## 1. Identité & Active Directory (A.8.2 / A.8.5 / A.5.18)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| Force brute (≥10 échecs / compte / 10 min) | P3 | T | 4625 agrégé par compte (exclut `*$`/ninjaone/ADSync) | T1110 |
| Password spraying (≥8 comptes / IP / 10 min) | P3 | T | 4625, `card(user)` par IP | T1110.003 |
| Force brute SUIVIE d'un succès (même compte / 15 min) | P3 | **M** | 4625 puis 4624 | T1110 |
| Tentative sur compte désactivé | P2 | T | échec motif `compte_desactive` | T1078 |
| Compte verrouillé (4740) | P2 | T | verrouillage AD (effet spraying) | — |
| Compte créé dans le domaine (4720) | P2 | T | création de compte AD | T1136.002 |
| Création de compte LOCAL (4720 hors DC) | P2 | T | compte local hors contrôleur | T1136.001 |
| Ajout au groupe Administrateurs LOCAL (4732) | P2 | T | élévation locale | T1098 |
| Modification d'un groupe privilégié | P3 | T | 4728/4732/4756 (`priv_group_label`) | T1098 |
| DCSync suspect | P3 | **M** | 4662 GUID réplication DS | T1003.006 |
| Kerberoasting suspect (≥5 SPN / compte / 10 min) | P3 | T | 4769 RC4/anormaux | T1558.003 |
| Kerberos RC4 / downgrade | P3 | T | `kerberos_rc4` (downgrade chiffrement) | T1558.003 |
| AS-REP roasting (compte sans pré-auth) | P3 | T | 4768 `PreAuthType=0` | T1558.004 |
| Shadow Credentials (msDS-KeyCredentialLink) | P3 | T | modif clé d'authentification | T1556.005 |
| Abus AD CS / certificats (ESC1-ESC8) | P3 | T | `adcs_abuse` | T1649 |
| Accès credentials GPP/SYSVOL | P3 | T | `gpp_creds_access` | T1552.006 |
| Reconnaissance LDAP (énumération annuaire) | P3 | T | `ldap_recon` | T1087.002 |
| Modification de GPO par un humain (5136) | P3 | T | `groupPolicyContainer`, hors SYSTEM/`*$` | T1484.001 |
| Connexion compte admin (adm-*) hors heures ouvrées | P3 | T | 4624 adm-* + `off_hours:oui` | T1078 |
| Échec logon service/batch (compte de service cassé) | P3 | T | 4625 LogonType 4/5 | — |
| Balayage de partages admin (≥3 hôtes / compte / 15 min) | P3 | T | 5140 `card(host)` | T1021.002 |

## 2. Endpoint & exécution / élévation (A.8.7)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| Accès mémoire LSASS (vol de credentials) | P2 | T | Sysmon 10 → lsass.exe | T1003.001 |
| Injection de processus (Sysmon 8/25) | P2 | T | CreateRemoteThread / tamper | T1055 |
| PowerShell suspect | P2 | T | 4104 encodé / `-enc` / FromBase64 | T1059.001 |
| LOLBin suspect (binaire système détourné) | P2 | T | certutil/regsvr32/rundll32/mshta/bitsadmin | T1218 |
| Masquerading (binaire système déplacé/renommé) | P2 | T | nom légitime hors chemin attendu | T1036.005 |
| Usage de credentials explicites (RunAs / lateral) | P2 | T | 4648 hors `*$`/self | T1078 |
| Exécution à distance WMI (lateral) | P2 | T | `wmi_lateral_exec` | T1047 |
| **Contournement UAC (élévation)** | P3 | **M** | Sysmon 1 : fodhelper/eventvwr/sdclt… → shell | T1548.002 |
| Defender : détection ou désactivation | P3 | T | Defender Operational (détection/AV off) | T1562.001 |
| Indicateur de ransomware (suppression shadow copies) | P3 | **M** | vssadmin/wmic shadow delete | T1490 / T1486 |
| Nouveau service installé (7045) | P2 | T | service système hors agents connus | T1543.003 |
| Service Windows installé (hors svchost) | P2 | T | 4697 hors svchost légitime | T1543.003 |
| Tâche planifiée créée (4698) | P2 | T | `scheduled_task`, agrégé hôte+compte | T1053.005 |

## 3. Réseau, VPN & exposition (A.8.20–A.8.22 / A.5.7)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| IP malveillante (Tor / Spamhaus) | P3 | T | threat-intel lookup sur IP publique | T1071 |
| FortiGate : virus / IPS | P3 | T | UTM (virus/ips/attack) | — |
| Service exposé sur Internet (port à risque) | P3 | T | `exposition_internet` (WAN→port risqué accepté) | T1190 |
| Force brute portail VPN (≥30 échecs / IP / h) | P2 | T | `subtype:vpn status:failure` → **SOAR** | T1110 |
| VPN monté depuis l'étranger | P3 | T | tunnel `remip` hors FR | T1133 |
| Scan réseau interne (reconnaissance / lateral) | P2 | T | `ndr_scan` / `network_scan` | T1046 |
| SOAR : IP bloquée automatiquement | P3 | T | action `omni-soar` (telemetry) | — |

## 4. Cloud Microsoft 365 / Entra (A.5.23)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| Compte M365 à risque (Entra ID Protection) | P3 | **M** | `m365_type:risk` atRisk (ML Microsoft), agrégé compte | T1078 |
| M365 connexion réussie hors France | P3 | T | `m365_etranger` (signin réussi non-FR) | T1078 |
| M365 modification de rôle privilégié | P3 | T | `m365_role` (rôle admin Entra) | T1098 |
| M365 transfert mail vers domaine externe | P3 | **M** | `m365_mail_forward` | T1114.003 |
| M365 délégation de boîte mail | P2 | T | `m365_mailbox_deleg` | T1098.002 |
| M365 partage externe / lien anonyme | P2 | T | `m365_partage_externe` | T1567 |
| M365 consentement OAuth applicatif | P2 | T | `m365_oauth_consent` | T1528 |
| M365 force brute (≥10 échecs / compte / 30 min) | P2 | T | signin échec agrégé compte | T1110 |
| Brute force M365 depuis l'étranger (spray cloud) | P2 | T | `m365_brute_externe` (échec non-FR / IP+compte) | T1110 |
| M365 suppression massive de fichiers (≥100 / compte / 15 min) | P2 | T | FileDeleted/Recycled | T1485 |
| Échecs AD + connexion M365 étrangère (même compte / 1 h) | P3 | T | corrélation 4625 + `m365_etranger` | T1078 |

## 5. UEBA / NDR / corrélation (A.5.7 / A.8.16)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| Incident critique (kill-chain corrélée) | P3 | **M** | `omni-incident-correlate` (multi-étapes) | — |
| Impossible travel (compte multi-localisé) | P3 | **M** | `ueba_geo` impossible travel | T1078 |
| Nouveau pays pour un compte (first-seen) | P3 | T | `ueba_geo` new_country | T1078.004 |
| Mouvement latéral réussi (1 compte → N hôtes) | P3 | **M** | `lateral_movement` (card host) | T1021 |
| Tunneling DNS suspect (exfiltration) | P3 | T | `ndr_dns` (entropie/sous-domaines) | T1071.004 |
| Anomalie de volume (z-score) | P3 | T | `volume_spike`/`volume_drop` | T1048 / T1562.001 |
| Hôte à risque élevé (score MITRE ≥15 / 1h) | P2 | T | somme `risk_score` par hôte | — |
| Entité à risque UEBA élevé (≥80) | P2 | T | `ueba_score` ≥ 80 | — |
| Beaconing / C2 suspect (NDR) | P2 | T | `ndr_beacon` (intervalle régulier) | T1071 |
| Exfiltration par volume (flux sortant anormal) | P2 | T | `ndr_exfil` / `data_exfil` | T1048 |

## 6. Coffre-fort, WAF, EDR & fichiers sensibles (A.8.7 / A.8.12 / A.5.23)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| Brute force coffre Vaultwarden (≥10 échecs / IP / 15 min) | P3 | **M** | `vault_auth_fail` (src_ip + compte) | T1555.005 |
| ESET : détection/menace antivirus | P2 | **M** | `eset_detection` (menace poste/serveur) | T1204 |
| BunkerWeb : pic de blocages WAF (≥20 / IP / 10 min) | P3 | T | `waf_block` agrégé IP | T1190 |
| WAF : scan applicatif (≥25 erreurs 404 / IP / 10 min) | P3 | T | HTTP 404 répétés / IP | T1190 |
| Accès massif à des fichiers sensibles (exfiltration ?) | P3 | **M** | `file_sensitive_access` ≥200 / compte / 10 min | T1039 |
| Suppressions massives de fichiers (ransomware ?) | P3 | **M** | `file_delete_sensible` ≥30 / compte / 10 min | T1485 |

## 7. Virtualisation vSphere (A.8.9)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| vSphere brute force (≥5 échecs / source / 10 min) | P2 | T | `vsphere_auth_fail` par src_ip | T1110 |
| vSphere accès SSH/Shell ESXi | P2 | T | `vsphere_shell_ssh` (ESXi shell — cf. note source) | T1059 |
| vSphere suppression de VM | P3 | T | `vsphere_vm_destroy` | T1485 |

## 8. Vulnérabilités, PKI & leurre (A.8.8 / A.8.16)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| Vulnérabilité KEV exploitée (à patcher en urgence) | P3 | T | `vuln_kev` (CISA Known Exploited) | T1190 |
| COMPTE CANARI touché (intrusion AD probable) | P3 | **M** | leurre AD (faux positifs ~nuls) | T1078 (decoy) |
| Certificat du parc expire bientôt | P3 | **M** | `cert_parc` (Get-OmniCertExpiry) | — |
| Certificat SIEM expire bientôt (<45j) | P3 | **M** | `siem_cert` auto-renouv. | — |

## 9. NPS / RADIUS (A.8.5)

| Règle | Prio | Tier | Logique | MITRE |
|-------|------|------|---------|-------|
| NPS : refus d'accès en masse (≥10 / compte / 15 min) | P3 | T | 6273/6274 (Wi-Fi/VPN RADIUS) | T1110 |

## 10. Santé SIEM, intégrité & exploitation (A.8.15 / A.8.16 / A.8.13)

| Règle | Prio | Tier | Logique | Contrôle |
|-------|------|------|---------|----------|
| Sabotage de l'audit (1102/4719/4794/104) | P3 | **M** | effacement/désactivation journalisation | A.8.15 / T1562.002 |
| **Intégrité des logs COMPROMISE (chaîne rompue)** | P3 | **M** | `siem_integrity` `integrity_state:compromis` | A.8.15 / A.5.28 |
| Silence Winlogbeat (0 log Windows / 15 min) | P3 | **M** | absence de flux Windows | A.8.16 (go-dark) |
| Hôte go-dark (collecte interrompue >26h) | P2 | T | `collecte_sla` `sla_type:go_dark` | A.8.16 |
| Robot d'analyse en panne (auto-supervision) | P3 | **M** | `siem_health` job_fail | A.8.16 |
| Disque SIEM >80% (/data) | P3 | **M** | `disk_warn` | A.8.6 (capacité) |
| PURGE D'URGENCE rétention (disque presque plein) | P3 | **M** | `disk_guard_prune` (≥88% → 82%) | A.8.6 |
| Backup config SIEM absent (>26h) / en échec | P3 | **M** | `backup_config_*` | A.8.13 |
| Veeam : job en échec ou avertissement | P3 | **M** | `veeam_job_echec` (résultat final eid 190) | A.8.13 / T1490 |
| Rapport hebdomadaire en échec | P3 | **M** | `omni-weekly-report` | A.5.25 (revue) |

---

## Maintenance du registre
À chaque ajout/retrait de définition (`13`/`16`/`47`/`48`/`59`/`60`…) : mettre à
jour la table concernée + la répartition. Compteurs vérifiables en direct :
`GET /api/events/definitions` (total) et `22-alert-routing.sh` (sortie « MAIL
conservé sur N »). Couverture technique : cf. **COUVERTURE-MITRE-ATTACK.md** +
le calque `mitre-navigator-layer.json`.
