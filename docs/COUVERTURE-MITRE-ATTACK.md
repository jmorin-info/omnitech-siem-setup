# Couverture MITRE ATT&CK — SIEM OMNITECH

> Généré/maintenu avec `57-mitre-coverage.sh` · Dernière revue : 2026-06-14
> Calque visuel : **`docs/mitre-navigator-layer.json`** → à charger dans
> [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (*Open Existing Layer*).

## Résumé exécutif
- **58 tags de détection mappés MITRE** (sous-ensemble des **88 définitions d'événements** :
  les alertes de santé/exploitation — backup, disque, robots… — n'ont pas de technique ATT&CK)
  → **44 techniques** ATT&CK distinctes → **12/14 tactiques** couvertes.
  *(màj 2026-06-14 : + Privilege Escalation comblée [uac_bypass/scheduled_task/service_install], + `m365_brute_externe` T1110 [spray cloud, donnée réelle], + `remote_discovery` T1018, + `service_stop_securite` T1489 → Discovery 3, Impact 4.)*
- Chaque détection pose un `alert_tag` mappé technique + tactique + score de risque (`lookups/mitre-attack.csv`), réutilisé par le scoring d'hôte (UEBA), les alertes et les dashboards.
- Les 2 tactiques non couvertes (**Reconnaissance**, **Resource Development**) sont **hors périmètre** d'un SIEM défensif interne (scan externe pré-compromission / acquisition d'infra attaquant — non visibles côté défenseur). Couverture *effective* = complète.

## Couverture par tactique
| Tactique | Techniques | Exemples de détections |
|---|---|---|
| Initial Access | 3 | exposition_internet (T1190), m365_risque/impossible_travel (T1078), waf_block |
| Execution | 3 | powershell_suspect (T1059.001), defender (T1204.002), eset_detection |
| Persistence | 4 | persistence_autorun (T1547.001), local_account_create (T1136), m365_role (T1098) |
| **Privilege Escalation** | **3** | **uac_bypass (T1548.002), scheduled_task (T1053.005), service_install (T1543.003)** — *ajouté 2026-06-14* |
| Defense Evasion | 7 | winsec_critique (T1562.002), sysmon_injection (T1055), lolbin_suspect (T1218), masquerading |
| Credential Access | 11 | lsass_access (T1003.001), dcsync (T1003.006), kerberoasting (T1558.003), adcs_abuse (T1649), gpp_creds, vault_auth_fail |
| Discovery | 2 | network_scan (T1046), ldap_recon (T1087.002) |
| Lateral Movement | 3 | lateral_movement (T1021), wmi_lateral_exec (T1047), admin_share (T1021.002) |
| Collection | 1 | m365_mail_forward (T1114.003) |
| Command and Control | 2 | beaconing/threat_intel (T1071), dns_tunneling (T1071.004) |
| Exfiltration | 2 | data_exfil/volume_spike (T1048), m365_partage_externe (T1567) |
| Impact | 3 | ransomware_indicator (T1486), vsphere_vm_destroy (T1485), veeam_job_echec (T1490) |

## Trous & axes d'enrichissement (priorisés)
1. **Collection (1) / Exfiltration (2)** — ajouter T1005 (données poste local), T1039 (partages réseau), T1056 (capture d'entrée). *[P2]*
2. **Discovery (2)** — ajouter T1018 (remote system discovery), T1482 (trust de domaine), T1057/T1083. *[P2]*
3. **Lateral Movement** — ajouter **T1550** (Pass-the-Hash / Pass-the-Ticket) — clé en environnement AD. *[P1]*
4. **Initial Access** — **T1566 (Phishing)** : nécessite la télémétrie de sécurité mail (au-delà de M365 signin). *[P2, dépend source]*
5. **Impact** — T1489 (Service Stop), T1498 (DoS). *[P3]*
6. **Execution/Persistence** — T1059.003 (cmd), T1505.003 (web shell sur IIS/serveurs exposés). *[P2]*

## Validation (purple team) — prouver que ça se déclenche
Méthode : exécuter le test [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) correspondant sur un poste **de test** et vérifier que le SIEM lève l'`alert_tag` attendu (page Investigation → `alert_tag:<tag>`), idéalement l'alerte.

| Technique | Test Atomic | `alert_tag` attendu | Source |
|---|---|---|---|
| T1003.001 LSASS | T1003.001 (comsvcs/procdump) | `lsass_access` | Sysmon 10 |
| T1558.003 Kerberoasting | T1558.003 | `kerberoasting` | 4769 |
| T1053.005 Scheduled Task | T1053.005 (`schtasks /create`) | `scheduled_task` | 4698 |
| T1543.003 Service | T1543.003 (`sc create`) | `service_install` | 4697 |
| **T1548.002 UAC bypass** | T1548.002 (fodhelper) | `uac_bypass` | Sysmon 1 |
| T1547.001 Run keys | T1547.001 | `persistence_autorun` | Sysmon 13 |
| T1059.001 PowerShell | T1059.001 (encoded) | `powershell_suspect` | 4104 |
| T1218 LOLBin | T1218.010 (regsvr32) | `lolbin_suspect` | Sysmon 1 |
| T1046 Network scan | T1046 | `network_scan` | FortiGate |
| T1087.002 LDAP recon | T1087.002 | `ldap_recon` | 4662/Sysmon |
| T1562.002 Clear logs | T1070.001 (`wevtutil cl`) | `winsec_critique` | 1102 |

> ⚠️ Ne PAS jouer les tests destructifs (T1486 ransomware, T1485 destruction) en production.
> Tenir un journal des campagnes de validation (date, technique, détecté oui/non, MTTD) — utile aussi pour ISO A.8.16.

## Maintenance
À chaque nouvelle détection : ajouter la ligne dans `lookups/mitre-attack.csv` (via `add_mitre` dans le script de détection), puis **relancer `57-mitre-coverage.sh`** pour régénérer le calque Navigator et le bilan de couverture.
