# Volet Windows / Active Directory — étapes exactes

Tout ce qui se passe côté **DC (BX-AD-01-IT-VM / 10.33.50.250)** et côté
**postes/serveurs**. Ordre conseillé : 1 → 5, en pilote d'abord.

> **⭐ Voie recommandée (12/06) : `Install-OmniSiem-NinjaOne.ps1`** — script
> UNIQUE et definitif pour NinjaOne (SYSTEM, 64 bits, planification
> quotidienne). Il REMPLACE `Deploy-SiemAgents-NinjaOne.ps1` +
> `Set-OmniAudit-NinjaOne.ps1` : Root CA (TOFU), politique d'audit, Sysmon,
> Winlogbeat (restart seulement si la conf change), canal « Veeam Backup »
> ajouté automatiquement sur le serveur Veeam, et vérification de santé
> (test output 5044 + scan des erreurs de canal). Résumé [OK]/[KO] par
> composant, exit 1 si un composant est KO (visible dans NinjaOne).
> Les sections GPO/NETLOGON ci-dessous restent valables comme voie alternative
> sans NinjaOne.

## 0. Préparer le point de distribution (1 fois, sur le DC)

```powershell
# Sur BX-AD-01-IT-VM, en admin du domaine :
$d = "C:\Windows\SYSVOL\sysvol\omnitech.security\scripts\SIEM"   # = NETLOGON\SIEM
New-Item -ItemType Directory -Path $d -Force
# Y déposer :
#  - Sysmon64.exe                  <- https://live.sysinternals.com/Sysmon64.exe
#  - sysmonconfig-omnitech.xml     <- ce kit
#  - winlogbeat-oss-8.17.4-windows-x86_64.zip
#       <- https://artifacts.elastic.co/downloads/beats/winlogbeat/
#          !! version OSS obligatoire (la standard refuse une sortie non-Elastic)
#  - winlogbeat.yml                <- ce kit (vérifier le FQDN du SIEM dedans)
#  - omnitech-rootca.pem           <- export Base64 de la Root CA :
#       Sur BX-PKI2022 : certutil -ca.cert C:\temp\rootca.cer
#       puis renommer .cer (déjà en Base64 ? sinon : certutil -encode rootca.cer omnitech-rootca.pem)
```
NETLOGON est répliqué sur les deux DC et lisible par les comptes ordinateurs :
parfait pour un déploiement sans Internet.

## 1. GPO d'audit (sur le DC)

```powershell
cd <kit>\windows
# Lie par défaut à omnitech.security/Entreprise + Domain Controllers :
.\Deploy-AuditGPO.ps1
```
Ce que la GPO applique : la stratégie d'audit avancée du CSV (4624/4625, 4688,
4768/4769/4776, gestion des comptes, 4662/5136, USB/Removable Storage, NPS,
Certification Services pour la PKI, 1102…), la **ligne de commande dans les
4688**, le **PowerShell Script Block + Module Logging**, un journal Security de
**2 Go**, et le forçage de la stratégie avancée (SCENoApplyLegacyAuditPolicy).

Vérification sur un client pilote :
```cmd
gpupdate /force
auditpol /get /category:*
wevtutil gl Security        :: maxSize doit afficher 2147483648
```

Notes DC : les sous-catégories *DS Access/DS Changes* ne produisent des
événements **que** sur les contrôleurs de domaine — la détection DCSync (4662)
fonctionne avec la SACL par défaut de la partition. Les 5136 exhaustifs
peuvent demander un élargissement de SACL (optionnel, plus tard).

## 2. Déploiement Sysmon + Winlogbeat sur TOUT le domaine

### Option A (recommandée) : GPO, depuis l'AD — `Deploy-AgentsGPO.ps1`

```powershell
cd <kit>\windows
# Lie par défaut à omnitech.security/Entreprise :
.\Deploy-AgentsGPO.ps1
```

La GPO `OMNI-SIEM-Agents` pousse une **tâche planifiée SYSTEM** sur chaque
machine (au boot +5 min, + tous les jours 12h00 avec délai aléatoire 0-2 h)
qui exécute `\\omnitech.security\NETLOGON\SIEM\Deploy-SysmonWinlogbeat.ps1`.
Comme ce script est idempotent, la GPO sert aussi de canal de **maintenance** :
remplacer `winlogbeat.yml` ou `sysmonconfig-omnitech.xml` dans NETLOGON\SIEM
suffit, le parc converge en moins de 24 h.

Suivi du déploiement (sur le SIEM) : compter les hôtes qui remontent —
recherche Graylog `streams:OMNI - Sysmon`, agrégation sur `host`, ou
dashboard *OMNI - Windows Securite*.

### IMPORTANT si tu déploies par NinjaOne (et non par GPO)

La GPO `OMNI-AUDIT-Baseline` ne s'applique **pas** aux postes pilotés par
NinjaOne hors du périmètre GPO → ils envoient Sysmon/PowerShell mais **0
événement Security** (Windows n'audite presque rien par défaut). Pousse alors
la politique d'audit **en local** avec un 2ᵉ script NinjaOne :

`Set-OmniAudit-NinjaOne.ps1` (SYSTEM, 64 bits, quotidien) applique exactement
la même baseline que la GPO (auditpol /restore + cmdline 4688 + ScriptBlock
4104 + SCENoApplyLegacyAuditPolicy + journal Security 2 Go). Idempotent, la
baseline CSV est embarquée dans le script (aucune dépendance réseau).
Vérification sur le poste : `auditpol /get /category:*` puis, après quelques
minutes, l'hôte remonte les 4624/4625/4688 dans Graylog (page *Identité AD*).

À enchaîner avec `Deploy-SiemAgents-NinjaOne.ps1` : deux scripts NinjaOne
distincts (agents + audit), ou appelle l'audit en fin du script agents.

### Option B : NinjaOne (parc hors domaine, VIP, rattrapage)

Dans NinjaOne : *Administration > Scripting* → nouveau script PowerShell,
coller `Deploy-SysmonWinlogbeat.ps1`, exécution **SYSTEM**, 64 bits.
L'affecter en tâche planifiée (ex. quotidienne) sur les groupes
PILOTE puis PRODUCTION_POSTES / PRODUCTION_SERVEURS — il est idempotent :
il installe, met à jour la config, ou ne fait rien si tout est conforme.
Les deux canaux peuvent coexister sans conflit (même script, même source).

Cibler aussi les serveurs sensibles : **BX-AD02, WSUS, PKI (BX-PKI2022),
NPS, serveurs de fichiers** — le DC1 ayant déjà Winlogbeat, le script le
mettra simplement au niveau (même conf pour tout le monde).

Vérification sur un poste :
```powershell
Get-Service Sysmon64, winlogbeat
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3
Get-Content "C:\ProgramData\winlogbeat\logs\winlogbeat*" -Tail 20   # "Connection to backoff(...) established"
```

## 3. Côté FortiAnalyzer (10.33.80.253)

*System Settings > Advanced > Log Forwarding > Create New* :
mode **Forwarding**, serveur `10.33.220.10`, protocole **syslog** port `1514`
(ou **CEF** port `5555` → alors créer l'input CEF dans Graylog : System >
Inputs > CEF TCP). Ajouter des **filtres** : event severity ≥ warning,
sous-types auth/admin/vpn/ips/av/local-in — le trafic *accept* verbeux reste
dans le FAZ (c'est lui le lac réseau, Graylog fait la corrélation).

## 4. DNS (sur le DC)

```powershell
Add-DnsServerResourceRecordA -ZoneName "omnitech.security" -Name "bx-it-graylog-vm" -IPv4Address "10.33.220.10" -CreatePtr
```

## 5. Ce que produisent les clients (modèle de données entrant)

| Canal Windows collecté | EventID clés | Usage détection |
|---|---|---|
| Security | 4624/4625/4634/4648/4740 | auth, bruteforce, latéralisation |
| Security | 4768/4769/4771/4776 | Kerberos, Kerberoasting, NTLM |
| Security | 4720-4756 | cycle de vie comptes/groupes |
| Security | 4662/5136 | DCSync, modifs AD |
| Security | 4688 (+cmdline), 4697/4698, 7045 | exécution, services, tâches |
| Security | 1102, 4719 | effacement journal, sabotage audit |
| Sysmon | 1, 3, 6, 7, 8, 10, 11, 12-14, 17-21, 22, 25 | process+hash, réseau, LSASS, persistance, DNS |
| PowerShell/Operational | 4103, 4104 | script blocks malveillants |
| Defender/Operational | 1116/1117, 5001/5007 | détections, désactivation AV |
| System | 104, 7045, 6008… | services, arrêts anormaux |

Les pipelines Graylog (script 12) normalisent ensuite vers : `event_id`,
`event_source`, `event_action`, `event_category`, `user`, `host`, `src_ip`,
`dest_ip`, `dest_port`, `process_name`, `process_path`, `command_line`,
`parent_process`, `dns_query`, `logon_type_label`, `failure_reason`,
`priv_group_label`, `alert_tag` — ce sont ces champs qu'utilisent les
détections (script 13) et les dashboards (script 14).
