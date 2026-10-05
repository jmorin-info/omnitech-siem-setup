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

## 2. Déploiement des agents sur le parc

### Voie unique recommandée : `Install-OmniSiem-NinjaOne.ps1`

**Un seul script, pour toutes les machines Windows** — postes, serveurs,
contrôleurs de domaine, machines hors domaine. Dans NinjaOne :
*Administration > Scripting* → nouveau script PowerShell, coller le fichier,
exécution **SYSTEM**, **64 bits**, planification **quotidienne**.

Il converge vers l'état cible et vérifie chaque étape :

| Étape | Ce qu'elle fait |
|---|---|
| Root CA | installe la CA OMNITECH si absente (TOFU au premier contact) |
| Audit | baseline `auditpol`, ligne de commande dans les 4688, ScriptBlock 4104, politique avancée forcée, journal Security 2 Go |
| Sysmon | installe, ou met à jour la configuration **seulement si son hash a changé** |
| Winlogbeat | version cible, configuration et CA ; ajoute automatiquement le canal `Veeam Backup` si le journal existe sur la machine |
| Santé | `test config` avant démarrage, `test output` vers 5044, lecture des logs pour détecter une erreur d'ouverture de canal |
| Inventaire | tâche quotidienne `OMNI-Inventory` (alimente la détection de vulnérabilités) |

Il est **idempotent** : il ne redémarre un service que si quelque chose a
réellement changé, et peut donc tourner tous les jours comme mécanisme
d'auto-réparation. Codes de sortie : `0` = tout OK, `1` = au moins un composant
en échec (le résumé par composant est affiché dans NinjaOne, le détail dans
`C:\ProgramData\OMNI-SIEM\install.log`).

Tout est téléchargé depuis le SIEM (`https://bx-it-graylog-vm.omnitech.security/kit/`) :
ni AD, ni NETLOGON, ni accès Internet requis sur la machine.

> Les scripts `Deploy-SiemAgents-NinjaOne.ps1` et `Set-OmniAudit-NinjaOne.ps1`
> sont **remplacés** par celui-ci et déplacés dans `archive/`. Ne pas les
> déployer : ils font la même chose en deux fois.

### Cas particuliers

- **Contrôleurs de domaine** : le script applique la baseline d'audit en local.
  Si la GPO `OMNI-AUDIT-Baseline` s'applique aussi, elle prime au refresh —
  la configuration étant identique, il n'y a aucun conflit.
- **Serveur Veeam** : rien à faire, le canal `Veeam Backup` est détecté et
  ajouté automatiquement à la configuration de cette machine uniquement.
- **Linux** : non couvert par ce script PowerShell. Utiliser `kit/install.sh`
  (ou `linux-omni.sh`), distribué par le même kit.

### Alternative : déploiement par GPO

`Deploy-AgentsGPO.ps1` pousse une tâche planifiée SYSTEM qui exécute
`Deploy-SysmonWinlogbeat.ps1` depuis NETLOGON. Cette voie **ne couvre que
Sysmon et Winlogbeat** : la politique d'audit doit alors être poussée
séparément par la GPO `OMNI-AUDIT-Baseline` (`Deploy-AuditGPO.ps1`).
À réserver aux parcs sans NinjaOne — sinon la voie unique ci-dessus est
préférable, puisqu'elle couvre audit et agents en une seule exécution.

Suivi du déploiement, côté SIEM : recherche Graylog `streams:OMNI - Sysmon`
avec agrégation sur `host`, ou tableau de bord *OMNI - Windows Securite*.

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
