# Veeam Backup & Replication -> Graylog — procédure

Côté SIEM tout est prêt (passe du 12/06) :
- règles pipeline `omni-winother-10-veeam` (+ `-echec`) : les événements du
  canal Windows **« Veeam Backup »** sont normalisés (`event_source:veeam`,
  `event_category:sauvegarde`) et les jobs en échec/avertissement tagués
  `alert_tag:veeam_job_echec` (niveau error/warning ou message « failed ») ;
- alerte **« OMNI - Veeam : job en echec ou avertissement »** (P3, mail,
  grâce 4 h) ;
- page dashboard **OMNI - SOC > Sauvegardes** (volume, sévérité, échecs par
  serveur, snapshots vSphere de sauvegarde, triage).

## 1. Côté serveur Veeam : RIEN de spécifique à faire

Lancer simplement **`Install-OmniSiem-NinjaOne.ps1`** (le script NinjaOne
unique) sur le serveur Veeam : il détecte le journal Windows « Veeam Backup »
et ajoute automatiquement le canal à la conf Winlogbeat de CETTE machine.
Le canal journalise les démarrages/fins de jobs, succès/avertissements/échecs.

Vérification locale éventuelle :
```powershell
Get-WinEvent -ListLog "Veeam Backup"            # le journal existe ?
Get-WinEvent -LogName "Veeam Backup" -MaxEvents 5 | fl TimeCreated,LevelDisplayName,Message
```

## 2. Vérification côté SIEM (~2 min après le déploiement)

```bash
curl -s "127.0.0.1:9200/omni-winother_*/_search?size=3" -H 'Content-Type: application/json' \
  -d '{"query":{"term":{"event_source":"veeam"}},"sort":[{"timestamp":"desc"}]}' \
  | jq -r '.hits.hits[]._source | "\(.timestamp) | \(.source) | \(.winlogbeat_log_level) | \(.alert_tag // "-")"'
```
Puis dashboard **OMNI - SOC > Sauvegardes**.

## 3. Alternative / complément : syslog natif (Veeam 12.1+)

Veeam B&R >= 12.1 sait pousser ses événements en syslog (RFC 5424) :
**Menu principal > General Options > Event Forwarding > Syslog servers**
-> `bx-it-graylog-vm.omnitech.security`, port `1516` (input vSphere/syslog
existant) ou un input dédié. Apporte des champs structurés (jobId, etc.).
Le canal Windows suffit pour l'alerte « job en échec » ; activer le syslog
seulement si on veut le détail fin par job.

## 4. Bon à savoir

- L'alerte ne se déclenche que sur error/warning : un cycle nominal de
  sauvegarde n'envoie RIEN par mail (anti-bruit).
- Pour un test de bout en bout : relancer un job avec une VM inexistante ou
  couper la cible de dépôt, l'alerte doit partir dans le quart d'heure.
- Les snapshots vSphere créés/supprimés par Veeam pendant les sauvegardes
  sont visibles sur la même page (règle `snapshot_sauvegarde` du volet
  vSphere) — c'est le « pouls » visuel des sauvegardes.
