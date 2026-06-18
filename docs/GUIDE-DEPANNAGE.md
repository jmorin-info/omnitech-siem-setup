# Guide de dépannage — SIEM OMNITECH

*Version 1.1 — révisé le 14/06/2026 — Classification : interne. Format : symptôme → cause → solution.
Référence technique exhaustive des incidents résolus : `CONTEXT.md` (section « PIÈGE À RETENIR »).*

> Sources actuellement collectées : AD/Sysmon (Winlogbeat, Beats TLS 5044), FortiGate (via
> FortiAnalyzer, syslog 1514 TCP/UDP), Microsoft 365 (GELF HTTP 12201, collecte *pull*),
> vSphere (syslog 1516 TCP/UDP), Veeam (canal Windows), **ESET PROTECT** (syslog JSON TCP 1515,
> champs `eset_*`), **BunkerWeb WAF** (Filebeat sur le Beats 5044 partagé, champs `http_*`/`waf_*`).
> **NPS** est mappé (lookup `win-events.csv`) mais pas encore remonté côté client.

## 1. Collecte — une source ne remonte plus

| Symptôme | Cause probable | Solution |
|---|---|---|
| Un canal Windows **Security** muet, les autres OK | Liste `event_id` trop longue dans winlogbeat.yml (> ~23 expressions → ERROR_EVT_INVALID_QUERY) | Utiliser des **plages** (`4624-4799`), jamais une liste plate. Redéployer via `Install-OmniSiem-NinjaOne.ps1` |
| Un hôte n'apparaît plus du tout | Agent arrêté / pare-feu 5044 | Sur l'hôte : `Get-Service winlogbeat` ; tester `Test-NetConnection <siem> -Port 5044` |
| FortiGate : seul `voip` en UTM, pas virus/IPS/web | Profils UTM non attachés aux policies | `fortigate/05/06-utm-*.conf` ; vérifier `show firewall policy <id>` |
| FortiGate : `source` = adresse IP au lieu du nom d'équipement | Règle de normalisation non appliquée | Le pipeline pose `source` = champ `host` (règle `omni-forti-06-source-host`, script 12) ; vérifier que la règle est dans le stage FortiGate |
| FortiGate : horodatage décalé / événements « dans le futur » | `timestamp` non recalé sur l'heure d'origine de l'équipement | Le pipeline pose `timestamp` depuis `eventtime` (epoch ns → ms, règle `omni-forti-05-eventtime`, corrigé 14/06) |
| vSphere : logs présents mais **0 host/event_action** | Stage pipeline `match either` avec une seule règle conditionnelle → bloque le reste | Mettre la normalisation dans le même stage (corrigé 12/06) |
| Serveur Veeam : pas de canal « Veeam Backup » | Aucun job depuis le dernier contrôle (normal) **ou** canal non collecté | Attendre un job ; sinon relancer `Install-OmniSiem` (auto-détecte le canal) |
| M365 : volume très faible / page vide | Collecteur planté **ou** curseur non rejoué après purge | `journalctl -u omni-m365-fetch` (et `omni-m365-activity`) ; reset curseur `/var/lib/omni-m365/state.json` |
| **ESET** : input 1515 vide alors que la console ESET émet | Redirection 514→1515 absente côté pare-feu, ou syslog ESET désactivé | ESET PROTECT (10.33.50.20) envoie en **514**, redirigé vers 1515 par le pare-feu ; vérifier l'input `ESET (Syslog TCP 1515)` et la règle de redirection |
| **ESET** : messages reçus mais non parsés (`eset_*` absents) | Format non-JSON ou préfixe syslog non strippé | Le pipeline strip tout avant le 1er `{` puis `set_fields(..., "eset_")` (règle `omni-eset-05-json`) ; vérifier que `event_source=eset` est bien posé |
| **BunkerWeb** : logs WAF qui atterrissent dans « OMNI - Windows autres » | BunkerWeb partage le **Beats 5044** avec Winlogbeat → routage par `filebeat_event_source` | Filebeat doit poser `filebeat_event_source=bunkerweb` ; une règle d'exclusion (`inverted`) écarte BunkerWeb de « OMNI - Windows autres » (script 52) |
| **NPS** : rien ne remonte | Normal à ce stade : mappé mais pas encore activé côté client | NPS (10.33.50.247) passera par Winlogbeat/Beats 5044 ; mapping prêt via lookup `win-events.csv` |
| **Vaultwarden** : logs coffre dans « OMNI - Windows autres » | Même partage Beats 5044 → routage par `filebeat_event_source` | Filebeat doit poser `filebeat_event_source=vaultwarden` ; exclusion (`inverted`) + **index dédié `omni-vaultwarden`** (script 55). Le bruit « too many admin requests » (boucle conteneur) est droppé au pipeline |
| **`src_hostname` vide** sur les logs FortiGate internes | Attribution DHCP en panne | `systemctl status omni-fortidhcp-fetch.timer` + `journalctl -u omni-fortidhcp-fetch` ; vérifier token RO FortiGate + lookup `omni-dhcp-attribution` (script 56) |
| **Alerte « Intégrité des logs COMPROMISE »** | Chaîne de hachage rompue (suppression/altération) | `omni-integrity --verify` ; comparer `/var/lib/omni-integrity/chain.jsonl` avec la copie SMB `/SIEM/integrity/` ; figer & investiguer (script 60) |

## 2. Indexation — messages perdus

| Symptôme | Cause | Solution |
|---|---|---|
| **Indexer failures** > 0 (System → Indexer failures) | Champ typé rejeté (ex `src_ip` = "N/A"/"x.x"/ip:port) | Corriger **à la source ou au pipeline** (jamais assouplir le mapping). Cf. clean_ip / regex IP |
| Recherche « vide » alors que les logs arrivent | Index range non recalculé (après purge/manip) | `POST /api/system/indices/ranges/rebuild` |
| Tout semble vide sur 24h/7j après une **purge** | Comportement attendu : l'historique a été effacé, la collecte repart de zéro | Regarder une fenêtre « depuis la purge » ; les agents ne rejouent pas l'historique. La repopulation des dashboards est gérée par `54-post-purge-repopulate.sh` |
| Une source plus ancienne que sa rétention a disparu | Comportement attendu (rétention par index set) | Rétentions : **FortiGate 180 j** ; Windows/Sysmon/vSphere/M365/ESET **365 j** ; **BunkerWeb 90 j**. Disque `/data` = 7,3 To |

## 3. Alertes — trop, ou pas assez

| Symptôme | Cause | Solution |
|---|---|---|
| Tempête de mails identiques | Grâce trop courte / pas de clé / échec service compté comme brute force | `21-alert-hygiene.sh` (grâces ≥ 60 min, clés par compte/IP, exclusion logon type 4/5) |
| Trop d'alertes par mail (pas que le critique) | Routage 2 tiers non (ré)appliqué | `22-alert-routing.sh` : **Teams = firehose** (toutes les alertes, ~87) ; **mail = critique « réveille-moi » uniquement** (~26 : compromission confirmée + santé SIEM). À relancer après 13/21 |
| Plus aucune alerte Teams reçue | Flux Power Automate throttlé/cassé (échoue **en silence**, Graylog reçoit 202) | Vérifier l'**historique d'exécution** du flux Power Automate (pas les logs Graylog) |
| Plus aucun mail critique reçu | Notification mail retirée de toutes les définitions, ou SMTP cassé | Vérifier que `22-alert-routing.sh` a bien conservé le mail sur la liste `KEEP` ; tester l'envoi SMTP depuis Graylog |
| Une alerte ne se déclenche jamais | Le stream interrogé ne route pas la source ; ou `key_spec` sans `field_spec` | Vérifier les règles du stream ; toute clé doit avoir une entrée `field_spec` |
| Incident critique compté plusieurs fois | Doublons de kill-chain | Dédup au niveau de la corrélation d'incidents (`omni-incident-correlate`, corrigé 14/06) |
| Faux positifs récurrents | Détection trop large | Exclusion ciblée **au pipeline** (script 12/13/21), pas en console seule. Exclusions en place : comptes machine `*$` + comptes de service (`ninjaone`, `ADSyncMSA`) pour la force brute ; `wakeup-ssrs.ps1` pour PowerShell ; `vpxuser`/`dcui`/`localhost` pour la force brute vSphere |

## 4. Console / authentification

| Symptôme | Cause | Solution |
|---|---|---|
| « invalid credentials » avec un compte AD admin | Port 636 (LDAPS) bloqué → backend non créé → compte AD inconnu | Ouvrir 636 (règle FortiGate 425) puis `bash 33-ldaps-auth.sh` |
| Login AD refusé pour un compte admin du domaine | DN du groupe erroné dans le filtre | Récupérer le DN exact (`ldapsearch ... memberOf`) ; le groupe peut être hors `CN=Users` |
| Console inaccessible / boucle JSON.parse | TLS mal configuré (truststore, http_publish_uri) | CA dans `cacerts-omni.jks`, `http_publish_uri` = FQDN → 127.0.0.1 via /etc/hosts |

## 5. Sauvegarde / capacité / SOAR

| Symptôme | Cause | Solution |
|---|---|---|
| Sauvegarde config échoue (SMB) | Montage CIFS refusé (guest) / pare-feu 445 | `/root/.smb-siem.cred` (compte dédié, chmod 600) ; règle FortiGate Réseau ELK → Files 445 |
| `/data` se remplit | Volume anormal d'un flux | `32-disk-guard.sh` (timer `omni-disk-guard`) alerte à 80 %, purge d'urgence à 88 % ; revoir `41-retention-iso.sh` |
| SOAR : `diagnose` CLI échoue sur FortiGate | Commande non supportée par la version | Vérifier via **GUI** (External Connectors → View Entries) ; les logs nginx du SIEM prouvent le poll |
| SOAR ne bloque pas le portail VPN | Trafic « local-in » non filtré par une firewall policy forward | Utiliser une **`local-in-policy`** (le portail écoute sur le boîtier) |
| FortiGate ne lit pas le feed (HTTPS) | Root CA OMNITECH absente du FortiGate | Importer la CA (*System → Certificates*) ou servir le feed en HTTP |
| Certificat console / parc proche de l'expiration | Surveillance permanente | `omni-cert-check` (télémétrie continue) alerte par mail ; renouvellement console automatisé via `omni-cert-renew` (CSR → AD CS via SMB) |

## 6. Purge / remise à zéro propre

| Symptôme / besoin | Détail | Solution |
|---|---|---|
| Repartir sur des index vides sans perdre la config | Après validation des correctifs de faux positifs | `53-purge-clean.sh` : cycle deflector + suppression des anciens index via l'API (streams, pipelines, lookups, inputs, alertes, dashboards conservés ; `gl-system-events` conservé). **DESTRUCTIF** |
| Dashboards vides juste après une purge | Widgets dérivés non re-calculés tant que les robots n'ont pas re-tourné | `53-` enchaîne automatiquement `54-post-purge-repopulate.sh` (rebuild ranges + re-fetch M365 + relance des robots). Désactiver l'enchaînement : `PURGE_NO_REPOP=1` |
| Après purge, UEBA/NDR/vulnérabilités restent partiellement vides | Normal : baseline UEBA, motifs NDR sur heures, inventaire vuln quotidien nécessitent de la donnée fraîche | Attendre l'accumulation — ce n'est pas un bug |

## 7. Réflexes de diagnostic (commandes utiles, sur le SIEM)

```bash
# état général
systemctl status graylog-server opensearch mongod nginx
systemctl list-timers 'omni-*'
curl -s '127.0.0.1:9200/_cat/indices/omni-*?h=index,docs.count,store.size&s=index'

# débit d'un flux (5 min) — préfixes : omni-winsec omni-sysmon omni-winother
#   omni-fortigate omni-m365 omni-vsphere omni-eset omni-bunkerweb
curl -s "127.0.0.1:9200/omni-<flux>_*/_count" -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"timestamp":{"gte":"now-5m"}}}}'

# un hôte remonte-t-il ?  (recherche source:<hostname> sur 15 min via la console)

# journal d'un collecteur
journalctl -u omni-m365-fetch -n 20
journalctl -u omni-m365-activity -n 20
tail -f /var/log/graylog-server/server.log
```

## 8. Pièges API Graylog 7.x (à connaître pour intervenir au pipeline)

- **Pas de ternaire** dans les règles pipeline : utiliser `if/else`.
- `contains()` prend **2 arguments** (`contains(valeur, sous-chaîne)`).
- Sur les `POST` d'entités, encapsuler le corps dans l'**enveloppe** `{entity}` attendue.
- Cycle du deflector : `POST /system/deflector/{id}/cycle` (utilisé par la purge).
- Dashboard unique **« OMNI - SOC »** (24 pages) : `requires={}` → 100 % OSS, **pas d'Enterprise**.

---

> En cas d'incident non listé : consigner symptôme + résolution dans `CONTEXT.md`
> (section « PIÈGE À RETENIR ») pour enrichir ce guide.
> Voir aussi : `INTEGRATION-SOURCES.md`, `POLITIQUE-RETENTION.md`, `PROCEDURE-INCIDENT.md`.
