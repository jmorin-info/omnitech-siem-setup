# Intégration de nouvelles sources — ESET / NPS / BunkerWeb

> Procédure d'ajout des 3 sources. Côté SIEM tout est déjà provisionné
> (`52-new-sources.sh`). Il reste / restait la config **côté source**, détaillée ici.
>
> **Revue : 2026-06-14.**

## État réel des 3 sources (au 2026-06-14)

| Source | Côté SIEM | Côté source | Données reçues |
|--------|-----------|-------------|----------------|
| **ESET PROTECT** (10.33.50.20) | ✅ input Syslog TCP 1515, stream `OMNI - ESET`, pipeline `eset_*` | ✅ syslog configuré | ✅ **arrive** (volume faible — détections ponctuelles, champs `eset_*` parsés) |
| **BunkerWeb** (10.33.70.1, hôte `bx-waf-it-vm`) | ✅ stream `OMNI - BunkerWeb`, pipeline `http_*`/`waf_*` | ✅ **Filebeat déployé** (logs Docker) | ✅ **arrive** (~15,5 k docs, flux nominal) |
| **NPS / RADIUS** (10.33.50.247, `bx-nps-it-vm`) | ✅ lookup `win-events.csv` + widgets/alerte prêts | ⚠️ Winlogbeat actif mais **canal Security absent** | ❌ **0× 6272/6273/6274** (voir diagnostic §2) |

> ESET et BunkerWeb sont donc **opérationnels** ; la section qui les concerne sert
> désormais de référence (rappel de conf) plus que de tâche à faire. NPS reste la
> seule source réellement « en attente » côté serveur.

### Routage / rétention par source

- **ESET** : index set dédié `omni-eset`, **rétention 365 j** (forensique).
- **BunkerWeb** : index set dédié `omni-bunkerweb`, **rétention 90 j** (volume).
- **NPS** : pas d'index dédié — les events atterrissent dans le stream *Windows
  Security* (rétention Windows = 365 j).

---

## 1. ESET PROTECT (10.33.50.20) — ✅ opérationnel

**Côté SIEM (fait) :** input *Syslog TCP* sur **1515** (TLS désactivé sur cet
input), et le pare-feu **redirige 514 → 1515** (ton ESET reste donc sur 514).
Stream `OMNI - ESET` (routé sur `gl2_source_input` de l'input ESET). Le pipeline
pose `event_source=eset`, parse le JSON ESET en champs **`eset_*`**
(`eset_event_type`, `eset_severity`, `eset_action`, `eset_hostname`, `eset_user`,
`eset_target`, `eset_detail`…), calcule un **`eset_risk_score`** (lookup
`eset-severity`, défaut 3), un **`eset_outcome`** (remédiée / non remédiée) et
pose le tag **`eset_detection`** (`alert_tag`) sur les menaces (`Threat_Event` /
`HipsAggregated_Event`). La règle `omni-eset-08-source-fix` réécrit `source` avec
`eset_hostname` (corrige le `source=mois` issu du syslog FR).

**Côté ESET PROTECT (déjà configuré par toi) :** Serveur syslog
`10.33.50.20 → 10.33.220.10:514`, TCP, format **syslog** (payload JSON ESET).

> **Vérifié au 2026-06-14 :** les events arrivent bien dans `OMNI - ESET` et les
> champs `eset_*` sont correctement extraits. Volume faible (détections
> ponctuelles) — c'est attendu, pas un problème de collecte.

⚠️ **Un seul point à vérifier — le cadrage (framing)** : Graylog attend par
défaut un cadrage **LF (non-transparent framing)**. Si tu as choisi
« octets comptabilisés » (octet-counting RFC 6587) et que les messages
arrivent **collés/tronqués**, bascule ESET sur **non-transparent / nouvelle
ligne (LF)**. Vérifie l'arrivée :
- Console Graylog → *Search* → `gl2_source_input` de l'input ESET, ou stream
  `OMNI - ESET`. Tu dois voir les events sous ~1 min.

---

## 2. NPS / RADIUS (10.33.50.247, `bx-nps-it-vm`) — ⚠️ en attente côté serveur

**Côté SIEM (déjà géré) :** les events NPS **6272** (accès accordé), **6273**
(refusé), **6274** (rejeté) sont **automatiquement enrichis** (lookup
`win-events.csv` → `event_action=acces_reseau_nps_*`, `event_category=nps`) et
apparaissent dans le stream *Windows Security* + le widget « Accès NPS refusés ».
Rien à créer.

**Côté serveur NPS (à faire) :** déployer **Winlogbeat** (le même agent que le
reste du parc) sur `10.33.50.247`. Le plus simple :
1. Lancer `Install-OmniSiem-NinjaOne.ps1` sur ce serveur (il installe Winlogbeat
   + Sysmon + la conf, et 10.33.50.247 est déjà autorisé sur le 5044 via le /16).
2. Les events NPS sont dans le journal **Security** (déjà collecté par
   `winlogbeat.yml`). Aucune conf supplémentaire.

> Pré-requis côté NPS : l'audit doit générer 6272-6274 (par défaut activé si NPS
> est rôle RADIUS ; sinon `auditpol /set /subcategory:"Network Policy Server"
> /success:enable /failure:enable`).

### Diagnostic (état au 2026-06-14)

Constaté à l'audit : `bx-nps-it-vm` (10.33.50.247) **émet bien via Beats 5044**
(~435 docs/24h) mais **uniquement du Sysmon** — **aucun event du canal Security**
(donc 0× 6272/6273/6274). Deux causes possibles, à corriger côté serveur :

1. **Audit NPS non activé.** Sur Windows **français**, le nom anglais de la
   sous-catégorie échoue → utiliser le **GUID** (indépendant de la langue) :
   ```powershell
   $g="{0CCE9243-69AE-11D9-BED3-505054503030}"
   auditpol /set /subcategory:$g /success:enable /failure:enable
   auditpol /get /subcategory:$g     # doit afficher "Réussite et Échec"
   ```
2. **Winlogbeat ne collecte pas le canal Security sur ce serveur.** Vérifier que
   `C:\Program Files\winlogbeat\winlogbeat.yml` contient bien
   `- name: Security` sous `winlogbeat.event_logs:` (sinon seul Sysmon remonte).
   Re-déployer via `Install-OmniSiem-NinjaOne.ps1` si la conf locale a dérivé.

Puis **provoquer une authentification RADIUS** (les 6272/6273 ne sont émis que sur
une vraie demande d'accès) et vérifier côté SIEM : recherche `event_id:6272`.
Tant que ce flux n'arrive pas, les widgets **[NPS en attente]** de la page
« Sources externes » restent vides — c'est attendu, pas un bug.

> Côté SIEM, **rien à faire** : le lookup `win-events.csv` mappe déjà
> 6272/6273/6274 → `acces_reseau_nps_*`, le widget « Accès NPS refusés » et
> l'**alerte P3** « OMNI - NPS : refus d'accès en masse (≥10 / compte / 15 min) »
> (script `13-graylog-alerts.sh`, sur le stream Windows Security) sont prêts.

> **Vérifié au 2026-06-14 :** toujours **0** event 6272/6273/6274 dans l'index —
> le canal Security du serveur NPS ne remonte pas encore (cf. causes ci-dessus).

---

## 3. BunkerWeb (10.33.70.1, hôte `bx-waf-it-vm`) — Filebeat → Beats 5044 — ✅ opérationnel

**Côté SIEM (fait) :** stream `OMNI - BunkerWeb`. ⚠️ **Le stream est routé sur le
champ `filebeat_event_source=bunkerweb`** (et **non** `event_source`) : Filebeat
envoie un champ `fields.event_source` que l'input Beats de Graylog **préfixe en
`filebeat_`**. C'est seulement *ensuite*, dans le pipeline, que la règle
`omni-bunkerweb-00-normalise` recopie `filebeat_event_source` → `event_source`.
Le pipeline pose alors `event_category=waf`, parse les accès nginx/BunkerWeb
(`src_ip`, `http_method`, `http_status`, `http_user_agent`, octets, vhost,
classe HTTP 2xx/3xx/4xx/5xx), pose le tag **`waf_block`** (HTTP 403 / ModSecurity),
détecte les **backends 5xx** et les **outils offensifs** dans le User-Agent, et
**drope ~97 % de bruit** (stderr/metrics) via `omni-bunkerweb-02-drop-noise`.
Réutilise l'input **Beats TLS 5044** existant (10.33.70.1 déjà autorisé via le /16).

> **Vérifié au 2026-06-14 :** flux nominal (~15,5 k docs), `event_source=bunkerweb`
> bien posé, parsing HTTP OK. Les logs proviennent du **conteneur Docker BunkerWeb**
> (`/var/lib/docker/containers/*/*-json.log`) — le déploiement réel est l'**option
> Docker** ci-dessous, pas le paquet systemd.

> ⚠️ **Point clé si tu redéploies Filebeat :** **ne mets PAS `fields_under_root:
> true`**. Si tu le mets, `event_source` arrive à la racine et n'est **pas**
> préfixé `filebeat_` → le stream `OMNI - BunkerWeb` (qui filtre sur
> `filebeat_event_source`) **ne matchera plus**. Laisse Filebeat poser le champ
> sous `fields:` (comportement par défaut, préfixé par Graylog).

### Étapes (Debian)

**a. Installer Filebeat (OSS) :**
```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-8.15.0-amd64.deb
sudo dpkg -i filebeat-oss-8.15.0-amd64.deb
```

**b. Copier la CA du SIEM** (le Beats input est en TLS) sur le serveur :
```bash
# depuis le SIEM, ou récupère /etc/graylog/certs/omnitech-rootca.crt
sudo install -m 644 omnitech-rootca.crt /etc/filebeat/omnitech-rootca.crt
```

**c. Repérer les logs BunkerWeb.** Selon l'installation :
- **Docker (déploiement réel sur `bx-waf-it-vm`)** : BunkerWeb tourne en conteneur,
  ses logs sont écrits par le driver json-file Docker. Filebeat pointe donc sur
  `/var/lib/docker/containers/*/*-json.log` (la conf utilise le module/`add_docker_metadata`
  ou un filtrage par conteneur ; le drop du bruit stderr/metrics se fait côté
  pipeline Graylog, règle `omni-bunkerweb-02-drop-noise`).
- **Paquet/systemd** (autre installation possible) : `/var/log/bunkerweb/access.log`,
  `error.log`, et l'audit ModSecurity `/var/log/bunkerweb/modsec_audit.log` (si activé).

**d. `/etc/filebeat/filebeat.yml` — variante Docker (celle en production) :**
```yaml
filebeat.inputs:
  - type: filestream
    id: bunkerweb
    paths:
      - /var/lib/docker/containers/*/*-json.log
    parsers:
      - container: ~                 # décode l'enveloppe json-log Docker
    fields:
      event_source: bunkerweb        # <- NE PAS mettre fields_under_root: true.
                                     #    Graylog préfixe -> filebeat_event_source,
                                     #    sur lequel le stream OMNI - BunkerWeb filtre.

output.logstash:                      # protocole Beats (= input Graylog 5044)
  hosts: ["10.33.220.10:5044"]
  ssl.certificate_authorities: ["/etc/filebeat/omnitech-rootca.crt"]

logging.level: warning
```

> **Variante paquet/systemd** : remplace `paths:` par les `access.log` / `error.log`
> / `modsec_audit.log` de `/var/log/bunkerweb/` et retire le parser `container`.
> **Conserve** `fields: { event_source: bunkerweb }` **sans** `fields_under_root`.

**e. Démarrer :**
```bash
sudo systemctl enable --now filebeat
sudo filebeat test output      # doit afficher 'talk to server... OK'
```

**f. Vérifier côté SIEM** : stream `OMNI - BunkerWeb` se remplit sous ~1 min.
Recherche de contrôle : `event_source:bunkerweb` (après normalisation pipeline) ou
`filebeat_event_source:bunkerweb` (champ brut, immédiat). Le champ `source` doit
afficher l'hôte WAF (`bx-waf-it-vm`).

### Alternative sans agent (rsyslog)
Si tu préfères ne pas installer Filebeat : configure BunkerWeb/nginx pour logguer
en syslog vers le SIEM, mais il faudra un input syslog dédié BunkerWeb (dis-le moi,
je l'ajoute). **Filebeat reste recommandé** (structuré, parsing access/ModSecurity).

---

## Récapitulatif des flux à ouvrir (FortiGate, si segmentation inter-VLAN)
| Source | → SIEM | Port | Protocole |
|--------|--------|------|-----------|
| ESET 10.33.50.20 | 10.33.220.10 | **514** (→1515) | TCP syslog |
| NPS 10.33.50.247 | 10.33.220.10 | **5044** | TCP (Beats TLS) |
| BunkerWeb 10.33.70.1 | 10.33.220.10 | **5044** | TCP (Beats TLS) |

*Le pare-feu LOCAL du SIEM est déjà ouvert pour ces flux.*
