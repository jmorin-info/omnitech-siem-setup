# OMNITECH SIEM — déploiement Docker

Reproduit la plateforme **Graylog 7.1.3 / OpenSearch 2.19.5 / MongoDB** en conteneurs.
Toute la configuration Graylog (streams, pipelines, **136 détections**, lookups, alertes,
notifications) vit dans MongoDB : **restaurer le dump de sauvegarde = la plateforme entière**.

> Pour **staging, reprise après incident (DR), portabilité et démonstration**. La production
> reste le déploiement bare-metal chiffré LUKS ; ce bundle n'est pas destiné à le remplacer.

## 🇫🇷 Français

### Prérequis
- Docker Engine + plugin Compose v2 (`docker compose version`).
- ≥ 6 Go de RAM libre (OpenSearch + Graylog), ≥ 20 Go de disque.
- `vm.max_map_count` ≥ 262144 : `sudo sysctl -w vm.max_map_count=262144` (persister dans `/etc/sysctl.conf`).

### Démarrage
```bash
cd docker
cp .env.example .env          # puis renseigner les secrets (voir ci-dessous)
./deploy.sh up                # monte Graylog + OpenSearch + MongoDB
# Console : http://<hôte>:9000   (admin / le mot de passe dont vous avez mis le sha256)
```
Secrets de `.env` :
- `GRAYLOG_PASSWORD_SECRET` — `openssl rand -hex 48`
- `GRAYLOG_ROOT_PASSWORD_SHA2` — `echo -n 'MotDePasse' | sha256sum | cut -d' ' -f1`

### Déployer la configuration COMPLÈTE (deux voies)

**Voie 1 — Restauration (DR / clone, recommandée).** Repart d'une sauvegarde produite par
`30-backup-config.sh` (dump Mongo + `/etc/graylog` chiffré) :
```bash
./deploy.sh restore omni-siem-config_AAAAMMJJ.tar.gz.enc
# Demande la BACKUP_PASSPHRASE (celle du coffre). Restaure la conf + les lookups, redémarre Graylog.
```
Résultat : un Graylog Docker **identique** (mêmes 17 streams, 13 inputs, 136 détections,
27 tables de lookup, alertes, notifications).

**Voie 2 — Reconstruction depuis les scripts (IaC).** Monter la stack vide, puis appliquer les
scripts d'intégration contre l'API du Graylog conteneurisé. Les scripts `1x`–`9x` pilotent
l'API Graylog ; exporter l'URL et les identifiants du conteneur avant de les lancer (cf.
`00-vars.env`, champ `API`). À privilégier pour repartir d'une base neuve et versionnée.

### Sécurité (à lire)
- Le plugin de sécurité OpenSearch est **désactivé** : l'instance n'écoute que sur le réseau
  Docker interne, **jamais exposée**. N'exposez que le port `9000` de Graylog, **derrière un
  reverse proxy TLS** (nginx/traefik). Ne publiez pas `9200`/`27017`.
- `.env` contient des secrets : `chmod 600 .env`, hors du dépôt git (déjà `.gitignore`).
- Pour de la production conteneurisée : activer la sécurité OpenSearch (TLS + comptes),
  chiffrer les volumes, et restreindre les ports d'ingest aux réseaux sources.

### Exploitation
```bash
./deploy.sh status            # état des conteneurs
./deploy.sh logs graylog      # logs en direct
./deploy.sh down              # arrêt (volumes conservés)
```
Les **lookups CSV** versionnés (`../lookups/`) sont montés en lecture seule dans Graylog
(`/etc/graylog/lookup`) ; toute mise à jour côté dépôt est reprise au redémarrage.

---

## 🇬🇧 English

Reproduces the **Graylog 7.1.3 / OpenSearch 2.19.5 / MongoDB** platform in containers. The entire
Graylog configuration (streams, pipelines, 136 detections, lookups, alerts, notifications) lives
in MongoDB: **restoring the backup dump = the whole platform**. Intended for staging, disaster
recovery, portability and demos — not to replace the LUKS-encrypted bare-metal production.

### Prerequisites
- Docker Engine + Compose v2, ≥ 6 GB free RAM, ≥ 20 GB disk.
- `sudo sysctl -w vm.max_map_count=262144` (persist it).

### Quick start
```bash
cd docker && cp .env.example .env     # fill the secrets
./deploy.sh up                        # Graylog + OpenSearch + MongoDB
# Console: http://<host>:9000
```

### Deploy the FULL configuration
- **Restore (DR/clone, recommended):** `./deploy.sh restore omni-siem-config_YYYYMMDD.tar.gz.enc`
  — restores the Mongo dump (all Graylog config) + lookups, restarts Graylog. Identical SIEM.
- **From scratch (IaC):** bring the empty stack up, then run the `1x`–`9x` integration scripts
  against the containerized Graylog API (set `API` to the container URL first).

### Security
OpenSearch security plugin is **disabled** and bound to the internal Docker network only — never
expose `9200`/`27017`. Publish only Graylog `9000`, behind a TLS reverse proxy. `chmod 600 .env`.
For containerized production, enable OpenSearch security (TLS + users) and encrypt the volumes.

### Operations
`./deploy.sh status | logs <svc> | down`. Versioned lookup CSVs (`../lookups/`) are mounted
read-only into Graylog and picked up on restart.
