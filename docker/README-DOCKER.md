# OMNITECH SIEM — déploiement Docker (plateforme complète)

Reproduit la plateforme en conteneurs, **bout en bout** : moteur Graylog 7.1.3 + OpenSearch 2.19.5
+ MongoDB, **console SOC** (`/soc`), **PWA** (`/m`) + backend `/m/api`, et **nginx TLS** en frontal
(`/soc //m //kit` + Graylog). Toute la configuration Graylog vit dans MongoDB : **restaurer le
dump de sauvegarde = la plateforme entière** (17 streams, 13 inputs, 136 détections, 27 lookups,
alertes, notifications).

> Pour **staging, reprise après incident (DR), portabilité et démonstration**. La production reste
> le déploiement bare-metal chiffré LUKS ; ce bundle ne le remplace pas.

## Services & dépendances (ce que la stack couvre)

| Service     | Image / build                       | Rôle                                           |
|-------------|-------------------------------------|------------------------------------------------|
| `mongodb`   | `mongo:7.0`                         | Toute la config Graylog                        |
| `opensearch`| `opensearchproject/opensearch:2.19.5` | Stockage/recherche des événements            |
| `graylog`   | `graylog/graylog:7.1.3`             | Moteur SIEM (inputs, pipelines, détections)    |
| `console`   | `Dockerfile.console` (Python+pywebpush) | Backend `/m/api` (lecture OpenSearch, push) |
| `nginx`     | `nginx:1.27-alpine`                 | TLS, sert `/soc //m //kit`, proxy Graylog      |

**Collecteurs optionnels (non inclus)** : les fetchers M365/ESET/EMS, l'export SMB et les moteurs
oms-xdr/oms-ml/oms-graph sont des **add-ons** déployés séparément (cf. leurs dossiers). Le cœur SIEM
+ console + proxy fonctionne sans eux ; leurs secrets ne sont donc pas requis ici.

## 🇫🇷 Démarrage

### Prérequis
- Docker Engine + Compose v2, ≥ 6 Go RAM libre, ≥ 20 Go disque.
- `sudo sysctl -w vm.max_map_count=262144` (persister dans `/etc/sysctl.conf`).

```bash
cd docker
cp .env.example .env        # renseigner les secrets (voir ci-dessous)
chmod 600 .env
./deploy.sh up              # construit la console + monte les 5 services
# Console SOC : https://<SERVER_NAME>/soc/   |   Graylog : https://<SERVER_NAME>/
```
Le premier démarrage construit l'image console et initialise Graylog (~1–2 min).

### Secrets (.env) — tous générables en une ligne
| Variable | Génération |
|---|---|
| `GRAYLOG_PASSWORD_SECRET` | `openssl rand -hex 48` |
| `GRAYLOG_ROOT_PASSWORD_SHA2` | `echo -n 'MotDePasse' \| sha256sum \| cut -d' ' -f1` |
| `MOBILE_SECRET` | `openssl rand -hex 32` (HMAC des sessions console) |
| `VAPID_PUBLIC_KEY` | *optionnel* (push web) ; vide = push désactivé |
| `SERVER_NAME` | nom servi (CN du cert auto-signé généré au 1er démarrage) |

### Déployer la configuration COMPLÈTE
**Restauration (DR / clone, recommandée)** — depuis une sauvegarde de `30-backup-config.sh` :
```bash
./deploy.sh restore omni-siem-config_AAAAMMJJ.tar.gz.enc   # demande la BACKUP_PASSPHRASE
```
Restaure le dump Mongo (toute la conf) + les lookups, redémarre Graylog → SIEM **identique**.

**Reconstruction depuis les scripts (IaC)** — stack vide puis scripts `1x`–`9x` contre l'API du
Graylog conteneurisé (exporter `API` = URL du conteneur). À privilégier pour une base neuve.

## Scalabilité
- **OpenSearch** : `OS_HEAP` (~50 % de la RAM, max ~31 g). Pour un cluster multi-nœuds, dupliquer
  le service `opensearch` (os01/os02/os03), retirer `discovery.type=single-node` et fixer
  `discovery.seed_hosts` + `cluster.initial_cluster_manager_nodes` ; augmenter les replicas d'index.
- **Graylog** : `GRAYLOG_MEM` borne la mémoire ; pour la charge, lancer plusieurs nœuds Graylog
  (même MongoDB + OpenSearch) derrière nginx (`upstream` round-robin) — l'état est partagé en base.
- **Ingest** : régler les buffers/threads des inputs (process/output buffers Graylog) selon la RAM.
- Limites mémoire posées via `deploy.resources.limits` (compose v2) ; ajuster à l'hôte.

## Sécurité (à lire)
- Sécurité OpenSearch **désactivée** et liée au réseau Docker interne — **n'exposez jamais**
  `9200`/`27017`. Seuls `443`/`80` (nginx) sont publiés. nginx génère un **cert auto-signé** au
  démarrage ; en prod, monter un vrai certificat sur le volume `nginx_certs`.
- La console pose des cookies `Secure` → **HTTPS obligatoire** (assuré par nginx).
- `.env` (secrets) : `chmod 600`, hors git (déjà `.gitignore`). Les lookups CSV (`../lookups`) sont
  montés en lecture seule dans Graylog et la console.

## Exploitation
```bash
./deploy.sh status              # état des conteneurs
./deploy.sh logs graylog        # (ou console / nginx / opensearch)
./deploy.sh down                # arrêt (volumes conservés)
```

---

## 🇬🇧 English (summary)
Full containerized platform: Graylog 7.1.3 + OpenSearch 2.19.5 + MongoDB + **SOC console** (`/soc`,
`/m`, `/m/api`) + **TLS nginx**. All Graylog config lives in MongoDB → restoring the backup dump = the
whole platform. `cp .env.example .env` (set `GRAYLOG_PASSWORD_SECRET`, `GRAYLOG_ROOT_PASSWORD_SHA2`,
`MOBILE_SECRET`, `SERVER_NAME`), then `./deploy.sh up`. Restore full config with
`./deploy.sh restore <archive.tar.gz.enc>`. Scale OpenSearch to a multi-node cluster and run several
Graylog nodes behind nginx for load. Optional collectors (M365/ESET/EMS fetchers, oms-xdr/ml/graph)
are separate add-ons. Never expose `9200`/`27017`; only nginx `443/80`. Console requires HTTPS
(Secure cookies); nginx self-signs at first start — mount a real cert for production.
