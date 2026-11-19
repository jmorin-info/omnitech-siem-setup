# Docker : socle, console et reprise isolée

Le bundle démarre Graylog 7.2.2, OpenSearch 2.19.7, MongoDB 8.0.38, la console SOC
et nginx TLS. Il sert au staging et à la reprise en environnement isolé.
Il ne remplace pas automatiquement tous les services du déploiement natif.
La configuration initiale Graylog est vide : importer des Content Packs ou
restaurer une sauvegarde compatible, puis configurer réellement les sources.

## Démarrage neuf

Docker Engine/Compose v2, mémoire suffisante et `vm.max_map_count=262144` sont
nécessaires. Dimensionner les heaps dans `.env` ; les paramètres d'exemple ne
constituent pas un dimensionnement de production.

```bash
cd docker
cp .env.example .env
chmod 600 .env
# Renseigner les secrets et SERVER_NAME.
docker compose config --quiet
bash deploy.sh up
bash deploy.sh status
```

Accès navigateur : `https://<SERVER_NAME>/soc/` et `https://<SERVER_NAME>/`.
Le certificat provisoire auto-signé doit être remplacé par un certificat approuvé.
`/soc/` n'existe pas sur le port 9000 : ce port Graylog est publié uniquement sur
loopback pour le diagnostic. Les ports de collecte publiés sont listés dans
`docker-compose.yml` ; les restreindre aux sources attendues au niveau de l'hôte.
MongoDB et OpenSearch ne sont pas publiés vers le réseau externe.

La console écrit sa configuration privée dans `/app/data`. L'API Graylog utilise
HTTP dans le réseau Docker interne, avec une option explicite limitée au nom de
service `graylog` ; le navigateur utilise HTTPS. Ne pas exposer ce réseau interne.
Les secrets `.env` et leurs variantes fichiers ne doivent pas être versionnés.

## Périmètre

| Élément | Traitement |
|---|---|
| Socle Graylog/OpenSearch/MongoDB, nginx, console/PWA | Services de base Compose |
| Streams, pipelines, dashboards et détections | Import de packs ou restauration de configuration compatible |
| TLS des inputs | Certificats et clés dans `certs/` aux chemins attendus par leur configuration |
| GeoIP | Bases MMDB dans `geoip/`, si les traitements activés les utilisent |
| XDR | Profil `analytics` explicite, configuration propre au site |
| ML, graphe, triage, robots, M365/SEAL et autres collecteurs | Extensions distinctes, non fournies par le simple `up` |
| Logs historiques OpenSearch | Restauration de snapshots distincte du dump MongoDB |

Le profil XDR exige les bons identifiants de streams et paramètres du site :

```bash
# Après préparation d'un fichier YAML du site :
OMS_CONFIG_HOST=/chemin/du/site-xdr.yaml OMS_CONFIG_FILE=/app/site-config.yaml \
  docker compose --profile analytics up -d
```

Les modules WatchGuard/UniFi/Palo Alto sont décrits dans
[INTEGRATIONS-MODULAIRES.md](../docs/INTEGRATIONS-MODULAIRES.md). Leurs nouveaux ports
UDP doivent être publiés dans Compose et autorisés au pare-feu ; ils ne sont pas
ouverts implicitement par l'import du pack. Le bind de l'input doit correspondre
au conteneur (`0.0.0.0` pour recevoir le trafic publié).

## Versions existantes et restauration

`deploy.sh up` refuse les conteneurs MongoDB hors série 8.0, Graylog hors série 7.2
et les anciens volumes Mongo orphelins non identifiés. Ne pas contourner ce garde-fou
par `compose up` sur d'anciennes données : utiliser une migration préparée.
La procédure de [mise à jour du code](../docs/UPDATES.md) ne migre pas les bases.

Une restauration remplace la configuration Graylog. Utiliser un environnement
isolé et vérifier les versions de la sauvegarde, les certificats, les chemins,
les notifications et les connecteurs avant sa mise en réseau. Le `password_secret`
Graylog doit correspondre à la sauvegarde pour relire les secrets chiffrés stockés
en base ; une valeur neuve ne remplace pas ce secret d'origine.

```bash
CONFIRM_RESTORE=YES SOURCE_MONGODB_SERIES=8.0 SOURCE_GRAYLOG_SERIES=7.2 \
  bash deploy.sh restore /chemin/omni-siem-config_DATE.tar.gz.enc
```

Les lookups restaurés sont conservés dans `runtime-lookups/` (hors Git), puis
montés en lecture seule. Un dump MongoDB ne restaure ni les logs OpenSearch ni
les états locaux de tous les robots. La copie des collections ne prouve donc pas
à elle seule une reprise opérationnelle. Tester une vraie restauration complète.

## Diagnostic et secrets fichiers

```bash
bash deploy.sh logs console
bash deploy.sh logs nginx
bash deploy.sh logs graylog
bash deploy.sh down  # arrête les conteneurs ; conserve les volumes
```

Pour une configuration avec secrets fichiers :

```bash
bash gen-secrets.sh
# Placer les valeurs non vides requises par Compose dans .env, puis :
docker compose -f docker-compose.yml -f docker-compose.secrets.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.secrets.yml up -d
```

Vérifier `/soc/`, ses scripts et `/m/api/` selon
[CONSOLE-DEPLOIEMENT.md](../docs/CONSOLE-DEPLOIEMENT.md). Les scripts natifs qui
modifient nginx/systemd ne s'appliquent pas à ce bundle. La syntaxe Compose et
l'entrypoint sont testés ; un démarrage complet avec Docker et une recette sur
les équipements restent à réaliser sur la cible.
