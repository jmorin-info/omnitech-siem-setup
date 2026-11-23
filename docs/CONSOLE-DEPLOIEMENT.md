# Déployer ou réparer la console SOC

La console du projet est publiée par **nginx sur HTTPS, port 443**, sous `/soc/`.
Le port 9000 sert Graylog et son API ; il ne sert pas les fichiers de cette console.
Une page Graylog fonctionnelle n'implique donc pas que `/soc/` soit installé.

## Installation native

Sur une installation neuve, `sudo bash install.sh --apply` inclut la console.
Sur un SIEM existant, depuis sa copie du dépôt mise à jour :

```bash
# Inspecter les routes à ajouter et les fichiers à publier (aucune modification).
sudo bash tools/install-console.sh

# Installer les composants manquants et publier la console.
sudo bash 71-soc-console.sh
```

L'opération copie tous les assets publics de `mobile/soc/` : scripts `app*.js`,
bibliothèques, images de carte, icônes, manifeste et service worker. Elle ajoute
les routes manquantes dans `/etc/nginx/sites-enabled/graylog`, sans remplacer
les locations ni les restrictions d'accès qui existent déjà. Pour un autre vhost,
définir `NGINX_SITE=/chemin/du/vhost` explicitement.

La configuration nginx modifiée est sauvegardée hors des répertoires inclus,
validée par `nginx -t`, puis rechargée. Si la validation ou le rechargement échoue,
le fichier est restauré. Les assets publics déjà copiés ne sont pas annulés par
ce retour arrière de configuration.

Si le backend est absent, il est installé sous `/opt/omni-siem/console` avec un
compte système dédié, des secrets générés localement et une configuration dans
`/etc/default/omni-mobile`. Les accès Graylog existants servent à l'authentification ;
AD/LDAPS n'est pas un prérequis imposé à tous les sites. L'API locale HTTP permet
le bootstrap ; une API TLS exige son FQDN et sa CA (`SIEM_FQDN`, `GRAYLOG_API_CA`).

Un backend installé et identifié par ce mécanisme possède `backend.json` sous
son répertoire applicatif. Lors d'une publication ultérieure, son empreinte est
contrôlée, l'ancien code sauvegardé, le nouveau code activé et sa santé vérifiée.
En cas d'échec, l'ancien code est restauré et le service redémarré. Un changement
local du backend bloque cette activation. Les secrets et données ne sont pas remplacés.

Pour un **ancien service personnalisé**, son code et sa configuration restent en
place. Vérifier `systemctl cat omni-mobile-api` et adapter sa procédure de mise en
service ; une mise à jour du dépôt ne met pas nécessairement à jour son `ExecStart`.
Les endpoints de SOAR, graphe ou supervision qui dépendent d'autres services peuvent
rester indisponibles tant que ces extensions ne sont pas configurées.

### Identité du site et journaux affichés

Sur une installation native, le backend lit `/etc/default/omni-mobile`. Les nouvelles
installations y inscrivent les valeurs du site ; une configuration existante est
conservée. Pour l'adapter, modifier les seules variables nécessaires, puis lancer
`sudo systemctl restart omni-mobile-api` :

```ini
SIEM_FQDN=siem.example.interne
SIEM_IP=192.0.2.10
SOC_ORIGINS=siem.example.interne,192.0.2.10
SOC_LOG_INDICES=omni-*,graylog_*
SOC_ADMINS=analyste-responsable
```

Remplacer le nom et l'adresse d'exemple. `SIEM_FQDN` et `SIEM_IP` alimentent la page
Déploiement ; aucun nom ni adresse du site de référence ne sert de valeur de repli.
`SOC_ORIGINS` contient les noms ou IP autorisés pour les actions provenant du
navigateur, sans schéma ni chemin. À défaut, le backend utilise l'identité du site
et le nom de son API Graylog. L'authentification reste assurée par Graylog.
Si la console est aussi atteinte par un autre nom (proxy ou publication via le pare-feu),
ce nom doit figurer dans `SOC_ORIGINS` : sinon les écritures d'administration sont refusées
(« origine absente ou refusée » dans le journal d'administration, « Connexion au SIEM
interrompue » dans la console). Définir alors la liste complète, valeurs par défaut comprises.

`SOC_ADMINS` énumère les identifiants Graylog autorisés aux demandes SOAR et aux
notifications push, séparés par des virgules. Une liste vide n’accorde ces droits
à personne. Conserver les comptes autorisés existants lors d’une mise à jour.
Les lectures de la console utilisent le périmètre OpenSearch du backend : elles
ne reproduisent pas les restrictions par stream de chaque compte Graylog.
Réserver donc l’accès à la console aux opérateurs habilités à voir ces journaux.

`SOC_LOG_INDICES` délimite les indices des journaux utilisés par la recherche et
les vues globales. Sa valeur par défaut inclut `graylog_*`, utilisé par les modules
natifs WatchGuard, UniFi et Palo Alto, en plus des sources `omni-*`. Ajouter les
préfixes propres au site si ses index sets utilisent d'autres noms, par exemple
`omni-*,graylog_*,client-*`. Les motifs doivent comporter un préfixe explicite avec
un tiret ou un soulignement ; `*`, `_all`, les préfixes système et les chemins sont
refusés. Les requêtes dédiées aux événements Graylog ou à une source particulière
gardent leur périmètre propre.

En Docker, renseigner `SIEM_IP` et `SOC_LOG_INDICES` dans `docker/.env` ;
`SERVER_NAME` fournit le FQDN et l'origine autorisée. Puis recréer le service :
`docker compose up -d console`. Une erreur OpenSearch renvoie un état indisponible
(`502` ou `503`) ; elle ne doit pas être interprétée comme l'absence de journaux
ou une situation nominale.

### Choisir les sources dont la collecte doit être surveillée

`SOC_EXPECTED_SOURCES` définit les seules sources attendues par le site, avec leur
délai maximal sans journal en minutes. Par exemple :

```ini
SOC_EXPECTED_SOURCES=watchguard:120,unifi:240,paloalto:120
```

N'ajouter que les sources effectivement prévues. Les noms correspondent au champ
`event_source` des journaux ; utiliser des minuscules, chiffres, tirets ou
soulignements, en commençant par une lettre. Chaque source apparaît une seule fois,
avec un seuil entier compris entre `1` et `43200` minutes. Une configuration
invalide empêche le démarrage du backend, sans afficher les valeurs saisies.

Une valeur explicitement vide (`SOC_EXPECTED_SOURCES=`) ne déclare aucune source
attendue : les journaux reçus restent visibles, sans inventer de collecteurs
manquants. Les nouvelles installations natives et Docker écrivent cette valeur
vide. Pour préserver les installations historiques, l'absence complète de cette
variable conserve la liste des onze sources historiques et leurs seuils.

En natif, renseigner cette variable dans `00-vars.env` avant une nouvelle
installation ; sur un serveur déjà installé, adapter `/etc/default/omni-mobile`
puis redémarrer `omni-mobile-api`. En Docker, la définir dans `docker/.env` puis
recréer le service `console`. Ces réglages suivent les arrivées de journaux ; ils
ne créent ni input, ni règle de pare-feu, ni configuration sur l'équipement.

## Espace Administration

Fonctionnement et matrice des actions : [CONSOLE-SOC.md](CONSOLE-SOC.md#espace-administration).

### Paramètres du backend (`/etc/default/omni-mobile`)

Toutes les variables sont facultatives ; les valeurs indiquées sont les défauts.

```ini
# Clone du dépôt utilisé pour lookups et oms-graph (lu aussi depuis l'environnement)
OMNI_REPO_DIR=/opt/omni-siem/repository
# Dérivés surchargeables : OMS_GRAPH_DIR, OMS_GRAPH_PY, OMS_GRAPH_CFG, MITRE_LOOKUP
# Rôles et audit
SOC_ADMIN_DIR=/var/lib/omni-mobile/admin
SOC_DEFAULT_ROLE=analyste
# Apparence de la console (appearance.json et logo), dérivé du dossier de MOBILE_SUBS_FILE
SOC_APPEARANCE_DIR=/var/lib/omni-mobile/appearance
# Écritures d'administration limitées aux réseaux internes
SOC_ADMIN_INTERNAL_ONLY=1
SOC_ADMIN_NETS=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,fc00::/7
# Validation par un second administrateur, validité d'une demande (s), simulation globale
SOC_ADMIN_SELF_APPROVE=0
SOC_ADMIN_APPROVAL_TTL=86400
SOC_ADMIN_DRY_RUN=0
SOC_ADMIN_WRITES_PER_5MIN=30
# Copie GELF du journal d'audit (vide = désactivée)
SOC_ADMIN_GELF_URL=http://127.0.0.1:12201/gelf
# Détections Graylog : fichier contenant un jeton d'accès (vide = onglet indisponible)
SOC_GRAYLOG_TOKEN_FILE=
# Services redémarrables (doivent aussi figurer dans SOC_EXEC_RESTARTABLE de l'exécuteur)
SOC_ADMIN_RESTARTABLE=
```

Les chemins des services réutilisés ont des défauts conformes à la production et ne sont
à surcharger que sur une autre installation : `SOC_TRIAGE_URL`, `SOC_TRIAGE_ENV`,
`SOC_SOAR_URL`, `SOC_SOAR_ENV`, `SOC_SOAR_STATE`, `SOC_SOAR_META`, `SOC_SOAR_EXCL`,
`SOC_SOAR_FIX`, `SOC_SOAR_DEC`, `SOC_SYSTEMCTL`. Une plage invalide dans `SOC_ADMIN_NETS`
empêche le démarrage du backend.

Sur une installation neuve où le backend tourne sous le compte `omni-console`,
`/etc/omni-alert-triage.env` n'est généralement pas lisible par ce compte : l'onglet
Paramètres l'indique et l'ajout de faux positifs échoue faute de jeton de triage.

Les chemins d'état (`MOBILE_SUBS_FILE`, `MOBILE_CASES_FILE`, `MOBILE_WATCH_FILE`,
`SOC_REQ_DIR`, `SOC_ADMIN_DIR`, `SOC_APPEARANCE_DIR`) se lisent dans ce fichier ou, à défaut, dans
l'environnement. Avec `OMNI_TEST_MODE=1` (imposé par la suite de tests), le backend et
l'exécuteur refusent de démarrer si l'un d'eux vise `/var/lib`, `/etc`, `/var/www`,
`/var/log`, `/usr` ou `/opt/oms-*`, et aucune copie GELF n'est émise.

Le venv du backend s'installe à partir de `mobile/requirements.txt` (pywebpush et ses
dépendances, versions alignées sur le venv en service le 21/11/2026).

### Exécuteur privilégié

Le backend est confiné (écriture limitée à `/var/lib/omni-mobile`). Les actions qui
modifient `/etc/omni-soar/*` ou `/etc/omni-alert-triage.env`, ou redémarrent un service,
sont déposées dans `SOC_ADMIN_DIR/exec/pending` puis appliquées par
`omni-soc-admin-exec` (root, oneshot, déclenché par une unité path et un timer de
rattrapage de 5 minutes ; fichiers dans `mobile/` et `mobile/systemd/`). Sans exécuteur
installé, ces demandes restent à l'état « Transmise à l'exécuteur » ; l'onglet Supervision
affiche son dernier passage. Sa liste blanche de redémarrages (`SOC_EXEC_RESTARTABLE` dans
`/etc/default/omni-soc-admin-exec`, modèle `mobile/systemd/omni-soc-admin-exec.default.example`)
est vide par défaut.

### Jeton Graylog pour les détections

Créer dans Graylog un utilisateur de service dédié (par exemple `soc-console`), limité à
la lecture et à la modification des définitions d'événements, puis un jeton d'accès pour
cet utilisateur. Déposer ce jeton dans `/etc/omni-mobile/graylog-admin.token` (droits
`600`, jamais dans le dépôt) et renseigner
`SOC_GRAYLOG_TOKEN_FILE=/etc/omni-mobile/graylog-admin.token`.

### Configuration nginx non versionnée

Le vhost en service référence des éléments absents du dépôt : les zones `limit_req`
`omni_api` (utilisée par `location /m/api/`) et `omni_auth` (login Graylog), déclarées dans
`/etc/nginx/conf.d/omni-ratelimit.conf`, et `/var/www/siem-mobile/sw-retire.js` (retrait de
l'ancien service worker `/m/`). Les conserver lors d'une réinstallation ; sur un nouveau
serveur, déclarer ces zones avant de reprendre ce vhost, sinon `nginx -t` échoue. Leur
versionnement relève du chantier de déploiement. L'espace Administration n'ajoute aucune
route nginx : il passe par `location /m/api/`, qui doit continuer à poser
`proxy_set_header X-Real-IP $remote_addr;` (utilisé pour la restriction réseau).

### Déployer cette version en production

Commandes à exécuter par l'administrateur, après fusion de la branche dans `main`.
Aujourd'hui, `omni-mobile-api` exécute `/root/omnitech-siem-setup/mobile/omni-mobile-api.py`
avec le venv de cette ancienne copie ; la procédure le repointe vers le clone de référence.

1. Mettre à jour le clone : `cd /opt/omni-siem/repository && git pull --ff-only`.
2. Sauvegarder : `TS=$(date +%Y%m%d-%H%M%S)`, puis
   `cp -a /etc/default/omni-mobile /etc/default/omni-mobile.avant-admin-$TS` et
   `cp -a /var/www/siem-soc /var/backups/siem-soc.avant-admin-$TS`.
3. Créer le venv : `python3 -m venv /opt/omni-siem/repository/mobile/.venv`, puis
   `/opt/omni-siem/repository/mobile/.venv/bin/pip install -r /opt/omni-siem/repository/mobile/requirements.txt`.
4. Ajouter à `/etc/default/omni-mobile` (sans rien retirer) : `OMNI_REPO_DIR=/opt/omni-siem/repository`
   et, tant que le clone n'a pas de venv oms-graph,
   `OMS_GRAPH_PY=/root/omnitech-siem-setup/oms-graph/.venv/bin/python`.
5. Créer le drop-in `/etc/systemd/system/omni-mobile-api.service.d/20-depot-reference.conf`
   contenant une section `[Service]`, une ligne `ExecStart=` vide puis
   `ExecStart=/opt/omni-siem/repository/mobile/.venv/bin/python /opt/omni-siem/repository/mobile/omni-mobile-api.py`.
   **Ne pas redémarrer le service avant que le venv de l'étape 3 existe** : sans lui,
   le service échoue au démarrage (`status=203/EXEC`).
6. Installer l'exécuteur :
   `install -m 755 /opt/omni-siem/repository/mobile/omni-soc-admin-exec /usr/local/sbin/`,
   `install -m 644 /opt/omni-siem/repository/mobile/systemd/omni-soc-admin-exec.service /opt/omni-siem/repository/mobile/systemd/omni-soc-admin-exec.path /opt/omni-siem/repository/mobile/systemd/omni-soc-admin-exec.timer /etc/systemd/system/`,
   et, si absent, copier `omni-soc-admin-exec.default.example` vers `/etc/default/omni-soc-admin-exec` (droits `640`).
7. Publier les assets : `install -m 644 /opt/omni-siem/repository/mobile/soc/*.js /opt/omni-siem/repository/mobile/soc/*.css /opt/omni-siem/repository/mobile/soc/index.html /var/www/siem-soc/`,
   puis `chown www-data:www-data /var/www/siem-soc/*.js /var/www/siem-soc/*.css /var/www/siem-soc/index.html`.
8. Activer : `systemctl daemon-reload`,
   `systemctl enable --now omni-soc-admin-exec.path omni-soc-admin-exec.timer`,
   `systemctl restart omni-mobile-api`.
9. Contrôler : `systemctl show omni-mobile-api -p ExecStart --value`,
   `curl -fsS http://127.0.0.1:8090/m/api/vapid`, `journalctl -u omni-mobile-api -n 30 --no-pager`.

Ensuite, depuis un poste du réseau interne, ouvrir `/soc/`, accepter **Recharger** (service
worker `soc-v6-2026112101`), vérifier l'entrée **Administration** avec un compte de
`SOC_ADMINS`, lancer une **simulation** (par exemple un blocage SOAR) et contrôler qu'elle
apparaît dans l'onglet **Journal** avec une chaîne vérifiée. Facultatif, une fois
`audit.jsonl` créé : `chattr +a /var/lib/omni-mobile/admin/audit.jsonl` interdit la
réécriture du journal tout en autorisant les ajouts.

Retour arrière : supprimer le drop-in `20-depot-reference.conf`, restaurer
`/etc/default/omni-mobile.avant-admin-$TS` et `/var/backups/siem-soc.avant-admin-$TS`,
désactiver `omni-soc-admin-exec.path` et `omni-soc-admin-exec.timer`, puis
`systemctl daemon-reload` et `systemctl restart omni-mobile-api`. L'ancienne version
ignore les fichiers de `/var/lib/omni-mobile/admin`.

## Distinguer les erreurs

| Symptôme | Vérifications et action |
|---|---|
| `404 Not Found` sur `/soc/` | Vérifier l'URL sans `:9000`, le bon vhost nginx et la présence de `/var/www/siem-soc/index.html`. Publier avec le script ci-dessus. |
| Page présente, écran vide ou JS en 404 | Vérifier `app-boot.js`, `app-loader.js`, `app.js`, icônes et bibliothèques. Une copie du seul HTML est insuffisante. |
| `502 Bad Gateway` sur `/m/api/` | Vérifier `omni-mobile-api`, le port local 8090 et les logs du backend. Une correction des fichiers statiques ne répare pas son transport Graylog. |
| Réponse `401` sans connexion | Comportement normal pour un endpoint protégé ; vérifier ensuite le login avec un compte Graylog valide. |
| Login refusé / TLS | Vérifier la CA et le nom du serveur utilisés par le backend ; ne pas désactiver la validation TLS pour contourner l'erreur. |
| Page 200 mais graphiques vides | Vérifier les sources, pipelines, champs et extensions. HTTP 200 n'atteste pas que les données arrivent. |

```bash
systemctl status nginx omni-mobile-api --no-pager
nginx -t
nginx -T 2>/dev/null | rg 'location|siem-soc|8090'
ls -l /var/www/siem-soc/index.html /var/www/siem-soc/app-boot.js
curl -fsS http://127.0.0.1:8090/m/api/vapid
journalctl -u omni-mobile-api -n 50 --no-pager
```

Depuis le navigateur ou avec la CA approuvée du site, contrôler `/soc/`,
`/soc/app-boot.js`, `/soc/app-loader.js`, `/soc/icons/icon-192.png` et
`/soc/manifest.webmanifest`. Les anciennes versions mises en cache par un service
worker peuvent nécessiter un rechargement ou l'effacement des données du site.

## Docker

La console est un service Compose distinct du service Graylog :

```bash
cd docker
docker compose ps
docker compose logs --tail=80 console nginx
docker compose config --quiet
```

Le frontal reste `https://<SERVER_NAME>/soc/` sur le port 443. Le port Graylog 9000
est publié sur loopback pour le diagnostic. Les scripts natifs de configuration
nginx/systemd ne doivent pas être exécutés dans cette variante.

L'entrypoint écrit sa configuration privée dans le volume de données avec les
droits de l'utilisateur du conteneur ; il accepte secrets d'environnement et
fichiers `*_FILE`. Le transport HTTP vers le seul nom de service interne `graylog`
est une option explicite du conteneur. Le navigateur continue d'utiliser HTTPS.

## Vérifications automatisées et limites

Les tests couvrent les assets, les routes absentes, la préservation des ACL,
le rollback nginx, le lancement de l'entrypoint avec les deux modes de secrets,
le refus HTTP vers d'autres serveurs et le rollback du backend géré.
Un test réel de Nginx 1.24 sur Ubuntu 24.04 vérifie les réponses 200 et 404 des
ressources. La pile Docker complète et la collecte de chaque équipement doivent
encore faire l'objet d'une recette sur l'environnement cible.
