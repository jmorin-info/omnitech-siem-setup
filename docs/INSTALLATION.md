# Installer une nouvelle instance

Pour les commandes Ubuntu ligne par ligne, suivre [UBUNTU-DEMARRAGE.md](UBUNTU-DEMARRAGE.md).

Le point d'entrée est `bash install.sh`. Sans option, ou avec `--plan`, il affiche
un plan sans installer de paquet, modifier de service ni appeler l'API Graylog.
`--generate-secrets` est une opération distincte qui écrit les secrets manquants.
Pour un parcours guidé depuis SSH, lancer `sudo python3 tools/omni-manager.py` :
le menu prépare la configuration et délègue aux mêmes outils d'installation.
Voir [INTERFACE-ADMINISTRATION.md](INTERFACE-ADMINISTRATION.md).
Le profil `core-soc` installe la pile, la collecte de base, le modèle de données,
les enrichissements, les détections de base, les dashboards natifs, la console
`/soc/`, son backend et une sauvegarde applicative quotidienne.
Une phase finale vérifie les services et les entités attendues avant d'enregistrer
la réussite. Voir [la recette Ubuntu 26.04](QUALIFICATION-UBUNTU2604.md).

Ce profil est une installation neuve. Il refuse une machine qui possède déjà les
configurations MongoDB, OpenSearch ou Graylog. Pour une instance existante, suivre
[UPDATES.md](UPDATES.md) pour le code et [DEPLOYMENT.md](DEPLOYMENT.md) pour
redéployer un composant (robots, unités, venvs, console) avec sauvegarde et retour
arrière ; ne pas relancer une boucle sur les scripts numérotés.
Certains de ces scripts sont des opérations de maintenance ou de purge.

## Plateformes et versions

| Plateforme amd64 | État |
|---|---|
| Ubuntu 22.04 LTS | Dépôt MongoDB `jammy`, réseau Netplan, nginx compatible |
| Ubuntu 24.04 LTS | Dépôt MongoDB `noble`, réseau Netplan, nginx compatible |
| Ubuntu 26.04 LTS | Expérimental, option `--experimental-ubuntu-2604` obligatoire ; paquets MongoDB `noble`, hors support officiel de cette pile et sous réserve du noyau |
| Debian 12 | Dépôt MongoDB `bookworm`, réseau ifupdown |
| Debian 13 | Installation de référence existante ; paquets MongoDB `bookworm`, hors liste actuelle des OS Graylog officiellement pris en charge |

Les nouvelles installations utilisent les versions de [stack-versions.env](../stack-versions.env) :
Graylog 7.2.2, OpenSearch 2.19.7 et MongoDB 8.0.38. Les paquets sont épinglés et gelés.
Si un dépôt ne fournit plus une version, l’installation échoue plutôt que de
choisir silencieusement une autre version. Cette matrice ne déclenche aucune
migration des bases existantes. Les chemins Ubuntu ont des contrôles automatisés ;
une recette complète sur VM vierge reste nécessaire avant une mise en production.

Graylog documente Ubuntu 22.04/24.04 et la compatibilité des bases dans sa
[matrice officielle](https://go2docs.graylog.org/current/downloading_and_installing_graylog/compatibility_matrix.htm).
MongoDB fournit les [dépôts Ubuntu8.0](https://www.mongodb.com/docs/v8.0/tutorial/install-mongodb-on-ubuntu/).

## Préparer et installer

Prévoir un serveur dédié amd64 avec AVX, au moins 16 Go de RAM (32 Go recommandés
pour la pile et les extensions), un stockage adapté à la rétention, une adresse
stable et un DNS cohérent. Les heaps de l’exemple visent 32 Go : les réduire si la
machine dispose de 16 Go. Choisir un volume de sauvegarde dimensionné ; une archive
de configuration ne remplace pas une sauvegarde des journaux.
Le plan contrôle le budget mémoire : heaps JVM et cache MongoDB doivent laisser
au moins 3 Gio aux autres services et au système. Les valeurs d'exemple pour
32 Go sont donc refusées sur une VM de 16 Go tant qu'elles ne sont pas adaptées.

```bash
sudo git clone https://github.com/jmorin-info/omnitech-siem-setup.git /opt/omni-siem/repository
cd /opt/omni-siem/repository
cp 00-vars.env.example 00-vars.env
chmod 600 00-vars.env
# Renseigner identité, réseau, stockage, SMTP et le secret administrateur Graylog.
nano 00-vars.env
sudo bash install.sh --generate-secrets
sudo bash install.sh --plan
sudo bash install.sh --apply
```

`/opt/omni-siem/repository` est le dépôt canonique (variable `OMNI_SIEM_HOME`) :
les robots et unités déployés y lisent `00-vars.env` et y exécutent le code. Un
clone ailleurs fonctionne pour l'installation, mais `tools/omni-deploy.py` doit alors
recevoir `--home` ; voir [DEPLOYMENT.md](DEPLOYMENT.md#dépôt-canonique).

`00-vars.env` est un fichier shell de confiance. Il est exécuté par les scripts ;
il doit contenir des affectations uniquement et rester hors du dépôt. Utiliser
des guillemets simples pour les mots de passe contenant `$`, des espaces ou des
caractères spéciaux. Les mots de passe MongoDB sont transmis sans interpolation
JavaScript et encodés dans l’URI de connexion Graylog.

Le plan vérifie les paramètres requis avant toute mutation. L’application suit
une liste explicite de phases, s’arrête au premier échec et enregistre sa progression
dans `/var/lib/omni-siem/install-state.json`. Après correction de la cause :

```bash
sudo bash install.sh --apply --resume
```

La reprise exige le même commit, le même fichier de configuration et les mêmes
options. Par défaut, les fichiers suivis doivent être propres. Pour un correctif
local examiné, `--allow-local-changes` conserve les sources et enregistre leur
empreinte avec une archive privée du diff ; aucun commit local n'est exigé.
La reprise doit conserver ces sources et les options expérimentales éventuelles.
Elle saute les phases de provisioning terminées et rejoue la vérification finale.
La phase échouée peut avoir laissé un
état partiel et doit être inspectée avant la reprise. Le fichier
`/etc/omni-siem/instance.json` enregistre l’origine et la révision après réussite.
Le plan n’expose jamais les valeurs des secrets.

`--generate-secrets` est une opération séparée pour une instance neuve : elle
remplit les secrets MongoDB et OpenSearch absents ou `CHANGEME` sans afficher les
valeurs et sans remplacer les secrets déjà configurés. Le mot de passe Graylog
reste choisi par l'opérateur. Les prérequis CPU, RAM et noyau restent contrôlés :
MongoDB 8 refuse les noyaux 6.19 à 7.0.13 inclus, selon ses
[notes officielles](https://www.mongodb.com/docs/v8.0/release-notes/8.0/).

## Réseau, TLS et stockage

- `APPLY_NETWORK=0` conserve le réseau existant. Avec `1`, les fichiers sont
  préparés et validés ; aucune bascule réseau automatique n’est effectuée.
  Sur Ubuntu, examiner les fichiers Netplan existants puis utiliser `netplan try`
  depuis une console adaptée.
- `NET_ADMIN` autorise SSH. `WEB_NET` autorise HTTPS, avec `NET_ADMIN` comme valeur
  de repli. Aucun accès web public n’est ouvert par défaut. L’installateur refuse
  l’application si le client SSH courant est hors de `NET_ADMIN`.
- Le pare-feu utilise une table `inet omni_siem` et les réseaux du site. Les
  tables tierces sont conservées ; leurs politiques peuvent encore bloquer le
  trafic. Le fragment `/etc/nftables.d/omni-siem.nft` est inclus dans le fichier
  `/etc/nftables.conf` conservé et sauvegardé ; l'application ne redémarre pas le
  service nftables, dont l'arrêt pourrait vider les tables tierces. Contrôler
  `sudo nft list table inet omni_siem` ; l'unité peut rester inactive jusqu'au
  prochain démarrage alors que la table est chargée. Une ancienne déclaration
  inline de cette table exige une migration examinée. Les sources
  envoient directement sur les ports configurés (pas de redirection 514 implicite).
- nginx sert le navigateur en HTTPS 443. Un certificat auto-signé provisoire est
  généré ; le remplacer par un certificat approuvé. La communication nginx/Graylog
  reste HTTP sur loopback pour le bootstrap. Une API déjà en TLS conserve la
  vérification du certificat via `GRAYLOG_API_URL` et `GRAYLOG_API_CA`.
- Ouvrir `https://<fqdn>/soc/`, sans `:9000`. Le port 9000 est l’API locale Graylog
  et n’héberge pas la console SOC.
- `DATA_DISK=""` est la valeur par défaut. Un disque préparé et monté peut être
  utilisé via `DATA_MOUNT`. Le formatage d’un disque vierge exige un nom explicite
  et `ALLOW_FORMAT_DATA_DISK=1` ; les disques avec partitions ou montage sont refusés.
- `THP_MODE=preserve` conserve le choix système. MongoDB 8 recommande THP activé,
  contrairement à MongoDB 7. Sur un serveur partagé avec OpenSearch, valider la
  politique globale avant de choisir `enable` ou `disable` ; cette option n’est
  pas une modification automatique des serveurs existants. Voir les
  [notes MongoDB 8](https://www.mongodb.com/docs/v8.0/administration/production-notes/).

## Outils et connecteurs optionnels

Une installation générique ne peut pas inventer les identifiants M365/SEAL,
l’inventaire métier, les droits AD, les serveurs SMTP ou les politiques SOAR.
Les outils suivants restent disponibles dans le dépôt et s’activent après leur
configuration et une recette sur le site :

| Fonction | Activation et prérequis |
|---|---|
| Triage des mails | `sudo bash install.sh --apply --with triage` sur une installation neuve ; examiner `/etc/omni-alert-triage.env` et adapter SMTP, destinataires et URL de console avant de compter sur les notifications |
| WatchGuard/UniFi/Palo Alto | Catalogue modulaire dans `integrations/` ; parser, stream et dashboard, puis configuration syslog de l’équipement et recette sur des logs réels |
| M365/Entra | Application et droits tenant, secrets, configuration des collecteurs 17/18 ; aucun tenant de référence copié automatiquement |
| SEAL | Connexion SQL et vues documentées dans `seal/README.md` |
| ML/XDR/graphe | Configurations `oms-ml/`, `oms-xdr/`, `oms-graph/`, dépendances et identifiants des streams du nouveau site |
| SOAR et actions AD | Politique de réponse, droits et exclusions du site ; activation distincte après simulation |
| Scans actifs | Périmètre explicitement autorisé ; jamais lancés par le profil de base |
| Collecteurs Windows/Linux | Kits `windows/` et `kit/` ; les sources doivent ensuite être réellement enrôlées |

Les graphiques qui attendent ces sources restent vides tant que la source ou
l’extension correspondante n’a pas été configurée. « Installé » ne signifie pas
que les événements de chaque équipement arrivent déjà.

Sans l'option triage, une installation neuve conserve le routage mail natif et
Teams si configuré. Avec cette option, le triage précède le routage des détections.

## Contrôles de réception

`tools/verify-installation.py` est la réception d'une installation neuve (versions
exactes, entités Graylog attendues, fichiers de la console identiques au dépôt).
`tools/omni-healthcheck.py` est le contrôle de santé réutilisable ensuite, après
chaque déploiement ou redémarrage ; voir [DEPLOYMENT.md](DEPLOYMENT.md#3-vérifier--toolsomni-healthcheckpy).

```bash
sudo python3 tools/verify-installation.py --output /var/lib/omni-siem/acceptance.json
sudo python3 tools/omni-healthcheck.py
systemctl is-active mongod opensearch graylog-server nginx omni-mobile-api
curl -fsS http://127.0.0.1:8090/m/api/vapid
curl --cacert /etc/nginx/ssl/graylog.crt -I https://<fqdn>/soc/
curl --cacert /etc/nginx/ssl/graylog.crt -I https://<fqdn>/soc/app-boot.js
systemctl list-timers siem-backup.timer --no-pager
```

Vérifier aussi la connexion console, les inputs RUNNING, les dashboards et un
événement réel de chaque source. Tester la sauvegarde puis la restauration sur
une machine isolée avant d’annoncer un PRA opérationnel. Un HTTP 200 de `/soc/`
valide la publication des fichiers, pas la collecte ou toutes les extensions.

Pour tester le job installé et consulter son résultat :

```bash
sudo systemctl start siem-backup.service
sudo systemctl show siem-backup.service -p Result -p ExecMainStatus
```

Le job contrôle les archives MongoDB/configuration et attend le `SUCCESS` du
snapshot courant. `BACKUP_SNAPSHOT_TIMEOUT_SECONDS` règle cette attente
(3 600 secondes par défaut, à adapter au volume et au stockage). Le premier jour
ne réclame pas un snapshot de la veille. La rétention ne s'exécute qu'après une
sauvegarde réussie, sur les seuls noms natifs ; les snapshots tiers sont conservés.
Les archives privées incluent le fichier du site, la configuration et l'état
console, ainsi que les fragments de pare-feu présents. Les exporter vers un
stockage protégé hors du serveur. Le succès du job ne remplace pas une restauration testée.

## Variante Docker

Le bundle Docker contient la pile, nginx et la console, avec les mêmes versions
de base. Il fournit une infrastructure vide : il faut importer des Content Packs
ou restaurer une configuration de la même série, puis configurer les sources.
Les scripts natifs ne doivent pas être exécutés aveuglément contre les conteneurs
(chemins de certificats, adresses et API diffèrent).

```bash
cd docker
cp .env.example .env
chmod 600 .env
# Remplacer les secrets et SERVER_NAME.
docker compose config --quiet
bash deploy.sh up
```

Le profil analytics n’est pas lancé par défaut : il exige une configuration XDR
avec les identifiants de streams propres à l’instance. Monter cette configuration
avec `OMS_CONFIG_HOST`, définir `OMS_CONFIG_FILE=/app/site-config.yaml`, puis
activer explicitement `docker compose --profile analytics up -d`.

`deploy.sh up` refuse les conteneurs MongoDB d’une autre série que8.0 et Graylog
d’une autre série que7.2. Il refuse aussi un ancien volume Mongo sans conteneur
identifiable. Ne pas contourner ce contrôle avec un `compose up` direct sur des
volumes existants : préparer une migration et un retour arrière documentés.

Une restauration avec remplacement de configuration exige une sauvegarde dont
les versions ont été vérifiées :

```bash
CONFIRM_RESTORE=YES SOURCE_MONGODB_SERIES=8.0 SOURCE_GRAYLOG_SERIES=7.2 \
  bash deploy.sh restore sauvegarde.tar.gz.enc
```

La restauration remplace la base Graylog. Elle n’est ni une mise à jour tenant ni
un moyen de distribuer les secrets OMNITECH. Les lookups restaurés restent dans
`docker/runtime-lookups/`, bind mount local en lecture seule pour Graylog.
