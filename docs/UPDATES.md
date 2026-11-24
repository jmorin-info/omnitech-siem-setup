# Mises à jour de la plateforme OMNI SIEM

Ce guide couvre **toutes les couches** de mise à jour du SIEM : code du dépôt, paquets
du système et correctifs de sécurité, pile Graylog / OpenSearch / MongoDB (et Logstash),
dépendances Python des services, contenus de détection et intégrations. Pour chaque
couche : comment savoir ce qui est disponible, lire le plan, vérifier les pré-requis,
exécuter explicitement, contrôler le résultat et revenir en arrière.

Règle commune : **la consultation et le plan sont toujours en lecture seule**. Aucune
commande de ce guide ne modifie la machine sans option explicite (`apply-code`,
`--execute --confirm ...`, `--write`).

## Sommaire

1. [Vue d'ensemble des couches](#1-vue-densemble-des-couches)
2. [Politique de mise à jour](#2-politique-de-mise-à-jour)
3. [Point d'entrée unique : état des mises à jour](#3-point-dentrée-unique--état-des-mises-à-jour)
4. [Couche code du dépôt (omni-update.py)](#4-couche-code-du-dépôt-omni-updatepy)
5. [Couche paquets OS et sécurité](#5-couche-paquets-os-et-sécurité)
6. [Couche pile Graylog / OpenSearch / MongoDB : runbook](#6-couche-pile-graylog--opensearch--mongodb--runbook)
7. [Couche dépendances Python des venvs](#7-couche-dépendances-python-des-venvs)
8. [Couche contenus de détection et intégrations](#8-couche-contenus-de-détection-et-intégrations)
9. [Gestionnaire SSH](#9-gestionnaire-ssh)
10. [Sauvegardes, restauration et preuve de résilience](#10-sauvegardes-restauration-et-preuve-de-résilience)
11. [Garder GitHub et les fichiers réellement servis cohérents](#11-garder-github-et-les-fichiers-réellement-servis-cohérents)
12. [Limites connues](#12-limites-connues)
13. [Mise à jour depuis la console SOC (en un clic)](#13-mise-à-jour-depuis-la-console-soc-en-un-clic)

## 1. Vue d'ensemble des couches

Les pages et widgets SOC configurés sur le site sont des **données locales**, pas du
code à synchroniser : `SOC_MODULES_DIR/config.json` reste conservé lors d'une mise à
jour et d'un retour arrière. Inclure son emplacement dans les sauvegardes du site.
Le [guide des modules de la console](CONSOLE-MODULES.md) décrit leurs droits, leurs
filtres et l'arrivée de nouvelles machines.

Pour la publication automatique de la console, le plan contrôle aussi le profil réel :
backend exécuté depuis le dépôt configuré, port 8090, alias nginx standards
`/var/www/siem-soc` et `/var/www/siem-mobile`. Une copie séparée du backend ou des
chemins web personnalisés exige une publication manuelle adaptée et bloque le plan
automatique concerné avant modification. Les paramètres `UPDATE_CONSOLE_CONFIG`
et `UPDATE_NGINX_SITE` permettent de désigner les fichiers de configuration à inspecter ;
ils ne rendent pas un profil personnalisé automatiquement compatible.
Une redirection explicite de l'ancienne interface `/m/` vers `/soc/` est acceptée
et conservée ; elle n'est pas réactivée en tant qu'interface séparée.

| Couche | Détection (lecture seule) | Exécution explicite | Retour arrière | Automatisme existant en production |
|---|---|---|---|---|
| Code du dépôt | `omni-update-status.py --layer code`, `omni-update.py fetch` puis `plan` ; console SOC, Administration > Mises à jour (§ 13) | `omni-update.py stage` puis `apply-code` ; ou mise à jour en un clic depuis la console (§ 13) | `omni-update.py rollback` / `recover` ; retour arrière automatique ou manuel de la console (§ 13) | `omni-console-update-check.timer` (recherche quotidienne, une fois installé) |
| Paquets OS | `omni-update-status.py --layer os` | `unattended-upgrades` (sécurité), `oms-maj-siem` (hebdomadaire) | réinstallation de la version précédente (`apt-get install paquet=version`) ; sauvegardes `oms-maj-siem` dans `/data/backups/maj-*` | `apt-daily-upgrade.timer` (quotidien), `oms-maj-siem.timer` (dimanche 04:30) |
| Pile Graylog / OpenSearch / MongoDB / Logstash | `omni-update-status.py --layer stack`, `omni-stack-upgrade.py plan` | `omni-stack-upgrade.py apply --execute --confirm` | `omni-stack-upgrade.py rollback` (paquet) ; restauration MongoDB manuelle | `omni-version-watch.timer` (veille quotidienne) ; `oms-maj-siem` applique les correctifs **dans la série épinglée** |
| Dépendances Python | `omni-pydeps.py audit`, `omni-update-status.py --layer python` | réinstallation depuis le verrouillage (`pip install --no-deps -r python-locks/<venv>.txt`) | restaurer la copie du venv ou l'ancien verrouillage (Git) | aucun |
| Contenus de détection et intégrations | `omni-update-status.py --layer content [--graylog]`, `./synchro-manifeste.sh` | `omni-integrations.py install --apply`, scripts de provisioning numérotés | `omni-integrations.py uninstall --apply` ; sauvegarde de configuration | aucun |
| Pré-requis (santé, disque, sauvegardes) | `omni-update-status.py --layer health` | sans objet | sans objet | `omni-backup-config.timer` (03:15), `oms-snap-siem.timer` (01:30), `oms-snap-siem-test.timer` (mercredi 11:00) |

Tous les outils se trouvent dans `tools/` et reposent sur le paquet Python `omni_update/`
(bibliothèque standard uniquement, aucune dépendance à installer).

## 2. Politique de mise à jour

> Les éléments marqués **[en place]** sont vérifiables sur le serveur. Les éléments marqués
> **[proposé]** constituent la politique recommandée : ils doivent être validés par le RSSI
> avant d'être considérés comme applicables.

### Fréquence

| Couche | Fréquence |
|---|---|
| Correctifs de sécurité Debian | quotidienne, automatique, sans redémarrage immédiat (`unattended-upgrades`) ; un redémarrage requis est effectué au passage hebdomadaire suivant **[en place]** |
| Autres paquets Debian et correctifs de la pile **dans la série épinglée** | hebdomadaire, automatique, dimanche 04:30 (`oms-maj-siem`), avec redémarrage automatique si `/var/run/reboot-required` **[en place]** |
| Changement de série de la pile (ex. Graylog 7.2 vers 7.3) | au plus une fois par trimestre, en fenêtre planifiée, après lecture des notes de version et recette sur une VM de test **[proposé]** |
| Code du dépôt | à la demande, uniquement une révision dont la suite `bash run-tests.sh` est verte **[proposé]** |
| Dépendances Python | audit mensuel (`omni-pydeps.py audit`) ; mise à jour trimestrielle ou immédiate en cas de vulnérabilité publiée **[proposé]** |
| Contenus de détection et intégrations | à la demande, après recette sur logs réels **[proposé]** |
| Veille de versions | quotidienne (`omni-version-watch`, 07:15) **[en place]** |

### Fenêtre

- Automatique : dimanche 04:30 (`oms-maj-siem.timer`, délai aléatoire de 10 min) **[en place]**.
- Manuelle (pile, code, venvs) : jour ouvré, en matinée, administrateur présent pendant
  toute l'opération et la vérification, jamais la veille d'un jour non travaillé **[proposé]**.
- Redémarrage automatique : règle retenue par l'administrateur le 22/11/2026 **[en place]**.
  `unattended-upgrades` ne redémarre jamais (`52omni-siem.conf`, `Automatic-Reboot "false"`) ;
  c'est `oms-maj-siem` qui redémarre la machine, dans les conditions exactes suivantes
  (`deploye/sbin/oms-maj-siem`, `deploye/systemd/oms-maj-siem*.{timer,service}`) :
  - déclenchement par `oms-maj-siem.timer`, dimanche 04:30 plus un délai aléatoire de 0 à
    10 minutes, sans rattrapage (`Persistent=false`) ;
  - redémarrage uniquement si `/var/run/reboot-required` existe à la fin du passage, que
    l'indicateur vienne d'un paquet installé ce jour-là ou d'un correctif appliqué dans la
    semaine par `unattended-upgrades` (un indicateur présent suffit à lancer le passage
    même sans paquet en attente) ;
  - jamais avant les contrôles préalables (`/data` monté, OpenSearch vert, API Graylog,
    3 Gio libres sur `/var`, `apt-get update`) ni avant la sauvegarde : si l'un échoue, ou
    si `mongodump` échoue, le passage est annulé sans redémarrage ; rien non plus s'il n'y a
    rien à faire, ni en mode `--simuler` ;
  - le redémarrage est programmé 60 secondes après la fin (`systemd-run`, unité
    `oms-maj-siem-reboot`), y compris si `apt-get dist-upgrade` a signalé un échec ;
  - au démarrage, `oms-maj-siem-postboot.service` (activé, `oms-maj-siem --apres-boot`,
    120 s après le démarrage) n'agit que si le redémarrage vient d'`oms-maj-siem` : il
    refait les réparations connues, le contrôle final (services, OpenSearch, API Graylog,
    montage de `/data` déverrouillé par TPM2) et envoie le compte rendu par courriel ;
  - un lancement manuel (`systemctl start oms-maj-siem.service`) applique les mêmes règles
    et peut donc redémarrer la machine hors de la fenêtre du dimanche.

  Si le déverrouillage TPM2 de `/data` échoue au redémarrage, le compte rendu signale
  « /data NON MONTE » et l'ouverture se fait à la main avec la passphrase de secours
  ([procédure de chiffrement au repos](securite-conformite/PROCEDURE-CHIFFREMENT-REPOS.md)).

### Qui valide

- Administrateur SIEM : exécute, vérifie et consigne toute opération manuelle **[proposé]**.
- RSSI : valide au préalable tout changement de série de la pile, toute opération entraînant
  une interruption de collecte de plus de 15 minutes et toute restauration MongoDB **[proposé]**.

### Sauvegarde préalable obligatoire

Avant toute opération sur la pile : une sauvegarde de configuration **vérifiée** de moins de
26 heures (archive `/var/backups/siem/omni-siem-config_*.tar.gz.enc` produite par
`omni-backup-config`, dont le passage contrôle la restaurabilité) **et** un `mongodump`
dédié à l'opération. `omni-stack-upgrade.py` contrôle la première condition et réalise le
second avant tout arrêt de service ; `oms-maj-siem` réalise de son côté un `mongodump` et une
archive `/etc` dans `/data/backups/maj-AAAAMMJJ-HHMM` **[en place]**.

### Consignation

Chaque opération manuelle est consignée : commande, révision ou version, journal produit
(`/var/lib/omni-siem-stack-upgrade/<id>.json`, `/var/lib/omni-siem-manager/jobs/`,
`/var/lib/omni-siem-updater/backups/<transaction>/transaction.json`) et résultat des
vérifications **[proposé]**.

## 3. Point d'entrée unique : état des mises à jour

```bash
python3 tools/omni-update-status.py                 # texte
python3 tools/omni-update-status.py --json          # JSON stable (schema_version 1)
python3 tools/omni-update-status.py --layer stack --layer os
sudo python3 tools/omni-update-status.py --source /root/omnitech-siem-setup   # examiner une autre copie
GRAYLOG_API_TOKEN=... python3 tools/omni-update-status.py --graylog --layer content
python3 tools/omni-update-status.py --exit-code     # 0 : ok/info, 1 : attention/inconnu, 2 : action requise
```

L'outil est en lecture seule : il lance uniquement `dpkg-query`, `apt-cache policy`,
`apt list --upgradable`, `apt-mark showhold`, `apt-config dump`, `systemctl show`, des
commandes Git de lecture et `pip list` (sans index), et des requêtes HTTP GET vers
OpenSearch (`127.0.0.1:9200`) et l'API Graylog (`127.0.0.1:9000`). Il **ne lance jamais**
`apt-get update` (c'est le rôle d'`apt-daily.timer`) ni `git fetch`. Il ne lit dans
`00-vars.env` que `BACKUP_DIR` et `DATA_MOUNT`. Une couche en erreur est signalée
`inconnu` sans masquer les autres.

`--source` désigne la copie installée examinée par la couche code (et lue pour
`00-vars.env`) ; les inventaires de référence (`stack-versions.env`, `python-locks/`,
`integrations/`, `manifeste-deploye.txt`) proviennent toujours du dépôt de l'outil.

### Schéma JSON (version 1)

```json
{
  "schema_version": 1,
  "generated_at": "2026-11-21T14:22:02+00:00",
  "host": "bx-it-graylog-vm.omnitech.security",
  "source": "/chemin/copie/examinée",
  "repository": "/chemin/dépôt/de/référence",
  "read_only": true,
  "overall": "info",
  "layers": [
    {
      "id": "stack",
      "title": "Pile Graylog / OpenSearch / MongoDB",
      "status": "info",
      "summary": "conforme à la référence",
      "errors": [],
      "items": [
        {"name": "graylog-server", "status": "info",
         "detail": "installé 7.2.2-1 ; 7.2.2-2 disponible dans la série autorisée ; ...",
         "installed": "7.2.2-1", "available": "7.2.2-2", "reference": "7.2.2-1",
         "held": false, "pin": "7.2.*"}
      ]
    }
  ]
}
```

Contrat de stabilité :

- `layers[].id` prend les valeurs `code`, `os`, `stack`, `python`, `content`, `health`,
  toujours dans cet ordre lorsque toutes les couches sont demandées.
- `status` (global, par couche et par élément) vaut `ok`, `info`, `inconnu`, `attention`
  ou `action` (gravité croissante) ; `overall` et `layers[].status` valent la pire valeur
  de leurs éléments.
- Chaque élément porte au minimum `name`, `status`, `detail` (texte français destiné à
  l'affichage). Les champs facultatifs `installed`, `available`, `reference`, `held`, `pin`,
  `security`, `packages`, `holds`, `local_changes`, `behind`, `ahead`, `upstream`,
  `code_revision`, `identical`, `different`, `absent`, `missing`, `extra`, `mismatched`,
  `unpinned_requirements`, `venv`, `age_hours`, `age_days` complètent selon la couche.
- Tout changement incompatible incrémentera `schema_version`. Un consommateur (gestionnaire
  SSH, console SOC) doit ignorer les champs qu'il ne connaît pas.

La console SOC n'intègre pas encore ce document ; il est conçu pour être exposé tel quel par
son backend (lecture seule, exécution par un compte disposant des droits de lecture apt et Git).

## 4. Couche code du dépôt (omni-update.py)

`tools/omni-update.py` prépare une révision Git précise, affiche les différences,
sauvegarde les fichiers de code qu'il remplace et permet de revenir sur sa dernière
transaction. Il met à jour le **code applicatif et les fichiers statiques du dépôt
installé** : il ne lance aucun script de provisioning, ne met à jour aucun paquet système,
n'écrit dans aucune base et ne modifie ni `git HEAD`, ni la configuration du site.
L'état est conservé hors du dépôt, par défaut dans `/var/lib/omni-siem-updater`.

État constaté le 21/11/2026 : ce répertoire n'existe pas sur la production ; l'outil n'y a
jamais été utilisé. La copie `/root/omnitech-siem-setup` (qui porte encore des services) a
5 commits de retard sur `origin/main` selon son dernier fetch et des fichiers suivis modifiés
localement : la réconcilier avant une première transaction.

### Détecter et planifier

```bash
cd /chemin/du/depot/installe
sudo python3 tools/omni-update.py fetch --source "$PWD" --ref main
TARGET=<SHA_COMPLET_RENVOYÉ_DANS_target>
sudo python3 tools/omni-update.py plan  --source "$PWD" --target "$TARGET"   # lecture seule, hors ligne
sudo python3 tools/omni-update.py stage --source "$PWD" --target "$TARGET"   # copie contrôlée dans releases/<SHA>
```

`fetch` renvoie aussi `installed_code_revision` et `descends_from_installed`. Si l'historique
distant a été réécrit (cible qui ne descend pas de la révision installée), le champ `next`
l'indique et `plan` refuse la cible.

Le plan distingue `code_files` (remplaçables), `preserved_or_manual_files` (configuration,
scripts numérotés : jamais recopiés), `conflicts` (fichier de code modifié localement : la
mise à jour est bloquée avant toute copie) et `migration_review_required` (scripts
d'installation de la pile, `stack-versions.env`, `deploye/apt/oms-siem-series`, Compose,
migrations, `requirements*.txt`, `pyproject.toml`, `python-locks/`, Dockerfile : revue
manuelle obligatoire, `apply-code` refusé).

### Robustesse du téléchargement (fetch)

- L'URL doit être en HTTPS, sans identifiant, mot de passe, jeton, paramètre ni fragment ;
  elle est refusée **avant** la création de tout état. Ne jamais placer de jeton dans l'URL
  ou la ligne de commande : utiliser le mécanisme d'authentification Git de l'hôte.
- La référence est contrôlée (pas de `..`, `.lock`, `@{`, option déguisée, espace).
- Git s'exécute en locale C, sans invite de mot de passe, avec un délai maximal de 300 s et
  un seuil de débit minimal ; un réseau bloqué ne fige plus l'outil.
- Les échecs sont classés sans recopier la sortie de Git (qui peut contenir une URL ou un
  chemin sensible) : `ref_not_found`, `authentication_required`, `repository_not_found`,
  `network_unavailable` (y compris délai dépassé), `unsafe_repository`, `host_key_unverified`
  (clé d'hôte SSH inconnue), `git_error`. Un refus de clé SSH (`Permission denied (publickey)`)
  est classé `authentication_required`.
  Exemple : `Update refused: Git operation failed: fetch (ref_not_found)`.
- Le verrou `update.lock` est libéré après un échec ; un second `fetch` simultané est refusé.
- Le candidat et la révision installée sont épinglés par des références
  (`refs/omni/candidates/<sha>`, `refs/omni/base/<sha>`) : un `git gc` du cache ne peut plus
  rendre la planification hors ligne impossible.

Ces garanties sont couvertes par le test de non-régression `tests/test_updater_fetch.py`
(dépôts Git temporaires, URL HTTPS redirigée localement par `url.<base>.insteadOf`, aucun
accès réseau) : téléchargement d'une branche et d'un tag, idempotence, référence inexistante,
dépôt inexistant, URL avec identifiants ou schéma refusé, référence malformée, dépôt
divergent, réseau indisponible (port de boucle locale fermé), délai dépassé, verrou
concurrent, classement des messages en locale française.

### Appliquer, contrôler, revenir en arrière

```bash
sudo python3 tools/omni-update.py apply-code --source "$PWD" --target "$TARGET"
sudo python3 tools/omni-update.py status     --source "$PWD"
sudo python3 tools/omni-update.py rollback   --source "$PWD" --transaction <IDENTIFIANT>
sudo python3 tools/omni-update.py recover    --source "$PWD" --transaction <IDENTIFIANT>
```

Avant chaque remplacement, les anciens octets et permissions sont sauvegardés dans
`backups/<transaction>/` ; les copies sont atomiques et un échec restaure les fichiers déjà
remplacés. La syntaxe Python, JSON et shell du candidat est contrôlée sans l'exécuter.
Seule la dernière transaction peut être annulée ; une modification locale postérieure bloque
le retour arrière. Après une coupure, si aucun processus ne tourne et que le journal est
marqué `applying`, retirer le verrou orphelin puis lancer `recover`.

Après une mise à jour de la console : publier explicitement les assets
(`sudo bash 71-soc-console.sh`, voir [CONSOLE-DEPLOIEMENT.md](CONSOLE-DEPLOIEMENT.md)) et
vérifier `/soc/` ; une mise à jour de code n'est pas une migration complète de la plateforme.

## 5. Couche paquets OS et sécurité

### Ce qui tourne en production

- `unattended-upgrades` (quotidien via `apt-daily-upgrade.timer`) applique les origines
  Debian et Debian-Security ; `52omni-siem.conf` (installé par
  `62-auto-security-updates.sh`, miroir `deploye/apt/52omni-siem.conf`) interdit à
  `unattended-upgrades` de redémarrer la machine (le redémarrage éventuel est fait par
  `oms-maj-siem`, voir § 2), exclut `graylog-server`, `opensearch`, `mongodb-org*` et
  `mongodb-mongosh`, et `needrestart` est en mode liste. Logstash n'est pas dans la liste
  d'exclusion mais ne provient pas d'une origine Debian : il n'est donc pas concerné.
- `oms-maj-siem` (`deploye/sbin/oms-maj-siem`, timer du dimanche 04:30) : contrôles
  (`/data` monté, OpenSearch vert, API Graylog, 3 Gio libres sur `/var`), sauvegarde
  (`omni-backup-config`, `mongodump`, archive `/etc`, `dpkg -l` dans
  `/data/backups/maj-*`, 4 dernières conservées), `dist-upgrade` de **tout** ce qui est en
  attente dans les séries autorisées par `/etc/apt/preferences.d/oms-siem-series`
  (les paquets gelés sont dégelés le temps de l'opération puis regelés), réparations
  connues (greffon GELF Logstash, magasins de confiance), redémarrage si
  `/var/run/reboot-required` existe (conditions détaillées au § 2),
  compte rendu par courriel et `/var/log/oms-maj-siem.log`. Mode `--simuler` sans
  modification.
- Gels (`apt-mark showhold`) au 21/11/2026 : `opensearch` et les paquets `mongodb-org*`
  (sauf `mongodb-org-shell`). `graylog-server` et `logstash` ne sont pas gelés : seul
  l'épinglage de série les borne.

### Détecter

```bash
python3 tools/omni-update-status.py --layer os
sudo /usr/local/sbin/oms-maj-siem --simuler      # inventaire de ce que le prochain passage installerait
```

La couche signale : paquets en attente (dont sécurité et pile), âge des listes apt
(`action` au-delà de 7 jours : la veille est aveugle), gels, redémarrage requis,
configuration effective d'`unattended-upgrades`, date de son dernier passage et dernier
résultat d'`oms-maj-siem` avec son prochain passage, ainsi que la date du **dernier passage
réel** (hors simulation) : au-delà de 8 jours, un passage hebdomadaire a été manqué.
`oms-maj-siem.timer` est en `Persistent=false` : si la machine est arrêtée ou redémarre
pendant la fenêtre du dimanche, le passage est perdu sans rattrapage ni alerte ; ce contrôle
le rend visible.

**Règle retenue le 22/11/2026 : `Persistent=false` est conservé.** Avec le redémarrage
automatique maintenu, c'est la règle la plus sûre :

- `Persistent=true` lancerait le passage manqué dès le démarrage suivant, donc à une heure
  imprévue, souvent en journée : mise à jour de la pile puis redémarrage 60 s après la fin si
  `/var/run/reboot-required` existe. Le cas le plus probable de passage manqué est un arrêt
  non planifié (coupure, comme le 26/06/2026) : le rattrapage enchaînerait alors une mise à
  jour et un second redémarrage sur une machine qui vient juste de reprendre ;
- le coût d'un passage manqué est borné : les correctifs de sécurité Debian restent appliqués
  chaque jour par `unattended-upgrades` (`apt-daily-upgrade.timer`, indépendant de ce
  timer) ; seuls la pile épinglée, les autres paquets et le redémarrage attendent une
  semaine ;
- le passage manqué est visible : `omni-update-status.py --layer os` signale un dernier
  passage réel de plus de 8 jours.

Pour rattraper sans attendre, lancer `sudo systemctl start oms-maj-siem.service` à un moment
choisi (mêmes contrôles ; redémarrage possible). Un rattrapage automatique dans une fenêtre
de nuit (second créneau conditionné à l'absence de passage dans la semaine) demanderait une
modification d'`oms-maj-siem` ; il n'est pas implémenté.
Constat du 21/11/2026 : le passage du 15/11 a bien eu lieu (démarrage 04:38:41, journal
`/var/log/oms-maj-siem.log` et `journalctl -u oms-maj-siem.service`) ; le redémarrage du
timer à 04:43 correspond au redémarrage de la machine qu'il a lui-même déclenché. Attention : `oms-maj-siem --simuler`
lance `apt-get update` (rafraîchissement des listes), contrairement à
`omni-update-status.py`.

### Exécuter hors fenêtre automatique, vérifier, revenir en arrière

Hors de la fenêtre du dimanche, préférer `sudo systemctl start oms-maj-siem.service` (mêmes
contrôles et sauvegardes) à un `apt-get` manuel, en sachant qu'il redémarre la machine si
`/var/run/reboot-required` existe à la fin : le lancer seulement quand un redémarrage est acceptable. Vérifier ensuite
`tail -50 /var/log/oms-maj-siem.log`, `systemctl --failed` et
`python3 tools/omni-update-status.py`. Retour arrière d'un paquet Debian :
`apt-get install --allow-downgrades paquet=<version précédente>` si la version est encore
publiée (liste de référence : `/data/backups/maj-*/dpkg-l.txt`) ; `oms-maj-siem` vide le
cache apt (`apt-get clean`) après usage, les anciens `.deb` ne sont donc pas conservés.

Dernier passage constaté : 15/11/2026, un paquet, redémarrage, résultat « A VERIFIER »
(Logstash redémarré en boucle, `NRestarts=4`) : à examiner avant le prochain passage.

## 6. Couche pile Graylog / OpenSearch / MongoDB : runbook

### Référence et production

`stack-versions.env` fixe les versions des **installations neuves** ; la production est
mesurée par `python3 tools/omni-update-status.py --layer stack`.

| Composant | Référence (`stack-versions.env`) | Production (21/11/2026) | Gel | Série épinglée | Disponible dans la série |
|---|---|---|---|---|---|
| graylog-server | 7.2.2-1 | 7.2.2-1 | non | 7.2.* | 7.2.2-2 (révision de paquet) |
| opensearch | 2.19.7 | 2.19.7 (en service : 2.19.7) | oui | 2.19.* | aucune |
| mongodb-org-server | 8.0.38 | 8.0.38 | oui | 8.0.* | aucune |
| logstash | non référencé | 1:8.19.25-1 | non | 1:8.19.* | aucune |

Écart production / référence : nul pour les trois composants de base. Le miroir
`deploye/apt/oms-siem-series` était resté sur la série Graylog 7.1 alors que la production
épingle 7.2 depuis la montée du 14/11/2026 : il a été resynchronisé. Le dépôt Graylog
publie aussi des pré-versions (`alpha`, `beta`, `rc`) dans la série 7.2 : l'outil les refuse
par défaut.

Point d'attention : `graylog-server` n'étant pas gelé, le passage d'`oms-maj-siem` du
dimanche installera automatiquement 7.2.2-2. Pour réaliser cette montée manuellement en
fenêtre, la faire avant ce passage ou suspendre le timer (décision de l'administrateur).

### Outil : omni-stack-upgrade.py

Généralise `tools/upgrade-graylog-715.sh` (conservé pour l'historique). Composants :
`graylog` (graylog-server), `opensearch`, `mongodb` (tous les paquets `mongodb-org*`
installés, à la même version), `logstash`. Le plan et l'exécution partagent le même code :
le plan liste exactement les commandes qui seraient lancées.

Contrôles de compatibilité (`omni_update/compat.json`) :

- montée uniquement (une version inférieure ou égale est refusée : utiliser `rollback`) ;
- version finale (pré-versions refusées sauf `--allow-prerelease`, réservé aux tests) ;
- même série : accepté ; changement de série : refusé sauf `--allow-series-change` pour
  Graylog, OpenSearch et Logstash, et toujours refusé pour MongoDB (une série à la fois,
  `featureCompatibilityVersion` à aligner : procédure manuelle) ; changement de version
  majeure : refusé ;
- version présente dans les dépôts apt et autorisée par `/etc/apt/preferences.d/oms-siem-series` ;
- combinaison résultante comparée aux combinaisons **réellement validées en production**
  (seule déclarée : Graylog 7.2.2-1, OpenSearch 2.19.7, MongoDB 8.0.38, Logstash
  1:8.19.25-1) ; une combinaison nouvelle produit un avertissement non bloquant invitant à
  lire les notes de version de l'éditeur.

Pré-requis bloquants : droits root (exécution), espace libre (`/` 2 Gio, `/var` 3 Gio,
`BACKUP_DIR` 5 Gio), OpenSearch vert, API Graylog `lbstatus` 200, sauvegarde de configuration
vérifiée de moins de 26 h avec dernier passage `omni-backup-config` en succès,
`dpkg --audit` vide, `oms-maj-siem` inactif, paquet de la version installée disponible
(cache apt ou dépôt) pour le retour arrière (sinon `--accept-no-package-rollback`).
Avertissement : listes apt de plus de 2 jours.

### Runbook de montée de version (exemple : Graylog 7.2.2-1 vers 7.2.2-2)

1. **Préparer (J-1)** : lire les notes de version ; vérifier l'état global
   `python3 tools/omni-update-status.py` ; prévenir les analystes de l'interruption
   (quelques minutes pour un correctif Graylog ; des messages UDP émis pendant l'arrêt
   peuvent être perdus).
2. **Plan (lecture seule)** :
   ```bash
   cd /opt/omni-siem/repository
   python3 tools/omni-stack-upgrade.py plan --component graylog --to 7.2.2-2
   ```
   Le statut doit être `ready` ; lire les étapes et le retour arrière affichés.
3. **Exécution**, dans `tmux` ou `screen` (une coupure SSH ne doit pas interrompre apt) :
   ```bash
   tmux new -s maj-pile
   sudo python3 tools/omni-stack-upgrade.py apply --component graylog --to 7.2.2-2 \
        --execute --confirm graylog=7.2.2-2
   ```
   Le mot de passe administrateur Graylog est lu dans `00-vars.env` du dépôt de l'outil pour
   les vérifications ; un jeton peut être fourni à la place via `GRAYLOG_API_TOKEN` (jamais
   affiché). Déroulé : répertoire `BACKUP_DIR/upgrade-<composant>-<horodatage>` (0700),
   `mongodump` compressé (l'URI MongoDB de `server.conf` est passée par un fichier temporaire
   0600, jamais en argument), test `gzip -t`, archive des fichiers de configuration du
   composant et de `/etc/apt`, `dpkg -l`, copie ou téléchargement du `.deb` de la version
   installée, relevé des inputs RUNNING et du volume ingéré sur 5 minutes, arrêt ordonné des
   services, dégel, `apt-get install` de la version exacte avec `--force-confold`, regel,
   démarrage ordonné.
4. **Vérification automatique** : version installée, OpenSearch vert (30 min max), API
   Graylog (10 min max), Graylog `lifecycle=running` et `is_processing=true`, nombre d'inputs
   RUNNING au moins égal à celui d'avant (titres des inputs arrêtés affichés), documents
   ingérés sur les 5 dernières minutes, présence de nouveaux fichiers `.dpkg-dist` (la
   configuration en place est conservée), greffon `logstash-output-gelf` pour Logstash.
   Statut final : `success`, `verification_failed`, `failed` ou `blocked`, consigné dans
   `/var/lib/omni-siem-stack-upgrade/<id>.json` (0600).
5. **Contrôle manuel** : interface Graylog, recherches récentes par source, alertes,
   `python3 tools/omni-update-status.py` (la dette signalée par `omni-version-watch`
   disparaît au passage suivant).

Ordre des services par composant : Graylog (arrêt/démarrage de `graylog-server`) ;
OpenSearch (arrêt `graylog-server` puis `opensearch`, démarrage inverse) ; MongoDB (arrêt
`graylog-server` puis `mongod`, démarrage inverse) ; Logstash (`logstash`).

### Retour arrière

L'outil ne rétrograde jamais automatiquement : après un statut `failed` ou
`verification_failed`, l'administrateur décide.

```bash
# Plan du retour arrière du paquet (lecture seule), puis exécution :
sudo python3 tools/omni-stack-upgrade.py rollback --journal /var/lib/omni-siem-stack-upgrade/<id>.json
sudo python3 tools/omni-stack-upgrade.py rollback --journal /var/lib/omni-siem-stack-upgrade/<id>.json \
     --execute --confirm rollback-graylog
```

Le retour arrière réinstalle les `.deb` sauvegardés (`apt-get install --allow-downgrades`),
regèle et redémarre. **La base MongoDB n'est jamais restaurée automatiquement** : une
version plus récente de Graylog peut avoir migré des collections ; si la configuration
Graylog est altérée et après validation du RSSI :

```bash
sudo systemctl stop graylog-server
# fichier 0600 contenant la ligne : uri: "<valeur de mongodb_uri dans /etc/graylog/server/server.conf>"
sudo mongorestore --config=/root/mongo-uri.yaml --gzip --drop \
     --archive=<BACKUP_DIR>/upgrade-<id>/mongo.archive.gz
sudo shred -u /root/mongo-uri.yaml
sudo systemctl start graylog-server
```

En dernier recours, la restauration complète depuis l'archive chiffrée suit
[RESTORE.md](../RESTORE.md) et le [PRA](PRA-RECONSTRUCTION-SIEM.md).

### Changement de série

1. Lire les notes de mise à jour de la série cible et la matrice de compatibilité de
   l'éditeur (versions OpenSearch et MongoDB supportées par la série Graylog visée).
2. Recetter sur une VM de test (`tools/test-ubuntu-vm.sh`, `tools/test-integration-vm.py`).
3. Après validation du RSSI : modifier `/etc/apt/preferences.d/oms-siem-series` **et** son
   miroir `deploye/apt/oms-siem-series`, `apt-get update`, puis
   `omni-stack-upgrade.py plan ... --allow-series-change`.
4. Après succès : ajouter la combinaison constatée à `validated_combinations` dans
   `omni_update/compat.json` et mettre à jour `stack-versions.env`.

MongoDB : l'outil refuse tout changement de série ; suivre la documentation MongoDB (une
série à la fois, `featureCompatibilityVersion`) en procédure manuelle.

## 7. Couche dépendances Python des venvs

`python-locks/venvs.json` inventorie les venvs : `mobile` (backend console), `oms-xdr`,
`oms-graph`, `oms-ml`, et `oms-seal-sla` (facultatif). Pour chacun : le fichier de
dépendances directes s'il existe, le fichier de verrouillage `python-locks/<id>.txt`
(versions exactes relevées le 21/11/2026 dans les venvs de production) et les chemins
candidats du venv (le premier existant est audité). Les chemins historiques
proviennent du relevé du 21/11/2026 ; après une migration, vérifier que le champ
`venv` retourné désigne bien l'environnement à examiner. L'audit ne déduit pas
le processus actif à partir de systemd.
La console utilise `mobile/requirements.txt`, partagé avec le déploiement.
Playwright et ses dépendances de tests `pyee` et `greenlet`, présents dans le
relevé historique, sont exclus de l'audit du runtime console.

```bash
python3 tools/omni-pydeps.py audit                 # écarts venv / verrouillage
python3 tools/omni-pydeps.py audit --json --venv oms-ml
python3 tools/omni-pydeps.py lock --venv oms-xdr   # relevé des versions (sortie standard)
python3 tools/omni-pydeps.py lock --venv oms-xdr --write   # écrit python-locks/oms-xdr.txt dans le dépôt
python3 tools/omni-pydeps.py audit --vuln          # pip-audit s'il est installé (réseau requis)
```

L'audit (lecture seule, `pip list` sans index) signale : paquets absents, en trop, de version
différente, dépendances directes non verrouillées et dépendances à bornes ouvertes
(`requests>=2.31`, etc.). Au 21/11/2026 les cinq venvs sont conformes à leur verrouillage ;
les venvs de production contiennent aussi des outils de test (`pytest`, `ruff`) et, pour la
console, `playwright` : ils sont enregistrés tels quels.

Mettre à jour un venv : sur une copie de test, installer les nouvelles versions, lancer
`bash run-tests.sh`, régénérer le verrouillage (`lock --write`), committer ; en production,
sauvegarder le venv (`cp -a <venv> <venv>.avant-AAAAMMJJ`), puis
`<venv>/bin/pip install --no-deps -r python-locks/<id>.txt`, redémarrer le service concerné
et vérifier. Retour arrière : restaurer la copie du venv. `pip-audit` n'est pas installé sur
le serveur : le scan de vulnérabilités n'est donc pas réalisé aujourd'hui.

Toute modification de `python-locks/` ou d'un `requirements*.txt` impose une revue manuelle
dans `omni-update.py` (`migration_review_required`).

## 8. Couche contenus de détection et intégrations

- **Modules d'intégration** (`integrations/catalog.json`) : chaque manifeste porte une
  révision entière. `omni-update-status.py --layer content` affiche les révisions du
  catalogue ; avec `--graylog` et un jeton `GRAYLOG_API_TOKEN`, il lit en GET la révision
  du Content Pack installée et signale les modules en retard. Mise à jour :
  `omni-integrations.py plan` puis `install --apply` (gestionnaire SSH, menu intégrations) ;
  retour arrière : `uninstall --apply` avec l'identifiant d'installation. Une mise à jour
  du dépôt n'installe jamais une nouvelle révision dans Graylog.
- **Code de détection déployé** (robots `omni-*`, unités systemd et autres fichiers listés
  dans `manifeste-deploye.txt`) : la couche compare les empreintes SHA-256 entre la
  production et `deploye/`. Un écart signifie soit une modification en production à
  rapatrier (`./synchro-manifeste.sh`, puis `--copier`), soit une version du dépôt pas encore
  déployée. Au 21/11/2026 : 246 identiques, 1 différent (le miroir de l'épinglage apt,
  corrigé dans cette branche).
- **Flux de renseignement sur les menaces** : `omni-ti-feeds` (quotidien) écrit
  `/etc/graylog/lookup/ti-c2-ip.csv` (Feodo Tracker) et `ti-mal-domain.csv` (URLhaus). Quand
  une source ne renvoie rien, le robot conserve l'ancien fichier : une source morte se voit
  donc à l'âge du fichier, pas à son contenu. La couche signale tout fichier de plus de
  3 jours. Constat du 21/11/2026 : `ti-mal-domain.csv` est figé depuis le 21/10/2026
  (553 domaines) : les exports publics d'URLhaus (`downloads/text_recent`, comme `csv_recent`,
  `hostfile` et `text_online`) répondent HTTP 410 et l'API URLhaus répond 401 sans clé
  (vérifié le 22/11/2026). `omni-ti-feeds` interroge désormais l'API authentifiée
  (`urlhaus-api.abuse.ch/v1/urls/recent/`, 1 000 URL récentes) avec la clé abuse.ch gratuite
  `ABUSECH_AUTH_KEY` (ou `THREATFOX_AUTH_KEY`, la même clé) de `/etc/default/omni-ti-feeds`,
  vide en production au 22/11/2026. Sans clé, le robot l'écrit dans son journal et garde
  l'ancien fichier. Le format de réponse de l'API est repris de sa documentation et testé
  hors ligne ; il n'a pas été vérifié avec une vraie clé.
- **Définitions Graylog** (règles de pipeline, alertes, tableaux de bord) : provisionnées par
  les scripts numérotés, idempotents, lancés explicitement ; elles sont sauvegardées
  chaque nuit dans l'archive de configuration. Aucune comparaison automatique dépôt / Graylog
  n'est fournie par cet outil (voir `29-drift-check.sh`, contrôle 6, pour les règles).

## 9. Gestionnaire SSH

`sudo python3 tools/omni-manager.py`, menu « Préparer et appliquer une mise à jour » :

| Entrée | Action | Écriture |
|---|---|---|
| 1 à 9 | cycle `omni-update.py` (fetch, SHA, plan, stage, apply-code, publication console, état, rollback, recover) | apply, rollback, recover, publication : confirmation `OUI` |
| 10 | État de toutes les couches (`omni-update-status.py`) | non |
| 11 | Plan de montée de version de la pile (`omni-stack-upgrade.py plan`) | non |
| 12 | Audit des dépendances Python (`omni-pydeps.py audit`) | non |

Les entrées 10 à 12 construisent une ligne de commande fermée (composant parmi une liste,
version validée) et sont journalisées comme les autres opérations. L'exécution d'une montée
de version de la pile **n'est pas proposée dans le menu** : une déconnexion SSH tuerait apt
en pleine transaction. Après un plan valide, le menu affiche la commande exacte à lancer
dans `tmux`.

## 10. Sauvegardes, restauration et preuve de résilience

État constaté le 21/11/2026 :

- `omni-backup-config` (`30-backup-config.sh`, 03:15) : `mongodump`, configurations,
  en-tête LUKS (en fait absent de l'archive jusqu'à la correction du 22/11/2026, voir
  `docs/exploitation/RESTAURATION-COMPLETE.md` §7), archive chiffrée vérifiée (déchiffrement,
  lecture, présence des collections critiques) puis copiée sur le partage ; dernier passage
  en succès le 21/11/2026 à 03:21.
- `oms-snap-siem` (01:30) : snapshot OpenSearch sélectif ; `oms-snap-siem-test` (mercredi
  11:00) restaure un index dans un index temporaire et compare le nombre de documents
  (dernier test OK le 18/11/2026).
- Sauvegarde native `08-backup.sh` (`/home/siem-backup/mongo`) : dernière archive le
  14/08/2026, aucune planification active ; la couche `health` le signale.
- Avant mise à jour : `oms-maj-siem` (`/data/backups/maj-*`) et `omni-stack-upgrade.py`
  (`BACKUP_DIR/upgrade-*`).

Preuve de résilience : les objectifs RTO (4 h) et RPO configuration (24 h) sont fixés dans le
[PRA](PRA-RECONSTRUCTION-SIEM.md). Le test de restaurabilité de l'archive (22/06/2026) et le
test hebdomadaire de restauration de snapshot existent ; **une restauration complète
chronométrée sur VM jetable n'a pas encore été réalisée** : c'est la prochaine preuve à
produire (mesure du RTO réel, consignée au journal du PRA).

## 11. Garder GitHub et les fichiers réellement servis cohérents

Le dépôt est la référence du code partagé ; secrets, certificats, adresses et données de
site restent locaux. Il n'existe pas de synchronisation automatique bidirectionnelle :
comparer les adaptations du serveur, intégrer les correctifs réutilisables au dépôt, puis
déployer la révision testée.

Pour la console, comparer les sources `mobile/soc/`, les fichiers publiés sous
`/var/www/siem-soc/` et le backend réellement lancé :

```bash
git status --short
git log -1 --oneline
systemctl show omni-mobile-api -p ExecStart --no-pager
sha256sum mobile/omni-mobile-api.py
sha256sum mobile/soc/index.html /var/www/siem-soc/index.html
sha256sum mobile/soc/app.js /var/www/siem-soc/app.js
```

Avant publication, conserver une sauvegarde privée du backend, des assets publics et de
`/etc/default/omni-mobile` ; après publication, vérifier les empreintes, la connexion, la
recherche, les tableaux de bord et le rechargement de la PWA.

## 12. Limites connues

- `omni-update-status.py` ne lit pas la version de Graylog en service (l'API `/system`
  exige une authentification) ; la version du paquet fait foi.
- Les contrôles de compatibilité de la pile ne reproduisent pas la matrice de l'éditeur :
  hors combinaisons déjà constatées en production, la lecture des notes de version reste
  obligatoire.
- `omni-stack-upgrade.py` traite un composant par exécution ; un changement de série
  coordonné (par exemple OpenSearch puis Graylog) s'enchaîne en plusieurs exécutions, dans
  l'ordre indiqué par les notes de version.
- `omni-version-watch` lit encore `00-vars.env` dans `/root/omnitech-siem-setup`
  (chemin codé en dur) ; son alignement sur les chemins canoniques relève du chantier
  déploiement.
- Le scan de vulnérabilités Python suppose l'installation de `pip-audit` et un accès réseau.

## 13. Mise à jour depuis la console SOC (en un clic)

Automatise, depuis **Administration > Mises à jour** de la console `/soc/`, la procédure manuelle
suivie en production : arbre propre, `git fetch`, avance rapide possible, aucune unité en
démarrage, sauvegarde de la révision, `git merge --ff-only`, `omni-deploy.py deploy robots apt
systemd`, publication de la console si elle a changé, redémarrage des seuls services dont le code
a changé, contrôle de santé. Elle réutilise `omni-update.py` (appels Git, classement des échecs,
règles de revue manuelle), `omni_deploy` (plan, transactions, retour arrière, santé) et
`omni-integrations.py` (modules). Code : `omni_update/console.py`, `tools/omni-console-update.py`.

### Architecture et privilèges

| Élément | Compte | Rôle |
|---|---|---|
| `omni-console-update-check.timer` (quotidien 06:40, délai aléatoire 15 min, rattrapage au démarrage) et `omni-console-update-check.path` (bouton « Rechercher maintenant ») | root, `ProtectSystem=full`, `ProtectHome=read-only`, `NoNewPrivileges` | `omni-console-update.py check` : `git fetch` du remote attendu, plan, vérifications, tests ; publie `status.json` |
| `omni-mobile-api` (backend, confiné) | inchangé | lit `status.json` et `run.json`, dépose le déclencheur `check-request`, enregistre la demande confirmée et la transmet à l'exécuteur ; ne lance aucune commande |
| `omni-soc-admin-exec` (exécuteur privilégié existant) | root | revalide la demande (action, paramètres identiques, confirmation) puis la dépose dans la file root `/var/lib/omni-console-update/queue` (0700) |
| `omni-console-update.path` + `.service` | root, sans confinement (déploie dans `/usr/local/sbin`, `/etc/systemd/system`, `/var/www`) | `omni-console-update.py run-queue` : revalide encore, recalcule le plan, applique ou annule ; publie `run.json` à chaque étape |

Fichiers : état privé `/var/lib/omni-console-update` (verrou `update.lock`, `run.json`,
`runs/<id>.json`, `tests/<sha>.json`, `queue/`) ; publication pour la console
`/var/lib/omni-mobile/admin/update/` (`status.json`, `run.json`, `last_apply.json` : dernière mise à jour effective, seule annulable ; droits 640). Le backend ne fait
jamais confiance à son propre répertoire pour agir : le service recalcule tout à partir du dépôt.
Même un backend compromis ne peut faire appliquer qu'une révision présente sur `main` du remote
attendu et descendante de la révision installée, avec des options en liste fermée.

### Détection (lecture seule pour l'arbre de travail)

`git fetch --no-tags -- <UPDATE_EXPECTED_REMOTE> +refs/heads/main:refs/remotes/origin/main`, avec
`GIT_TERMINAL_PROMPT=0`, locale C, délai maximal, sans recopier la sortie de Git. Le dépôt
GitHub étant public, la lecture HTTPS anonyme suffit : aucune authentification n'est à
configurer. L'URL du remote `origin` doit être celle attendue (`UPDATE_EXPECTED_REMOTE`, par
défaut `https://github.com/jmorin-info/omnitech-siem-setup.git`) : un remote modifié localement
ne peut pas servir de source (`remote_refuse`). Une règle `url.*.insteadOf` portant des
identifiants est refusée. Les échecs sont classés (`authentication_required`,
`network_unavailable`, `repository_not_found`, `ref_not_found`, `host_key_unverified`...) et
affichés tels quels dans la console.

`status.json` contient : révision installée et disponible, commits (200 au plus), extrait des
lignes ajoutées au `CHANGELOG.md`, fichiers modifiés classés (code, robots, unités, console,
scripts numérotés, revue manuelle, non déployés automatiquement, intégrations, documentation et
tests), services à redémarrer, résultat des vérifications et des tests, options disponibles.

### Vérifications (affichées avant toute action, revalidées juste avant l'application)

Bloquantes : branche `main` extraite ; remote attendu sans identifiant ; aucune modification de
fichier suivi ; aucune mise à jour en cours (verrou) ni interrompue ; avance rapide possible ;
candidat présent sur `main` du remote ; aucun fichier non suivi écrasé ; manifeste valide ; aucun
changement exigeant une revue manuelle (mêmes règles que `omni-update.py` :
scripts de pile, `stack-versions.env`, `deploye/apt/`, Compose, migrations, `requirements*.txt`,
`pyproject.toml`, verrous, `python-locks/`, Dockerfile ; la mise à jour en un clic est alors
refusée et la procédure manuelle des sections 4, 6 et 7 s'applique) ; plan omni-deploy sans
blocage (une modification des préférences APT est bloquante) ; suite `run-tests.sh` verte sur le
candidat, exécutée dans une copie temporaire (`git archive`, jamais dans le dépôt actif) sous le
compte `UPDATE_TEST_USER` (`nobody` par défaut, via `setpriv`), résultat conservé 24 h par
révision ; aucune unité `omni-*`/`oms-*`/`siem-*` en `activating` (hors unités de la mise à jour
elle-même) ; OpenSearch vert ; API Graylog `lbstatus` 200 ; sauvegarde de configuration vérifiée
de moins de 26 h (`omni-backup-config` en succès) ; 2 Gio libres sur `/` et 1 Gio sur `/var`.

Avertissements (non bloquants) : unités en échec, fichiers non suivis, scripts numérotés modifiés
(**jamais lancés automatiquement** : à examiner et lancer à la main si nécessaire), composants
`etc`, `opt`, `nginx`, `logstash` modifiés (non déployés par la mise à jour en un clic : utiliser
`omni-deploy.py`), `00-vars.env.example` modifié (comparer avec `00-vars.env`, jamais modifié),
écarts préexistants entre la production et le dépôt (les fichiers seront remplacés, avec
sauvegarde dans la transaction), services à redémarrer hors liste blanche.

### Options

- **Publier la console** : proposé si `mobile/soc/` ou `mobile/www/` change ; composant `console`
  d'omni-deploy (transactionnel), les routes nginx ne sont pas modifiées.
- **Redémarrer les services concernés** : services longs `omni-*`/`oms-*` versionnés dont le
  code exécuté vit dans un répertoire modifié du dépôt (par exemple `omni-mobile-api` si `mobile/`
  change), restreints à `UPDATE_RESTART_ALLOW`. Les unités dont un fichier déployé change sont
  redémarrées par omni-deploy (si actives), même option décochée.
- **Modules d'intégration** (catalogue `integrations/` du candidat, par exemple un module
  WatchGuard) : état installé ou non lu par GET dans Graylog ; un module n'est proposé que s'il
  n'est pas installé et que `UPDATE_GRAYLOG_TOKEN_FILE`, `UPDATE_INTEGRATION_API` et
  `UPDATE_INTEGRATION_BIND` sont renseignés. **Un module non coché n'est jamais installé.**
  L'installation (`omni-integrations.py install --apply`, port par défaut du manifeste) a lieu
  après la mise à jour du code validée ; comme documenté dans
  [INTEGRATIONS-MODULAIRES.md](INTEGRATIONS-MODULAIRES.md), elle n'est pas transactionnelle : un
  échec est signalé (« terminée avec avertissements ») sans annuler la mise à jour du code ni
  supprimer d'entité. Un module déjà installé dans une autre révision exige une migration
  préparée : il n'est pas proposé.

### Exécution et retour arrière automatique

Après confirmation (voir la console ci-dessous), le service : prend le verrou, refait le `fetch`,
recalcule plan, vérifications et tests (refus sans modification si un blocage apparaît),
sauvegarde la révision (`refs/omni-console-update/avant-<id>`), l'état de santé et la liste des
unités en échec, fait `git merge --ff-only <révision approuvée>` (jamais au-delà, même si `main` a
avancé), applique `omni-deploy` (robots, unités, préférences APT), publie la console, redémarre
la liste blanche puis vérifie que chaque service reste actif, et lance le contrôle de santé
(`omni_deploy.health`, comme `omni-healthcheck.py`). Toute étape en échec, ou une régression du
contrôle final (contrôle critique passé en échec, nouvelle unité en échec), déclenche le retour
arrière automatique complet : transactions omni-deploy annulées en ordre inverse, `git reset
--keep` vers la révision sauvegardée, services redémarrés sur l'ancien code, contrôle de santé.
Statuts : `terminee`, `terminee_avec_avertissements`, `refusee` (rien modifié), `annulee`,
`annulation_incomplete` (à traiter à la main : voir le détail des étapes), `restauree`.

Délais : service 90 min (`TimeoutStartSec`), tests 30 min (`UPDATE_TEST_TIMEOUT`), Git 300 s,
redémarrage 180 s par service. Jamais : modification de `00-vars.env`, de `/etc/default/*` ou d'un
secret, lancement d'un script numéroté, `git push`, installation d'un module non coché.

Retour arrière manuel : bouton **Retour arrière de cette mise à jour** sur la dernière mise à
jour terminée ou interrompue (confirmation par la révision courte à restaurer). Refusé si l'arbre
a été modifié ou si `HEAD` n'est plus la révision installée par la mise à jour. Les modules
installés ne sont pas désinstallés. Une coupure pendant l'opération laisse `run.json` « en
cours » sans verrou : la console l'affiche « interrompue », bloque toute nouvelle mise à jour et
propose le retour arrière ; une transaction omni-deploy en cours au moment de la coupure n'est
pas connue du journal : la contrôler avec `python3 tools/omni-deploy.py history`.

### Dans la console : décision de l'administrateur (23/11/2026)

La mise à jour et son retour arrière sont des actions d'impact **élevé** en **libre-service** :
**un seul administrateur** les lance, sans approbation d'un second administrateur. Ce sont les
seules exceptions : toutes les autres actions à fort impact restent soumises à la double
validation et `SOC_ADMIN_SELF_APPROVE` n'est pas modifié. Déroulé : lecture du plan et des
vérifications, **Préparer la mise à jour** (simulation), motif obligatoire, case « J'ai lu le
plan et les vérifications », saisie des 12 premiers caractères de la révision cible, **Lancer**.
Le backend enregistre la demande (`self_service`, demandeur = confirmant), l'exécuteur n'accepte
ce libre-service que pour `update_apply` et `update_rollback` et revérifie la confirmation.
Restent actifs : rôle administrateur, réseau interne, `Origin`, jeton anti-CSRF, débit,
`SOC_ADMIN_DRY_RUN` (simulation sans transmission), audit chaîné, verrou, retour arrière
automatique. Le suivi en direct interroge `GET /m/api/admin/update` toutes les 4 s (le backend
peut être brièvement indisponible s'il est lui-même redémarré).

### Installer sur un environnement (administrateur, et collègue sur le sien)

Pré-requis : dépôt canonique cloné (`/opt/omni-siem/repository` ou `OMNI_SIEM_HOME`), console et
exécuteur `omni-soc-admin-exec` déjà installés ([CONSOLE-DEPLOIEMENT.md](CONSOLE-DEPLOIEMENT.md)),
compte de l'administrateur listé dans `SOC_ADMINS` de `/etc/default/omni-mobile` (ajouter le compte
Graylog du collègue sur son environnement, ou sur celui-ci s'il doit l'utiliser), sauvegarde
`omni-backup-config` active, accès HTTPS sortant vers github.com.

```bash
cd /opt/omni-siem/repository
git remote get-url origin          # doit afficher l'URL attendue (UPDATE_EXPECTED_REMOTE)
# Interpréteur de la suite de tests (aucun venv de production ne contient pytest au 23/11/2026)
python3 -m venv /opt/omni-siem/test-venv
/opt/omni-siem/test-venv/bin/pip install -r /opt/omni-siem/repository/requirements-dev.txt
# Configuration (modèle commenté)
install -m 640 mobile/systemd/omni-console-update.default.example /etc/default/omni-console-update
grep -q '^SOC_UPDATE_QUEUE=' /etc/default/omni-soc-admin-exec || \
  echo 'SOC_UPDATE_QUEUE=/var/lib/omni-console-update/queue' >> /etc/default/omni-soc-admin-exec
# Unités (plan puis application, transactionnel)
python3 tools/omni-deploy.py deploy systemd --filtre '*/omni-console-update*'
python3 tools/omni-deploy.py deploy systemd --filtre '*/omni-console-update*' --apply
systemctl enable --now omni-console-update-check.timer omni-console-update-check.path omni-console-update.path
systemctl start omni-console-update-check.service     # première recherche (quelques minutes)
python3 tools/omni-console-update.py status
```

Puis, avec le nouvel exécuteur et le nouveau backend en place (fichiers `mobile/`), ouvrir
**Administration > Mises à jour**. Désactivation : `systemctl disable --now` des trois unités.

### Dépôt redevenu privé (option, non requise aujourd'hui)

Utiliser une **clé de déploiement GitHub en lecture seule** dédiée au serveur, jamais un jeton :
`ssh-keygen -t ed25519 -N '' -f /root/.ssh/omni-siem-deploy -C "$(hostname -f) lecture seule"`,
déclarer la clé publique dans GitHub (dépôt > Settings > Deploy keys, sans « Allow write
access »), puis dans `/root/.ssh/config` un bloc `Host github.com` avec
`IdentityFile /root/.ssh/omni-siem-deploy` et `IdentitiesOnly yes`, ajouter la clé d'hôte de
GitHub à `known_hosts` après vérification de son empreinte publiée, et passer remote et
`UPDATE_EXPECTED_REMOTE` à `git@github.com:jmorin-info/omnitech-siem-setup.git` (adapter alors
`validate_remote` : seule l'URL HTTPS est acceptée aujourd'hui). Une clé par serveur, révocable
séparément. Ne jamais placer de jeton dans une URL, un fichier du dépôt ou un journal.

### Ligne de commande et limites

```bash
python3 tools/omni-console-update.py status          # lecture seule
python3 tools/omni-console-update.py plan [--tests]  # plan sur origin/main déjà récupéré, sans fetch
sudo python3 tools/omni-console-update.py check      # ce que fait le timer
```

- Ne traite que le code du dépôt et ses composants robots, unités, console et modules : pas la
  pile (section 6), pas les paquets OS, pas les venvs (section 7), pas les composants `etc`,
  `opt`, `nginx`, `logstash`, pas les scripts numérotés.
- Les services redémarrés sont déterminés d'après les chemins du dépôt cités par les unités :
  un service qui charge du code par un autre chemin n'est pas détecté.
- La comparaison de santé ignore les contrôles déjà en échec avant la mise à jour.
- L'installation d'un module n'est pas annulée automatiquement.
- Pas de notification par courriel ni d'alerte Graylog de fin de mise à jour : le compte rendu est
  dans la console, `run.json` et l'audit de l'exécuteur.

