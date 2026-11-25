# Installer et mettre à jour depuis une release

La préversion `0.1.0-rc.1` distribue **tous les fichiers suivis du dépôt**, à la
révision indiquée dans `release.json` : scripts, bases du serveur, console, modules,
collecteurs, moteurs d'analyse, tests et documentation. Elle ne contient ni secrets
de site ni données MongoDB/OpenSearch. Les dépendances externes sont téléchargées
pendant l'installation ; ce n'est pas une installation hors ligne.

## Ce qui est installé, ce qui demande une configuration

| Ensemble | Comportement |
|---|---|
| Paquet `omni-siem` | Livre le projet dans `/usr/share/omni-siem/source` et la commande `omni-siem` ; aucun service n'est créé ou redémarré à cette étape |
| Socle serveur | `omni-siem install --apply` installe MongoDB, OpenSearch, Graylog, nginx/TLS, pare-feu, collecte et détections de base, dashboards, console `/soc/`, sauvegarde et vérification finale |
| WatchGuard, UniFi, Palo Alto | Modules et dashboards disponibles ; installation explicite, réseau et émission des équipements à configurer. Voir [le guide des intégrations](INTEGRATIONS-MODULAIRES.md) |
| Collecteur Linux | Plan et installation réversible d'un transfert `auth/authpriv` par rsyslog sur APT/DNF. L'entrée Linux du serveur doit exister ; auditd n'est pas activé par ce parcours |
| Windows, M365, SEAL, Fortinet, XDR, ML, graphe, SOAR, scanners et autres extensions | Tous les fichiers sont livrés. Dépendances, comptes, licences, paramètres et recette propres au site ; accès par le catalogue et le gestionnaire SSH |
| Maintenance, purge, restauration, réponse active | Présentes dans le catalogue ; jamais lancées en boucle par l'installation ou une mise à jour du paquet |

Le [périmètre du socle](INSTALLATION.md), le [catalogue des scripts](reference/SCRIPTS-PROVISIONING.md)
et `omni-siem catalogue` permettent de retrouver chaque composant. « Livré » ne
signifie pas « activé » : contrôler ensuite l'état et les journaux de chaque service.

## Plateformes

| Cible | État de cette distribution |
|---|---|
| Ubuntu 24.04 amd64 | Cible recommandée pour une nouvelle installation serveur |
| Ubuntu 22.04, Debian 12/13 amd64 | Chemins présents dans l'installateur ; limites et support éditeur décrits dans [INSTALLATION.md](INSTALLATION.md) ; les extensions peuvent exiger Python 3.12 |
| Ubuntu 26.04 amd64 | Expérimental ; option explicite obligatoire et contraintes MongoDB/noyau conservées |
| Systèmes DNF/RPM | Le RPM livre le projet, les outils et le collecteur. **L'installation native du serveur SIEM est refusée** ; elle n'est pas portée ni qualifiée sur RHEL/Rocky/Fedora |
| ARM / autres OS | Aucun serveur qualifié par cette release |

Prévoir AVX, au moins 16 Gio de RAM, DNS et réseau stables, stockage de données et
sauvegardes dimensionné. Les contrôles ne sont pas retirés pour faire disparaître
une erreur. Le serveur a besoin d'une machine dédiée ; ne pas reprovisionner la
production existante.

## Ubuntu : commandes ligne par ligne

Télécharger le `.deb` et `SHA256SUMS` depuis la **même**
[release GitHub](https://github.com/jmorin-info/omnitech-siem-setup/releases).
Le dépôt peut demander une authentification GitHub ; utiliser le navigateur ou
`gh release download` avec sa session locale, sans placer un jeton dans une URL.

```bash
cd ~/Téléchargements                 # adapter au dossier contenant les deux fichiers
sha256sum --ignore-missing --check SHA256SUMS
sudo apt update
sudo apt install ./omni-siem_0.1.0~rc.1_all.deb
omni-siem version
omni-siem init --plan
sudo omni-siem init --apply
sudo omni-siem configure
```

Dans le gestionnaire SSH, choisir **Configuration** : identité, réseau, accès,
mémoire/stockage, SMTP et secrets. Les exemples du dépôt sont à remplacer. Vérifier
notamment le réseau d'administration pour conserver son accès SSH et adapter les
heaps à la RAM. Le fichier privé se trouve dans
`/opt/omni-siem/repository/00-vars.env` (mode `600`). Ensuite :

```bash
sudo omni-siem install --generate-secrets   # complète les secrets MongoDB/OpenSearch absents
sudo omni-siem install --plan
# Lire le JSON : continuer uniquement si blockers est vide.
sudo omni-siem install --apply
sudo omni-siem health --json
```

Sur **Ubuntu 26.04**, remplacer les deux commandes de plan/application par :

```bash
sudo omni-siem install --plan --experimental-ubuntu-2604
sudo omni-siem install --apply --experimental-ubuntu-2604
```

Ouvrir ensuite `https://<SIEM_FQDN>/soc/`, avec une autorité de certification
approuvée. Contrôler les entrées, les flux, un message réel et les sauvegardes ;
la présence de la page ne prouve pas que les équipements émettent.

Pour un chemin différent, placer `--root` **avant** la commande à chaque étape :
`sudo omni-siem --root /srv/omni/repository init --apply`. Un chemin existant ou
symbolique est refusé par `init`. Pour administrer une installation existante,
sélectionner directement son dépôt avec `--root`, sans relancer `init` ni `install`.
Les profils de publication automatique gardent leurs propres contrôles de chemins.

## Modules et nouvelles machines

```bash
sudo omni-siem modules list
sudo omni-siem modules validate watchguard
sudo omni-siem configure
```

Le menu **Modules** du gestionnaire demande l'API Graylog, le jeton, l'autorité TLS,
l'adresse d'écoute et le port, puis affiche un plan avant l'installation. Le jeton
ne doit pas être collé dans une commande ou dans un fichier versionné. Suivre
[WatchGuard et les autres intégrations](INTEGRATIONS-MODULAIRES.md), puis
[les pages et widgets SOC](CONSOLE-MODULES.md). Le nouveau poste apparaît après
réception et normalisation de ses journaux dans les streams choisis, pas après une
simple installation de paquet.

Sur un poste Linux APT/DNF, installer le paquet local correspondant puis :

```bash
# Ubuntu/Debian : sudo apt install ./omni-siem_0.1.0~rc.1_all.deb
# DNF : sudo dnf install ./omni-siem-0.1.0-0.1.rc.noarch.rpm
sudo omni-siem agent --receiver siem.exemple.fr --plan
sudo omni-siem agent --receiver siem.exemple.fr --apply
```

Ce profil utilise **TCP sans chiffrement** sur 1519, sur un réseau interne de
confiance. Il exige que le serveur ait déjà son entrée Syslog TCP et son pare-feu
configurés (script `92-linux.sh`, revue explicite) ; le socle ne l'active pas
implicitement. Le kit auditd historique est livré séparément dans `kit/`.
La connectivité TCP est contrôlée avant modification, mais la réception réelle
reste à vérifier dans Graylog. Une configuration historique est refusée pour éviter
une double collecte. Les paquets rsyslog éventuellement ajoutés sont conservés lors
du retour arrière ; seuls les fichiers gérés et l'état du service sont restaurés.

## Mise à jour d'un environnement existant

1. Sauvegarder configuration et données, vérifier leur restauration.
2. Installer le nouveau `.deb`/`.rpm` local avec APT/DNF.
3. Lancer `sudo omni-siem --root /chemin/du/depot status` : révision du paquet et
   révision active sont distinctes et affichées.
4. Lancer `sudo omni-siem --root /chemin/du/depot update` et examiner les couches,
   le candidat et les contrôles décrits dans [UPDATES.md](UPDATES.md).
5. Appliquer explicitement le déploiement validé, puis contrôler santé, console,
   collecte et modules. Les bases existantes suivent leur runbook de montée de version.

APT/DNF ne remplacent jamais `/opt/omni-siem/repository`, `00-vars.env`, les pages
locales SOC ou les bases ; ils ne redémarrent pas les services du SIEM. Cela garde
un contrôle avant une vraie modification de production. La désinstallation du
paquet retire la distribution, pas l'installation active ni ses données.
Le paquet ne rend pas les migrations de bases automatiques ni universellement réversibles.

**GitHub Releases n'est pas un dépôt APT/DNF.** Cette préversion s'installe avec un
fichier local (`apt install ./...deb`, `dnf install ./...rpm`). Un futur dépôt
nécessitera index APT/repodata RPM, signature et gestion des clés. Les SHA-256
contrôlent l'intégrité par rapport au manifeste téléchargé ; ce ne sont pas des
signatures de confiance indépendantes.

## Échec, reprise et retour arrière

| Symptôme | Action |
|---|---|
| Installation refusée | Lire `blockers` du plan : OS, noyau, AVX, RAM, configuration ou installation préexistante. Corriger la cause |
| Installation interrompue | Garder la même révision, configuration et options ; `sudo omni-siem install --apply --resume` (ajouter l'option Ubuntu 26.04 si utilisée) ; état `/var/lib/omni-siem/install-state.json` |
| Configuration modifiée entre les reprises | Refus explicite ; examiner l'état avant de décider d'une nouvelle procédure. Ne pas effacer l'état pour forcer |
| Collecteur : configuration rsyslog invalide/service en échec | Restauration tentée automatiquement ; lire `/var/lib/omni-siem-agent/<transaction>/transaction.json`, notamment `rollback_incomplete` |
| Retour arrière du collecteur | `sudo omni-siem agent --rollback TRANSACTION --plan`, puis `--apply` ; refuse d'écraser une modification postérieure |
| Collecteur interrompu pendant l'écriture | `sudo omni-siem agent --recover TRANSACTION --plan`, puis `--apply` ; uniquement si le fichier actuel correspond à celui de la transaction |
| Code ou console en échec après déploiement | Retour arrière de la transaction de déploiement, selon [UPDATES.md](UPDATES.md) ; réinstaller un ancien paquet ne restaure pas une base |

Ne jamais lancer tous les scripts numérotés pour « terminer » une installation.

## Construire et qualifier une livraison

Sur Linux, avec Git, Python 3.12, `dpkg-deb` et `rpmbuild`, depuis un arbre Git propre :

```bash
python3 tools/build-release.py --output /tmp/omni-release-rc1
# Option : --format deb ou --format rpm ; sinon les deux.
```

La construction utilise les blobs suivis du commit, puis produit un dépôt Git
isolé à historique limité avec **le vrai SHA**, sans configuration Git locale,
identifiants, hooks, secrets ignorés ou environnements virtuels. L'inventaire Git
reste utilisable et un futur `fetch` peut rejoindre le dépôt amont.
Les archives comprennent les tests et la documentation ; les fichiers ajoutés mais
non commités bloquent la construction.

Le workflow **Distribution packages** construit les deux formats, vérifie le
bootstrap, la réinstallation/désinstallation sans perte du fichier de site, les
échecs et retours arrière du collecteur. Le workflow **Ubuntu 26.04 fresh VM**,
option `package_install`, effectue l'installation réelle depuis le `.deb` dans
une VM isolée, puis teste socle, console, intégrations et sauvegarde.
Le RPM n'est pas une preuve de compatibilité serveur sur une distribution RPM.

Une étiquette `v0.1.0-rc.1` doit correspondre à `distribution/version.json` ; elle
prépare un **brouillon de préversion** avec les artefacts et SHA-256. Ne publier le
brouillon qu'après contrôle des résultats du commit retenu et de la recette VM.
Les changements du SOC encore en cours sur d'autres branches ne font pas partie
de cette release tant qu'ils ne sont pas fusionnés et qualifiés.

Références : [installation locale APT](https://wiki.debian.org/AptCLI),
[règles Debian sur les scripts de paquet](https://www.debian.org/doc/debian-policy/ch-maintainerscripts),
[gestion des services dans les paquets Fedora](https://fedoraproject.org/wiki/Packaging%3ASystemd).
