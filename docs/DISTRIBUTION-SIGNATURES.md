# Signature et dépôts de paquets

Cette chaîne prépare des fichiers signés et un site statique APT/DNF. Elle ne
téléverse rien et ne rend pas une version stable à elle seule. La préversion
publique `v0.1.0-rc.2` reste inchangée et non signée ; ne pas remplacer ses fichiers.

## Identité de publication

La clé publique du projet appartient à **Julien Morin (OMNI SIEM releases)**.
Empreinte complète :

```text
2668CC327A9ADCB1AE585187AE984C65217DB120
```

La [clé publique](../distribution/keys/omni-siem-release.asc) et sa
[politique](../distribution/keys/policy.json) peuvent être distribuées. La clé
principale sert à la certification et possède une sous-clé de signature. Les
exports privés sont chiffrés et conservés hors du dépôt. La sauvegarde locale du
mot de passe est protégée pour le compte Windows de l’opérateur. Cette sauvegarde
ne remplace pas une copie de secours externe, à vérifier avant la publication.

Ne jamais mettre de clé privée, certificat de révocation ou mot de passe dans
Git, les pièces jointes d’une release ou les journaux de CI. Une future CI de
signature ne doit recevoir que la sous-clé de signature, dans un environnement
réservé aux tags validés, sans accès depuis les contributions ou les pull requests.

## Construire puis préparer la publication

Sur une machine de publication Linux, installer `gpg`, `gpgv`, `rpm`
(`rpmbuild`, `rpmsign`, `rpmkeys`), `apt-utils` (`apt-ftparchive`) et
`createrepo-c` (`createrepo_c`). Construire depuis une révision Git propre :

```bash
python3 tools/build-release.py --output /var/tmp/omni-artifacts-VERSION
```

Le dossier doit contenir les trois formats, `release.json` et `SHA256SUMS`.
L’outil refuse les fichiers inattendus ou altérés. Vérifier le plan avec les
chemins réels de l’opérateur et l’URL HTTPS choisie pour l’hébergement :

```bash
python3 tools/publish-repositories.py \
  --artifacts /var/tmp/omni-artifacts-VERSION \
  --output /var/tmp/omni-publication-VERSION \
  --gpg-home /CHEMIN/PRIVE/gnupg \
  --fingerprint 2668CC327A9ADCB1AE585187AE984C65217DB120 \
  --base-url https://VOTRE_HEBERGEMENT/omni-siem \
  --suite testing
```

Le plan ne lit pas les secrets et ne crée pas le résultat. Pour exécuter, ajouter
`--apply`. Si un déverrouillage est nécessaire, fournir le chemin d’un fichier
temporaire de mot de passe, mode `0600`, via
`OMNI_SIGNING_PASSPHRASE_FILE`, puis supprimer ce fichier après l’opération.
Ne pas placer le mot de passe dans les arguments du processus.

Le résultat contient :

- `signed-release/` : paquets, archive, métadonnées, signatures détachées et
  manifeste signé. La signature interne RPM change son empreinte : les sommes
  sont recalculées après signature.
- `site/apt/` : paquets et catalogue avec `InRelease` signé.
- `site/dnf/` : RPM signé et métadonnées `repomd.xml` signées.
- `site/keys/`, `site/omni-siem.sources` et `site/omni-siem.repo` : clé publique et
  configurations clientes avec `Signed-By`, `gpgcheck=1` et `repo_gpgcheck=1`.
- `publication.json` : version, révision, empreinte, taille et absence de
  téléversement par cet outil.

Une préversion est refusée dans le canal `stable`. Une signature prouve l’origine
des fichiers, pas la compatibilité complète du serveur ni la réussite de sa reprise.

## Publication GitHub et renouvellement

Le workflow **Signed package repositories** s’exécute uniquement depuis `main`.
L’environnement `release-signing` doit autoriser uniquement cette branche. Il
contient l’export chiffré de la **sous-clé** (`OMNI_RELEASE_SUBKEY`) et son mot de
passe (`OMNI_RELEASE_PASSPHRASE`). L’import refuse une clé primaire privée réelle.
Les secrets ne sont accessibles ni aux pull requests ni aux branches de travail.
L’espace GnuPG temporaire est retiré même si la publication échoue.

Le canal est fixé dans [repository.json](../distribution/repository.json), avec
le tag autorisé, le canal `testing`, l’URL et l’empreinte attendue. Le mode
`publish` exige un **nouveau brouillon** du workflow Distribution packages,
les contrôles du dépôt et des paquets réussis sur la révision exacte, et une
recette VM déclenchée avec `package_install=true`. Le rapport doit confirmer
le socle, les intégrations et l’adoption sur cette même révision.

Parcours de publication :

1. Fusionner le code qualifié et créer un nouveau tag correspondant à
   `distribution/version.json`. Ne jamais déplacer un tag publié.
2. Attendre les contrôles Repository checks et Distribution packages. Ce dernier
   laisse un brouillon de préversion et des fichiers non signés.
3. Déclencher Ubuntu 26.04 fresh VM sur la **même révision**, avec
   `package_install=true`, et attendre sa réussite.
4. Depuis `main`, déclencher Signed package repositories en mode `publish` avec
   l’identifiant de ce passage VM. Le workflow conserve les identifiants des preuves et l’empreinte du rapport
   JSON normalisé (clés triées, séparateurs compacts) dans les métadonnées signées.
5. Le workflow signe, vérifie, remplace les fichiers du **brouillon uniquement**,
   déploie les catalogues via GitHub Pages, puis vérifie les octets hébergés et les
   empreintes GitHub avant de publier la préversion. Un échec laisse le brouillon
   non publié. Il n’existe aucune promotion automatique vers une version stable.

La publication Pages remplace le site comme un ensemble. Seuls les paquets, la
clé publique et les catalogues sont hébergés, jamais le dépôt complet ni les
secrets. URL du canal configuré :
`https://jmorin-info.github.io/omnitech-siem-setup/`.
Les commandes clientes ci-dessous s’utilisent **après** une publication réussie.

Chaque mardi, le mode `refresh` vérifie la release déjà signée, recrée les
catalogues et renouvelle leur signature. Les octets des paquets et les pièces
jointes publiées restent inchangés. Le catalogue APT expire après **30 jours** :
un échec du workflow hebdomadaire doit être traité avant cette échéance, sans
contourner `Valid-Until` côté client. Une relance manuelle en mode `refresh`
permet de réessayer. Le site conserve actuellement la seule version configurée ;
les anciennes releases GitHub restent disponibles avec leurs signatures.

## Installer le paquet depuis le canal de préversion

Vérifier l’empreinte dans ce dépôt par un canal de confiance avant de l’accepter.
Ces commandes livrent les outils ; elles ne lancent pas l’installation ou la
mise à jour des bases et services du SIEM. Suivre ensuite le
[parcours de distribution](DISTRIBUTION.md).

### Ubuntu / Debian

```bash
set -e
base=https://jmorin-info.github.io/omnitech-siem-setup
key=$(mktemp)
curl --fail --silent --show-error "$base/keys/omni-siem-release.asc" -o "$key"
listing=$(gpg --batch --show-keys --with-colons "$key")
test "$(printf '%s\n' "$listing" | grep -c '^pub:')" = 1
test "$(printf '%s\n' "$listing" | grep -E -c '^(sec|ssb):')" = 0
fingerprint=$(printf '%s\n' "$listing" | awk -F: '$1=="fpr" {print $10; exit}')
test "$fingerprint" = 2668CC327A9ADCB1AE585187AE984C65217DB120
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 "$key" /etc/apt/keyrings/omni-siem.asc
rm -- "$key"
curl --fail --silent --show-error "$base/omni-siem.sources" | sudo tee /etc/apt/sources.list.d/omni-siem.sources >/dev/null
sudo apt-get update
sudo apt-get install omni-siem
omni-siem version
```

Prérequis pour l’import : `curl`, `gnupg` et les certificats système. La clé est
limitée à cette source par `Signed-By`. Pour recevoir un paquet ultérieur, utiliser
`sudo apt-get install --only-upgrade omni-siem`, puis le parcours explicite de
mise à jour du site ; le paquet ne remplace pas le dépôt actif de lui-même.

### Rocky / RHEL compatibles DNF

```bash
set -e
base=https://jmorin-info.github.io/omnitech-siem-setup
key=$(mktemp)
curl --fail --silent --show-error "$base/keys/omni-siem-release.asc" -o "$key"
listing=$(gpg --batch --show-keys --with-colons "$key")
test "$(printf '%s\n' "$listing" | grep -c '^pub:')" = 1
test "$(printf '%s\n' "$listing" | grep -E -c '^(sec|ssb):')" = 0
fingerprint=$(printf '%s\n' "$listing" | awk -F: '$1=="fpr" {print $10; exit}')
test "$fingerprint" = 2668CC327A9ADCB1AE585187AE984C65217DB120
sudo rpm --import "$key"
rm -- "$key"
curl --fail --silent --show-error "$base/omni-siem.repo" | sudo tee /etc/yum.repos.d/omni-siem.repo >/dev/null
sudo dnf install omni-siem
omni-siem version
```

Les contrôles `gpgcheck` et `repo_gpgcheck` restent actifs. Le RPM distribue les
outils et le collecteur Linux ; l’installation native du **serveur** SIEM sur
ces OS reste refusée. Un test DNF dans Rocky Linux 9 vérifie l’import de la clé,
les métadonnées et l’installation du paquet signé ; il ne qualifie pas tous les
OS RPM ni une plateforme SIEM complète sur ces systèmes.

## Diagnostic et reprise

- Empreinte différente : ne pas importer la clé. Vérifier l’URL, la politique et
  l’éventuelle rotation publiée par le responsable du projet.
- Signature ou somme invalide : arrêter la mise à jour. Ne pas utiliser
  `--nogpgcheck`, `trusted=yes` ou la désactivation de `Valid-Until`.
- Publication interrompue avant le remplacement du brouillon : corriger la cause
  puis relancer. Si le brouillon contient déjà une partie des signatures,
  rétablir ses fichiers bruts depuis l’artefact Distribution packages validé,
  sans modifier une release déjà publiée.
- Site publié mais contrôle final en échec : le brouillon reste privé. Corriger
  l’hébergement et relancer une vérification avant publication ; ne pas modifier
  les paquets signés pour masquer l’écart.
- Renouvellement en échec : la release publiée reste intacte ; relancer `refresh`
  après correction. Contrôler la dernière réussite dans GitHub Actions.

Les tests utilisent une clé temporaire distincte de celle du projet et couvrent
APT, signatures RPM, installation DNF, intégrité, refus d’une recette incomplète,
rejet d’une clé primaire privée en CI et conservation des octets en renouvellement.

## Renouveler ou révoquer la clé

Sur le poste de publication, consulter les échéances et les empreintes :

```bash
gpg --homedir /CHEMIN/PRIVE/gnupg --list-keys --with-subkey-fingerprint 2668CC327A9ADCB1AE585187AE984C65217DB120
```

Avant expiration, le responsable utilise la clé principale hors CI pour prolonger
la sous-clé sélectionnée ou en certifier une nouvelle. Exemple de prolongation,
en remplaçant `EMPREINTE_SOUS_CLE` par la valeur complète relevée ci-dessus :

```bash
gpg --homedir /CHEMIN/PRIVE/gnupg --quick-set-expire 2668CC327A9ADCB1AE585187AE984C65217DB120 1y EMPREINTE_SOUS_CLE
```

Exporter le certificat public mis à jour et l’export chiffré des sous-clés ;
actualiser le dépôt, la politique et les secrets de l’environnement GitHub,
puis vérifier une publication. Les clients doivent réimporter le certificat
actualisé après contrôle de l’empreinte primaire. La clé principale privée
reste hors CI.

Une nouvelle clé primaire demande une migration explicite des clients et de la
politique de confiance ; ne pas ajouter plusieurs certificats dans le fichier
public. En cas de compromission, suspendre la publication, révoquer la clé avec
le certificat conservé séparément et diffuser la révocation aux utilisateurs.
Conserver une sauvegarde chiffrée externe et tester sa récupération.

Référence : [gestion des clés GnuPG](https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html).

## Conditions avant une 1.0 stable

Restent nécessaires : sauvegarde externe de la clé, qualification complète du
parcours d’enrôlement des sources et exercice de reprise de la plateforme. Les
fonctions SOC avancées en chantier ne sont pas ajoutées à une release par simple
changement de numéro. Ubuntu 26.04 conserve son statut expérimental. Le statut des
OS et fonctions reste celui du [guide de distribution](DISTRIBUTION.md).
