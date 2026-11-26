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

## Vérifier et héberger

Les tests de publication utilisent une clé temporaire indépendante. Ils vérifient
les signatures détachées, `InRelease`, les métadonnées RPM, la signature interne
du RPM, une lecture APT et le rejet d’une archive ou d’un catalogue altéré.
Ils n’utilisent jamais la clé privée du projet.

Avant de publier, vérifier les fichiers avec la clé publique attendue, conserver
les preuves de qualification et téléverser **seulement** `site/` sur l’hébergement
statique HTTPS choisi. Distribuer `signed-release/` dans une **nouvelle** release.
Ne pas recopier le dossier privé GnuPG ou les fichiers temporaires de déverrouillage.

Le catalogue APT expire au bout de **30 jours**. Prévoir sa régénération et sa
signature avant échéance ; ne pas conseiller de désactiver cette vérification
chez les utilisateurs. La conservation de plusieurs versions et la publication
atomique du site restent à mettre en place dans la chaîne d’hébergement.

## Conditions avant une 1.0 stable

Restent nécessaires : hébergement configuré, publication protégée sur tag,
vérification des signatures depuis l’hébergement réel, essai client DNF complet,
renouvellement du catalogue, sauvegarde externe de la clé et exercice de reprise
de la plateforme. Le statut des OS et des fonctions reste celui du
[guide de distribution](DISTRIBUTION.md), indépendamment de la signature.
