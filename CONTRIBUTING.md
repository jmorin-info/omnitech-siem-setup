# Contribuer au dépôt OMNI SIEM

Ce dépôt provisionne et maintient un SIEM **en production**. Toute
modification doit pouvoir être relue, testée hors ligne, rejouée sans
dommage et annulée. Ce guide fixe les conventions communes.

## Avant de commencer

- Lire [l'index de la documentation](docs/README.md) et, pour un script de
  provisioning, [l'inventaire des scripts](docs/reference/SCRIPTS-PROVISIONING.md).
- Travailler sur une branche dédiée, jamais directement sur `main`.
- Installer les crochets Git du dépôt une fois par clone :
  `./scan-depot.sh --installer` (blocage des secrets et des mentions d'outillage).
- Ne jamais tester une modification directement sur la production : utiliser
  les tests hors ligne, la VM de qualification (`tools/test-ubuntu-vm.sh`) ou
  la pile Docker de préproduction.

## Scripts Bash

**En-tête obligatoire** : nom du script, objet, contexte (pourquoi), prérequis
(numéros des scripts ou services attendus), effet sur la production, mode
d'emploi et retour arrière.

**Idempotence** : un script se rejoue sans effet de bord. Créer les entités
Graylog par les fonctions `ensure_*` et `wrap_entity` de `lib-graylog.sh`,
vérifier l'existence avant toute création (définitions d'événements :
`all_event_defs`, qui pagine). Une entité est retrouvée **par son titre** :
changer un titre crée une nouvelle entité ; pour renommer, modifier l'entité
existante par son identifiant.

**Simulation par défaut** : tout script qui modifie la production affiche ce
qu'il ferait et n'écrit qu'avec une option explicite (`APPLY=1` ou `--apply`).
Un script destructif (purge, suppression d'index) le signale dans son nom ou
son en-tête, exige une confirmation et n'est jamais lancé par une boucle.

**Structure** :

```bash
#!/usr/bin/env bash
# NN-objet.sh - Objet en une ligne.
#   Contexte, effet, prérequis, retour arrière.
#   Idempotent. DRY-RUN par défaut ; appliquer : APPLY=1 ./NN-objet.sh
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env      # toujours en premier
source ./lib-graylog.sh   # puis la bibliothèque (construit API à partir de 00-vars.env)
require_api
```

**Numérotation** : ne pas créer de nouveau numéro en double. Un nouveau
script de provisioning prend le prochain numéro libre et est ajouté à
[SCRIPTS-PROVISIONING.md](docs/reference/SCRIPTS-PROVISIONING.md). Un script à
usage unique (correctif daté, migration, retour arrière) n'est pas numéroté :
il va dans [`tools/ponctuel/`](tools/ponctuel/README.md), avec sa date.

**Commentaires dans `00-vars.env`** : toujours sur une ligne séparée ; les
collecteurs Python ne retirent pas les commentaires en fin de ligne.

## Code Python

- Les projets `oms-xdr`, `oms-ml` et `oms-graph` ont leurs propres tests sous
  `<projet>/tests` ; toute évolution s'accompagne d'un test.
- Les collecteurs déployés sous `/usr/local/sbin` privilégient la bibliothèque
  standard (pas de dépendance à installer sur le serveur).
- Une action de réponse non implémentée doit le signaler explicitement et ne
  jamais renvoyer un succès simulé.
- La couche LLM ne déclenche jamais seule une action bloquante ou destructrice.

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
bash run-tests.sh
```

`run-tests.sh` compile le code Python, contrôle les liens internes de la
documentation (`tools/check-doc-links.py`) et lance les suites `pytest` du
dépôt et des sous-projets, sans réseau ni service. Pour utiliser un autre
interpréteur : `OMNI_TEST_PYTHON=/chemin/python bash run-tests.sh`.
La suite doit être verte avant toute demande de fusion ; ajouter des tests
pour ce qui est ajouté.

## Documentation

- Le français est la langue de référence, correctement accentué ; l'anglais
  est maintenu pour le `README.md` et les documents listés dans la
  [politique linguistique](docs/README.md#politique-linguistique).
- Aucun émoji ni pictogramme : utiliser des libellés (`[OK]`, `[Partiel]`,
  `Attention :`).
- Aucune affirmation non vérifiable : un chiffre cite sa source et sa date
  (code, API en lecture seule) ; une fonctionnalité non implémentée est
  présentée comme telle.
- Ranger un nouveau document dans le dossier de son usage et l'ajouter à
  [docs/README.md](docs/README.md). Un document daté qui n'évolue plus rejoint
  `docs/archives/`.
- Après un déplacement de fichier, corriger les liens et les références
  (scripts compris) ; `run-tests.sh` signale les liens cassés.
- Consigner toute évolution notable dans la section « Non publié » de
  [CHANGELOG.md](CHANGELOG.md).

## Secrets

- Aucun secret dans le dépôt : mots de passe, jetons, clés, URL de webhook,
  certificats privés. Les valeurs réelles vivent dans `00-vars.env`
  (permissions 600, ignoré par Git) et dans les fichiers `/etc/*.env` du
  serveur.
- Les gabarits versionnés (`00-vars.env.example`,
  [SECRETS.example.md](docs/securite-conformite/SECRETS.example.md)) ne
  contiennent que des valeurs factices (`CHANGEME`).
- Le crochet `pre-commit` (`scan-depot.sh --index`) bloque un commit suspect ;
  ne pas le contourner. En cas de fuite, suivre [SECURITY.md](SECURITY.md).

## Messages de commit

- En français, sobres et descriptifs : un titre de 72 caractères au plus,
  au présent (« Ajoute… », « Corrige… », « Range… »), puis un corps qui
  explique le pourquoi et l'effet.
- Un commit par sujet : ne pas mélanger un déplacement de fichiers et une
  modification de fond.
- Aucun émoji, aucune mention d'outil d'assistance, aucune ligne de
  co-signature automatique (le crochet `commit-msg` les refuse).

## Demandes de fusion

Utiliser le modèle proposé (`.github/pull_request_template.md`) : objet,
effet sur la production, procédure de déploiement et de retour arrière,
tests exécutés. Toute modification qui touche la production décrit les
commandes à exécuter par l'administrateur ; rien n'est déployé
automatiquement par une fusion.
