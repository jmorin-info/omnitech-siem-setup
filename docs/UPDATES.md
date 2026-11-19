# Mises à jour de code avec conservation de la configuration locale

`tools/omni-update.py` prépare une révision Git précise, affiche les différences,
sauvegarde les fichiers de code qu'il remplace et permet de revenir sur sa dernière
transaction. Il fonctionne avec Python 3 et Git, sans dépendance Python supplémentaire.

Ce mécanisme met à jour le **code applicatif et les fichiers statiques du dépôt installé**.
Il ne lance aucun script de provisioning, ne met à jour aucun paquet système et n'écrit
dans aucune base Graylog, MongoDB ou OpenSearch. La publication des fichiers statiques
vers nginx et les redémarrages de services restent une étape explicite. Une mise à jour
de code n'est donc pas, à elle seule, une migration complète de la plateforme.

## Préparer une révision sans toucher au SIEM

Exécuter depuis le dépôt installé. L'état doit être stocké **hors du dépôt**, dans un
répertoire réservé à l'administrateur (par défaut `/var/lib/omni-siem-updater`).

```bash
# Télécharge la référence main dans un cache séparé du dépôt installé.
sudo python3 tools/omni-update.py fetch --source "$PWD" --ref main

# Reprendre le SHA complet de 40 caractères renvoyé dans le champ target.
TARGET=<SHA_COMPLET_RENVOYE_PAR_FETCH>

# Lecture seule : aucun fetch, aucune création de répertoire ou modification.
sudo python3 tools/omni-update.py plan --source "$PWD" --target "$TARGET"

# Prépare et contrôle les fichiers dans releases/<SHA> ; aucun code candidat exécuté.
sudo python3 tools/omni-update.py stage --source "$PWD" --target "$TARGET"
```

Le téléchargement utilise HTTPS, refuse les identifiants inclus dans l'URL et s'arrête
si Git échoue. Pour un fork public ou accessible par le mécanisme d'authentification
Git de l'hôte, `fetch --remote https://.../depot.git --ref <tag-ou-branche>` sélectionne
un autre dépôt. Ne pas inscrire de jeton dans la ligne de commande ou dans son URL.
Le SHA affiché est ensuite figé ; `apply-code` n'accepte pas une branche mouvante.

## Ce qui est préservé

- Les secrets, `00-vars.env`, les fichiers `.env`, clés et certificats.
- Les configurations de site YAML/YML et les lookups CSV, y compris leurs modifications
  locales lorsque Git les suit.
- Les fichiers système, les paramètres de rétention, les utilisateurs, les définitions
  Graylog, les installations de packs et les journaux.
- Les scripts numérotés de provisioning et de maintenance : ils sont signalés au plan,
  sans être exécutés ni recopiés par `apply-code`.

Les fichiers distribués sous `integrations/` (manifestes JSON, règles et dashboards)
constituent le code des packs. Leur mise à jour dans le dépôt **n'installe pas** une nouvelle
révision du pack dans Graylog. Les exports de configuration d'un client doivent être
conservés hors de ces répertoires distribués.

Le plan distingue `code_files`, `preserved_or_manual_files`, `conflicts` et
`migration_review_required`. Une personnalisation locale d'un fichier de code géré bloque
la mise à jour avant toute copie. Il faut alors conserver cette personnalisation et
résoudre le conflit explicitement ; aucun `reset --hard`, `clean`, écrasement forcé ou
fusion automatique n'est effectué. Un fichier local non suivi qui entrerait en collision
avec un nouvel asset est également conservé et bloque l'opération.

## Appliquer et publier

```bash
sudo python3 tools/omni-update.py apply-code --source "$PWD" --target "$TARGET"
sudo python3 tools/omni-update.py status --source "$PWD"
```

Avant chaque remplacement, les anciens octets et permissions sont sauvegardés dans
`backups/<transaction>/`. Les copies de fichiers sont atomiques ; si une copie échoue,
les fichiers déjà remplacés sont restaurés. L'intégrité du candidat et des sauvegardes
est vérifiée. La syntaxe Python, JSON et shell des sources gérées est contrôlée sans
importer ni exécuter le code candidat. Le verrou `update.lock` empêche deux opérations concurrentes.

Après une mise à jour de la console : publier explicitement les assets avec
`sudo bash 71-soc-console.sh`, puis vérifier `/soc/` et ses scripts. Sur une installation
récente gérée dans `/opt/omni-siem/console`, cette commande active aussi le nouveau backend
si son marqueur de propriété, son hash et le chemin `ExecStart` correspondent : sauvegarde,
redémarrage, contrôle de santé et retour arrière sur échec. La configuration locale reste
conservée. Un backend modifié localement est refusé ; les services hérités sont conservés
et nécessitent leur procédure de publication explicite. Ne pas assimiler un HTTP 200 de
l'ancienne version à une preuve de validation de la nouvelle.

Les changements de scripts d'installation Graylog/MongoDB/OpenSearch, du Compose ou
d'un dossier de migrations, les versions centrales (`stack-versions.env`) et les
dépendances Python/Docker bloquent `apply-code` et imposent une revue de compatibilité.
Le blocage est volontairement conservateur : une modification de commentaire dans ces
fichiers est aussi signalée. Une montée de version des bases exige ses sauvegardes,
son ordre de migration et son test de restauration ; le retour arrière du code ne
permet pas de rétrograder une base déjà migrée.

## Retour arrière et interruption

```bash
# Reprendre l'identifiant transaction renvoyé par apply-code.
sudo python3 tools/omni-update.py rollback --source "$PWD" --transaction <IDENTIFIANT>
```

Seule la dernière transaction appliquée peut être annulée. Un fichier modifié localement
après la mise à jour bloque le retour arrière pour ne pas détruire cette modification.
Ce retour arrière restaure uniquement les fichiers possédés par la transaction ; il ne
restaure ni les bases, ni les déploiements nginx effectués séparément.

Après une coupure de processus ou de machine, inspecter `update.lock` et le journal
`backups/<transaction>/transaction.json` avant de retirer un verrou devenu orphelin.
Si aucun processus de mise à jour ne tourne et que le journal est encore marqué
`applying`, retirer uniquement ce verrou orphelin, puis lancer :

```bash
sudo python3 tools/omni-update.py recover --source "$PWD" --transaction <IDENTIFIANT>
```

La récupération accepte uniquement les octets d'avant ou d'après la transaction et
contrôle toutes les sauvegardes avant la restauration ; une modification tierce bloque
l'opération. Aucune tentative de réparation des bases n'est lancée par l'outil.

L'outil conserve son propre `code_revision`. Il laisse `git HEAD` inchangé, puisque
les configurations et les scripts retenus hors du périmètre n'ont pas été remplacés.
Ainsi, il ne prétend pas que l'ensemble de l'installation est identique à la révision
Git cible. Si `HEAD` change séparément, l'état de l'outil doit être réconcilié avant
la prochaine transaction.
