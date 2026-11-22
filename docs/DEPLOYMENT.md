# Déploiement

Cette page décrit le parcours complet : installation neuve, redéploiement d'un
composant, vérification et retour arrière. Les prérequis et options de
l'installation neuve sont détaillés dans [INSTALLATION.md](INSTALLATION.md), les
mises à jour de code dans [UPDATES.md](UPDATES.md), la console dans
[CONSOLE-DEPLOIEMENT.md](CONSOLE-DEPLOIEMENT.md).

## Dépôt canonique

Le code s'exécute depuis **un seul** clone Git : `/opt/omni-siem/repository`
(variable `OMNI_SIEM_HOME`). Les robots de `/usr/local/sbin` y lisent
`00-vars.env`, les unités systemd y trouvent les scripts et les venvs Python
(`mobile/.venv`, `oms-xdr/.venv`, `oms-graph/.venv`, `oms-ml/.venv`).

- Les scripts shell exécutés depuis le dépôt utilisent
  `${OMNI_SIEM_HOME:-/opt/omni-siem/repository}` ou leur propre répertoire.
- Les fichiers déployés (robots, unités) contiennent le chemin par défaut en clair ;
  avec un autre emplacement, `omni-deploy` le remplace au moment du déploiement
  (`--home` ou `OMNI_SIEM_HOME`).
- `omni-deploy` refuse d'appliquer depuis une autre copie que le dépôt canonique.

**Différence avec l'installation historique** : la production de référence exécute
encore une partie de son code depuis `/root/omnitech-siem-setup` (9 unités, 25 robots,
venvs). Certaines unités de base conservent leurs chemins historiques ; les
drop-ins `50-depot-reference.conf` définissent leur nouvel emplacement après
déploiement. Le backend versionné utilise désormais `OMNI_REPO_DIR` pour ses
chemins de données. Tant que l'ancien backend reste en service, ses chemins
restent ceux de l'installation historique. La migration est décrite en section 6.

## 1. Installation neuve

```bash
sudo git clone https://github.com/jmorin-info/omnitech-siem-setup.git /opt/omni-siem/repository
cd /opt/omni-siem/repository
sudo install -m 600 00-vars.env.example 00-vars.env
sudo nano 00-vars.env   # renseigner le site avant de continuer
sudo bash install.sh --generate-secrets
sudo bash install.sh --plan
sudo bash install.sh --apply
sudo python3 tools/omni-healthcheck.py
```

`install.sh` applique une liste explicite de phases (profil `core-soc`), enregistre
sa progression et refuse une machine déjà installée. **Ne jamais exécuter tous les
scripts numérotés** : certains purgent, changent la rétention ou recréent des
dashboards. Les robots, unités et venvs des extensions (ML/XDR/graphe, SOAR,
M365, SEAL...) ne sont pas installés par ce profil : après leur configuration, ils
se déploient avec `omni-deploy` (section 2).

## 2. Redéployer un composant : `tools/omni-deploy.py`

Sens unique dépôt vers système, piloté par `manifeste-deploye.txt`. **Plan par
défaut** ; `--apply` après lecture du plan.

```bash
python3 tools/omni-deploy.py deploy all                 # plan complet (lecture seule)
python3 tools/omni-deploy.py deploy robots systemd      # plan limité
sudo python3 tools/omni-deploy.py deploy robots --apply
sudo python3 tools/omni-deploy.py deploy systemd --filtre '*/oms-graph.service.d/*' --apply
python3 tools/omni-deploy.py history
```

| Composant | Cibles | Actions associées |
|---|---|---|
| `venvs` | `<dépôt>/{mobile,oms-xdr,oms-graph,oms-ml}/.venv` | construction depuis `requirements.txt`, `pip check` ; l'ancien venv est conservé pour le retour arrière |
| `robots` | `/usr/local/sbin`, `/usr/local/lib` | redémarrage des seuls services longs actifs qui exécutent le robot |
| `etc`, `opt` | fichiers suivis de `/etc` et `/opt` | aucune |
| `logstash` | `/etc/logstash` | aucun redémarrage automatique (signalé) |
| `systemd` | unités et drop-ins `omni-*`, `oms-*`, `siem-*` | `daemon-reload`, redémarrage des services longs et timers modifiés s'ils sont actifs |
| `nginx` | `/etc/nginx/snippets` | `nginx -t` puis `reload` |
| `console` | `/var/www/siem-soc`, `/var/www/siem-mobile` (toutes les ressources, page puis service worker en dernier) | aucune ; les routes nginx relèvent de `tools/deploy-console.py` |
| `apt` | préférences APT | jamais incluses dans `all` ; aucune commande apt |

`all` désigne tous les composants sauf `apt`, dans l'ordre du tableau (venvs en premier).

Garanties :

- **Idempotence** : un fichier identique n'est pas réécrit ; un second `--apply`
  sans changement ne crée pas de transaction.
- **Sauvegarde** : chaque fichier remplacé est copié dans
  `/var/lib/omni-siem-deploy/transactions/<id>/backup/` avant écriture atomique ;
  le propriétaire est conservé. Unités, nginx et console reçoivent 0644, sauf fichier
  portant un secret `Environment=` ; un fichier identique mais en 0600 ou 0664 est
  seulement remis en 0644. Les autres composants gardent leurs droits actuels.
- **Blocages** (rien n'est écrit) : source absente, cible en lien symbolique, cible
  dans le dépôt, mot de passe masqué par `synchro-manifeste.sh`, robot référençant
  l'ancien chemin, **exécutable d'un `ExecStart` effectif absent** (venv non
  construit, robot non déployé), dépôt non canonique.
- **Retour arrière automatique** si `daemon-reload`, `nginx -t`, un redémarrage
  échoue ou si un service redémarré n'est plus actif 5 secondes après : tous les
  fichiers et venvs de la transaction sont restaurés et les services qui tournaient
  avant sont relancés.
- Un verrou empêche deux déploiements simultanés.

Les deux sens ne se confondent pas : `synchro-manifeste.sh` recopie dans le dépôt
un changement fait en production (production vers dépôt), `omni-deploy` déploie le
dépôt (dépôt vers production). `generer-manifeste.sh` liste toujours les fichiers de
`deploye/sbin` et `deploye/systemd`, même pas encore en service.

Racine factice pour répéter un déploiement hors production (aucune commande système) :

```bash
python3 tools/omni-deploy.py --root /tmp/racine --home "$PWD" deploy all --apply
```

## 3. Vérifier : `tools/omni-healthcheck.py`

Lecture seule, à lancer après une installation, un déploiement ou un redémarrage
(`omni-deploy deploy --apply` le lance de lui-même) :

```bash
sudo python3 tools/omni-healthcheck.py          # ou : make health ; --json pour l'outillage
```

Contrôles critiques : `mongod`, `opensearch`, `graylog-server`, `nginx`,
`omni-mobile-api` et les services longs activés du dépôt actifs ; timers activés en
marche ; ports 443, 9000, 9200, 27017, 8090 en écoute ; OpenSearch vert ou jaune ;
API Graylog (`lbstatus`, `lifecycle=running`, tous les inputs RUNNING) ; backend
`/m/api/vapid` et page `https://<fqdn>/soc/` en HTTP 200 (certificat vérifié avec la
CA du site). Avertissements : unités en échec, disques au-delà de 85 %, fichiers en
service référençant encore `/root/omnitech-siem-setup`, certificat non approuvé.
Code de sortie 1 si un contrôle critique échoue. Les identifiants viennent de
`00-vars.env` (ou `GRAYLOG_API_TOKEN`) et ne sont jamais affichés. `verif-post-reboot.sh`
reste disponible pour les contrôles propres au redémarrage (LUKS, TPM, noyau).

## 4. Revenir en arrière

```bash
python3 tools/omni-deploy.py rollback <transaction>          # plan
sudo python3 tools/omni-deploy.py rollback <transaction> --apply
```

Le retour arrière restaure les sauvegardes, supprime les fichiers créés, remet les
venvs précédents et les droits d'origine, puis relance `daemon-reload`, nginx et les
services concernés. Il refuse un fichier modifié depuis la transaction (`--force`
pour l'écraser après examen). Il ne concerne que les fichiers de la transaction :
ni base de données, ni configuration Graylog, ni code mis à jour par `omni-update`.

## 5. Gestionnaire SSH

`sudo python3 tools/omni-manager.py`, entrée « Déployer les composants maison /
contrôle de santé » : choix du composant dans une liste fermée, plan, déploiement
après confirmation `OUI`, contrôle de santé, historique, plan et application d'un
retour arrière. Aucune commande libre n'est transmise.

## 6. Migration de la production vers le dépôt canonique

Alignée sur le plan du rapport de cohérence du 21/11/2026 (§ 5). Prérequis : cette
branche fusionnée et `/opt/omni-siem/repository` à jour et propre.

```bash
cd /opt/omni-siem/repository
bash tools/migrer-chemin-canonique.sh             # plan, lecture seule
sudo bash tools/migrer-chemin-canonique.sh --apply
```

`--apply` : archive l'ancienne copie, `/etc/systemd/system` et `/etc/nginx` dans
`/var/backups/omni-siem` ; ajoute `MITRE_LOOKUP` à `/etc/default/omni-mobile` s'il
manque ; construit et vérifie les venvs **avant tout repointage** ; pose les drop-ins
`50-depot-reference.conf` **une transaction par service** (omni-iso-evidence, oms-graph,
oms-graph-respond, oms-ml-anomaly, oms-ml-fp, oms-xdr, omni-backup-config,
omni-disk-guard, omni-mobile-api), avec arrêt au premier échec ; déploie les robots ;
remet les unités en 0644 ; lance le contrôle de santé. Les services `oneshot`
repointés ne sont pas démarrés : les tester avec `systemctl start <service>` puis
`journalctl -u <service>`.

Non traité automatiquement :

- `omni-iso-evidence`, ajouté après la migration du 22/11/2026, se repointe seul :
  `sudo python3 tools/omni-deploy.py deploy systemd --filtre '/etc/systemd/system/omni-iso-evidence.service.d/*' --apply`
  (le drop-in `50-depot-reference.conf` et le `hardening.conf` aligné sont dans la même
  transaction). Le service écrit alors uniquement dans
  `/opt/omni-siem/repository/docs/archives/preuves-iso` (`ReadWritePaths` limité à `/var/lib`
  et à ce dossier) ; chaque dossier mensuel y apparaît comme fichier non suivi du clone, à
  commiter depuis un poste de travail si on veut le versionner. Test : `systemctl start
  omni-iso-evidence.service` puis `journalctl -u omni-iso-evidence.service`.
- Étape 4 du plan, au plus tôt le 23/11/2026 à 10:00, après la pose du drop-in
  d'`omni-iso-evidence` : renommage de l'ancienne copie et lien symbolique vers le dépôt
  canonique, par `tools/retirer-ancienne-copie.sh` (à lancer depuis le dépôt canonique,
  jamais depuis l'ancienne copie) :

  ```bash
  cd /opt/omni-siem/repository
  bash tools/retirer-ancienne-copie.sh               # plan, lecture seule
  sudo bash tools/retirer-ancienne-copie.sh --apply  # mv vers .retire-AAAAMMJJ puis ln -s
  sudo bash tools/retirer-ancienne-copie.sh --rollback
  ```

  Contrôles bloquants : date ; aucune unité systemd dont la configuration **effective**
  (`systemctl show` : `ExecStart*`, `WorkingDirectory`, `EnvironmentFiles`,
  `ReadWritePaths`...) utilise l'ancienne copie, une unité de base repointée par son drop-in
  n'étant pas bloquante ; aucune tâche cron ; aucun processus (répertoire courant,
  exécutable, ligne de commande, fichiers ouverts, bibliothèques chargées) ; `00-vars.env`
  identique dans les deux copies (comparé sans affichage). Le plan liste aussi les fichiers
  de secrets en clair de l'ancienne copie (chemin, taille, droits) ; `--apply` en garde la
  liste dans `/var/lib/omni-retrait-ancienne-copie/secrets-a-supprimer.txt`. Relevé du
  22/11/2026 : seul `omni-iso-evidence` bloque encore ; secrets en clair `00-vars.env`
  (0600) et `SECRETS.md` (0644).
- Après 7 jours (étape 5 du rapport de cohérence) : suppression de la copie retirée,
  en commençant par `shred -u` sur les fichiers de secrets listés, puis retrait des autres
  copies obsolètes. Non automatisé.

## 7. Intégration continue

`.github/workflows/check.yml` :

| Tâche | Contenu |
|---|---|
| `offline` | `bash run-tests.sh` (dont `tools/check-manifest.py`), inventaire de portabilité |
| `lint` | `tools/ci-lint.sh` : ShellCheck niveau warning, Ruff erreurs bloquantes |
| `secrets-and-manifest` | `scan-depot.sh --arbre` (motifs de secrets sur tous les fichiers suivis), messages de commit, manifeste, plan `omni-deploy` complet en racine factice |

`ubuntu-vm.yml` installe une VM Ubuntu 26.04 vierge et lance la réception.

Exclusions ShellCheck justifiées dans `.shellcheckrc` (SC1090/SC1091 sources
calculées, SC2034 compteurs de boucle, SC2164 `cd` historiques) ; constats acceptés
un par un dans `tools/shellcheck-baseline.txt`, dont un **défaut réel non corrigé**
(`49-enrich-lots.sh`, `$message` non échappé dans un heredoc). Ruff vise Python 3.12 :
`triage/omni-alert-digest` n'est pas compatible avec Python 3.11 ni 3.10. Le scan
de secrets repose sur des expressions régulières, sans outil dédié de type gitleaks.

En local :

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt -r requirements-lint.txt
bash run-tests.sh
PATH="$PWD/.venv/bin:$PATH" bash tools/ci-lint.sh
bash scan-depot.sh --arbre
```

## Docker et reprise

Le [bundle Docker](../docker/README-DOCKER.md) est un profil distinct (préproduction,
PRA) : ses conteneurs n'incluent pas tous les services natifs. Une reprise après
sinistre n'est pas un déploiement : voir [RESTORE.md](../RESTORE.md) et
[PRA-RECONSTRUCTION-SIEM.md](PRA-RECONSTRUCTION-SIEM.md).
