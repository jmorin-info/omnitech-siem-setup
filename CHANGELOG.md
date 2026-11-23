# Journal des modifications

Toutes les évolutions notables du dépôt et de la plateforme SIEM OMNITECH sont
consignées ici. Le format suit les principes de
[Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) : entrées les plus
récentes en premier, regroupées par date de livraison, sections « Ajouté »,
« Modifié », « Corrigé », « Supprimé » pour les nouvelles entrées. Le dépôt ne
publie pas de versions numérotées : chaque livraison est identifiée par sa date.

Les entrées antérieures au 21/11/2026 sont reprises de l'ancien journal
tenu dans le dossier `docs` sans réécriture ; elles sont rédigées en liste libre.

## [Non publié]

### Ajouté

- Console SOC, Administration > Apparence : nom affiché, sous-titre, logo (PNG, JPEG ou WebP, 512 Ko, signature binaire et dimensions contrôlées, SVG refusé), couleurs des modes sombre et clair limitées aux variables existantes de `app-professional.css` avec refus sous 4,5:1 de contraste, thème par défaut, aperçu local et retour aux valeurs d'origine. Routes `GET /m/api/appearance`, `GET /m/api/appearance/logo` (utilisateur authentifié, `nosniff`), `GET`/`POST /m/api/admin/appearance` (administrateur, garde-fous et audit existants) ; stockage sous `SOC_APPEARANCE_DIR` ; nouveau module `mobile/soc/app-theme.js`, service worker `soc-v8-2026112301`. Documentation `docs/CONSOLE-SOC.md#apparence`, tests `tests/test_console_appearance.py`.
- `tools/maj-detections-2026-11.py` et `tools/maj-detections-2026-11/cibles.json` : mise à jour des définitions corrigées en production. Plan par défaut en lecture seule (diff production -> cible et `_count` OpenSearch avant/après sur 30 jours) ; `--apply` sauvegarde chaque définition puis applique par PUT une définition à la fois (planification conservée, relecture, arrêt au premier échec), idempotent, dérive bloquante sauf `--forcer`, seule désactivation possible celle listée (ZON-001) ; `--rollback`. Tests `tests/test_maj_detections.py`.
- `seal/graylog/gabarit_zone_portes.py` et `seal/graylog/omni-seal-zone.gabarit.csv` : gabarit des 127 portes SEAL à rattacher à une zone physique (clé `seal_site:OBFI_ID`, lecture OpenSearch) et production du CSV du lookup `omni-seal-zone` à partir du gabarit renseigné. Tests `tests/test_seal_zone_gabarit.py`.
- Fixtures de validation 19 (IP malveillante sortante), 20 (SEAL HYP-002) et 21 (SEAL SLA-001) ; fixture 17 (RAT/RMM) complétée de deux cas en casse Windows. `tools/detection-validation/exceptions.json` : quatre exceptions `notifications` reprenant des décisions tracées (adm-* hors heures, enregistrement MFA M365, blocage SOAR, SEAL EVT-001).
- `tools/omni-soc-kpi.py` : indicateurs SOC calculés en lecture seule (OpenSearch `_search`, API Graylog en GET, fichiers d'état) sur une période paramétrable, sortie JSON et Markdown avec médiane et p90 : volume d'alertes par sévérité, source et détection ; MTTD exact pour les détections unitaires et encadré pour les agrégations ; prise en charge et clôture des dossiers, délai alerte vers blocage SOAR, journal d'audit ; faux positifs du triage ; couverture ATT&CK des définitions actives. Les données absentes sont listées dans « lacunes ». Documentation `docs/exploitation/INDICATEURS-SOC.md`, tests `tests/test_soc_kpi.py`.
- Console SOC : page « Indicateurs » (`mobile/soc/app-kpi.js`) et point d'API `GET /m/api/soc-kpi?days=N` réservé aux rôles analyste et administrateur, calcul partagé avec l'outil, cache de 10 minutes.
- `tools/migrer-depot-snapshots.sh` : relocalisation du dépôt de snapshots OpenSearch de `/home` (`graylog_fs`) vers `/data` (`graylog_fs_data`) ; plan en lecture seule par défaut, `--apply` (ancien chemin conservé dans `path.repo`, redémarrage contrôlé avec santé avant et après, enregistrement et vérification du dépôt, bascule de `/etc/oms-snap-siem.conf`, premier snapshot vérifié), `--rollback`, et `--retirer-ancien` refusé avant 3 snapshots réussis. Tests hors ligne `tests/test_migration_snapshots.py`.
- Drop-in `deploye/systemd/omni-iso-evidence.service.d/50-depot-reference.conf` : `omni-iso-evidence` exécute `68-iso-evidence.sh` du dépôt canonique et n'écrit que dans `/var/lib` et `docs/archives/preuves-iso` ; `hardening.conf` (lu après le drop-in) et `27-harden-services.sh` portent la même liste. Le service est ajouté à `tools/migrer-chemin-canonique.sh` et au manifeste ; `68-iso-evidence.sh` ne réécrit plus l'unité quand il tourne sous systemd.
- `tools/maj-cert-orchestrator-prod.sh` (plan, `--apply`) : met à jour par PUT idempotent les 5 règles `omni-cert-*` déjà créées en production et aligne l'index set `omni-cert` sur `P1M` x 3, sans création ni suppression. Tests `tests/test_cert_orchestrator.py`.
- `tools/retirer-ancienne-copie.sh` (plan, `--apply`, `--rollback`) : étape 4 du plan de cohérence, renommage de `/root/omnitech-siem-setup` et lien vers le dépôt canonique, après contrôle de la date, des unités systemd (configuration effective), des tâches cron, des processus et de l'identité des `00-vars.env` ; liste des secrets en clair pour l'étape 5. Tests `tests/test_retrait_ancienne_copie.py`.
- `tools/omni-restore-drill.py` : exercice de restauration complète sur VM isolée (socle, archive de configuration déchiffrée avec une clé fournie à l'exécution, MongoDB, snapshots OpenSearch en dépôt lecture seule avec `include_aliases=false`, démarrage de Graylog, contrôles de réception), étapes chronométrées, rapport JSON et Markdown avec RTO mesuré et RPO déduit de l'âge des sauvegardes. Garde anti-production avant toute écriture : nom d'hôte, adresse, nœud OpenSearch, volume d'index préexistant, variable `OMNI_RESTORE_DRILL_ISOLATED=1`. Courriel Graylog désactivé, robots et unités systemd jamais réappliqués. Sous-commandes `plan`, `analyser`, et pour le banc VM `jeu-factice` et `sinistre-factice`.
- `tools/omni-backup-inventory.py` : mesure en lecture seule (GET OpenSearch, liste des archives, journal d'`oms-snap-siem`, `systemctl show`) de l'âge, de la fréquence, de la taille des sauvegardes, de la couverture des index et du débit, avec estimation du RTO ; inventaire des index pour l'exercice.
- `docs/exploitation/RESTAURATION-COMPLETE.md` : couverture des sauvegardes, intrants mesurés le 22/11/2026, objectifs RTO/RPO proposés, procédure d'exercice, constats sur les sauvegardes.
- Banc VM : étape facultative `restore_drill` de `tools/test-ubuntu-vm.sh` (variable `OMNI_VM_RESTORE_DRILL=1`, option manuelle `restore_drill` du flux `ubuntu-vm.yml`), sur données factices générées dans la VM.
- Tests hors ligne `tests/test_restore_drill.py` et `tests/test_backup_inventory.py`.
- Validation continue des détections (`tools/omni-detection-validate.py`, lecture seule) : contrôles statiques des définitions actives via l'API Graylog en GET (requête, flux, notifications, champs présents dans le mapping OpenSearch, planification, producteurs `alert_tag`), vivacité par `_count` sur 30 et 7 jours, 18 fixtures synthétiques de détections critiques rejouées en mémoire (`tools/detection-validation/fixtures/`), mode replay réservé à un OpenSearch jetable, rapports JSON et Markdown datés, code retour 2 si une détection critique est cassée. Unité et minuterie hebdomadaires `omni-detection-validate` (lundi 05:30) ajoutées au manifeste, non installées. Documentation `docs/detection/VALIDATION-DETECTIONS.md`, tests `tests/test_detection_validate.py`.
- Sauvegarde MongoDB native quotidienne (`omni-mongo-backup`, timer 02:40) : contrôle d'intégrité, préfixe propre `omni-mongo-*`, archives héritées conservées, purge après succès seulement, verrou et secrets temporaires privés. Le test de restauration possède son processus et son socket Unix privé ; sa comparaison porte sur les comptages de collections.
- `26-graylog-objets-manuels.sh` : versionne les objets Graylog créés à la main en
  production (audit de cohérence du 21/11/2026, écarts G2 et G3). Sont concernées les
  définitions « balayage IKE », « scan applicatif WAF (404) » et « lecture d'un mot de
  passe LAPS », ainsi que les règles `omni-v3-laps-lecture`, `omni-v3-laps-lecture-it`
  et les 15 règles `omni-fp-26-*`, avec leur raccordement aux pipelines. Sources :
  `objets-graylog/` (flux et notifications désignés par titre) et
  `tools/alertes-v2/regles/`. Le script affiche un plan en lecture seule par défaut ;
  `--apply` crée seulement les objets absents. Un objet présent n'est jamais modifié et
  un écart éventuel est signalé. Test hors ligne : `tests/test_graylog_objets_manuels.py`.
- À relancer après `49-expo-port-class.sh`, `49-enrich-lots.sh`, `81-fp-allowlist.sh`
  et `tools/omni-v3/v3_build.py`. Ces scripts réécrivent la source complète de leur
  pipeline et en retirent les règles raccordées par le script 26.
- Fiche de l'incident du 21/11/2026 (tests de la console écrits en production, message de test `soc_admin` conservé dans Graylog) : `docs/archives/INCIDENT-CONSOLE-2026-11-21.md`.

### Modifié

- Dossiers de la console (`update_case`) : historique daté (`history`) des changements de statut, d'assignation et de qualification, et horodatage de clôture (`closed_ts`), pour mesurer le MTTR. Ajout seul, champs ignorés par l'affichage.
- `oms-snap-siem` lit le dépôt et son emplacement dans `/etc/oms-snap-siem.conf` (`DEPOT`, `DEPOT_CHEMIN`, `LIBRE_ARRET_PCT`) au lieu de `graylog_fs` et `/home` codés en dur ; `omni-drift-check` (script 29 et miroir) et `omni-update-status.py` suivent le même dépôt.
- `21-alert-hygiene.sh` ne crée plus « OMNI - Sauvegarde quotidienne SIEM absente (>26h) » (liée à `siem-backup.timer`, arrêté en août 2026) et ne la re-pointe plus : ce PUT `?schedule=true` l'aurait réactivée après sa désactivation. Il crée à la place « OMNI - Snapshot OpenSearch absent (>26h) » (`backup_daily_ok` émis par `oms-snap-siem`) et signale l'ancienne définition si elle est encore active, sans la modifier.
- `oms-maj-siem.timer` : `Persistent=false` confirmé et justifié (`docs/UPDATES.md`, en-tête de `62-auto-security-updates.sh`) : avec le redémarrage automatique conservé, un rattrapage au démarrage ferait une mise à jour suivie d'un redémarrage à une heure imprévue ; les correctifs de sécurité quotidiens d'`unattended-upgrades` ne dépendent pas de ce timer.
- Cert Orchestrator (`99-cert-orchestrator.sh`) : source renommée `cert_orchestrator` (`cert_parc` reste la source PKI Windows de bx-pki2022, 5 035 messages en production) ; index set créé directement en rotation `P1M` x 3, cohérent avec le script 83 et la politique de rétention, au lieu de `P1D` x 90 copié du modèle ; seuil watchdog dédié dans le modèle de `74-source-watchdog.sh` ; documentation des sources et de la rétention.
- `RESTORE.md` : chemin réel du partage SMB et rétention locale de 3 jours, restauration de l'historique couvert par les snapshots (§4 bis), recréation de `/etc/mongod.keyfile` absent de l'archive, dernière ligne `mongodb_uri` retenue, en-tête LUKS absent de l'archive.
- PRA : objectifs RTO/RPO révisés sur mesures (à valider par le RSSI), versions de référence, checklist de réception chiffrée, fréquence des exercices, journal des tests.
- `83-retention-consolidee.sh` augmente uniquement les compteurs de rétention : stratégie et période conservées, aucune réduction de compteur, plan par défaut et relecture avant écriture. Une erreur API arrête l'opération ; le routage reste contrôlé en lecture seule. Tests hors ligne `tests/test_retention_consolidee.py`.
- Redémarrage automatique : la règle retenue est de conserver celui d'`oms-maj-siem` (dimanche 04:30, seulement si `/var/run/reboot-required` existe après contrôles et sauvegarde). `62-auto-security-updates.sh`, le commentaire de `52omni-siem.conf` (script et miroir `deploye/apt`), `docs/UPDATES.md`, le guide d'exploitation et l'inventaire des scripts décrivent ce comportement ; `unattended-upgrades` ne redémarre toujours jamais.
- `39-alert-digest.sh` installe la minuterie du récapitulatif d'alertes du lundi au vendredi à 08:00 (`OnCalendar=Mon..Fri *-*-* 08:00:00`), comme en production.
- Politique de rétention : nombre d'index × période est une estimation ; les mois calendaires et les rotations anticipées empêchent d'en déduire une garantie d'âge minimal.
- Règles versionnées raccordées aux pipelines d'autres scripts : `49-expo-port-class.sh`, `49-enrich-lots.sh` (« OMNI - Exposition reseau »), `81-fp-allowlist.sh` (« OMNI - Allowlist FP ») et `tools/omni-v3/v3_build.py` (« OMNI v3 - Detections et correlation ») incluent eux-mêmes les 17 règles `omni-v3-laps-lecture*` et `omni-fp-26-*` dans la source qu'ils écrivent, à leur étape et à leur place. Inventaire unique `objets-graylog/raccordements.txt`, sources uniques les fichiers `.rule`, logique commune `lib-regles-versionnees.sh` (équivalent Python dans `v3_build.py`, testé identique). Les règles absentes sont créées, les présentes jamais modifiées. Cela remplace la consigne « à relancer après 49, 81 et v3_build.py » de l'entrée `26-graylog-objets-manuels.sh` ci-dessous : il n'y a plus de contrainte d'ordre.
- `26-graylog-objets-manuels.sh` ne crée plus que les trois définitions d'événements ; les règles versionnées et leur raccordement sont seulement contrôlés (script propriétaire indiqué si absent).
- Option `--source-pipeline` (hors ligne, sans API ni écriture) sur ces quatre scripts, et `tools/verif-pipelines-versionnees.sh` qui compare en lecture seule (un GET) la source générée à celle en service. Tests hors ligne : `tests/test_pipelines_versionnes.py`.
- Qualité : `SC2034` n'est plus exclu globalement de ShellCheck (8 constats restants listés dans `tools/shellcheck-baseline.txt`), 16 `cd` vers le répertoire du script sortent explicitement en cas d'échec (SC2164, scripts ponctuels et outils), `lib-graylog.sh` déclare son shell, l'exclusion Ruff `F821` de `seal/graylog/provision_seal.py` est supprimée (import de `NoReturn`), imports inutilisés retirés de quatre fichiers non déployés.

### Corrigé

- `30-backup-config.sh` : l'en-tête LUKS de `/data` est enfin archivé. Le script testait `/dev/sda1` (`/boot/efi`) ; il détecte désormais le périphérique sous-jacent de `/data` (`findmnt` ou `/etc/fstab`, puis `cryptsetup status`, `lsblk`, `/etc/crypttab` ; surcharge `LUKS_DEVICE`), copie l'en-tête par `cryptsetup luksHeaderBackup` dans `luks/data-header.img` de l'archive chiffrée, contrôle sa signature et son UUID et joint `luks/data-header.txt`. Un échec n'empêche pas l'envoi mais émet `backup_config_echec`.
- `30-backup-config.sh` : `mongodb_uri` lu sur la dernière ligne non commentée de `server.conf`, comme Graylog (les 4 lignes de production étaient concaténées) ; arrêt explicite si aucune ligne n'est trouvée.
- `30-backup-config.sh` : archive aussi la clé `keyFile` de `mongod.conf` (`/etc/mongod.keyfile`), la console `/var/www/siem-soc`, `/etc/default/omni-*`, `/etc/omni-*`, `/etc/oms-*` et `/opt/oms-*` (secrets compris, uniquement dans l'archive chiffrée) ; exclut `.venv` et caches (y compris ceux du dépôt canonique) ; seuls les chemins présents sont archivés. L'archive en clair est produite dans le répertoire temporaire (mode 700) et non plus dans `/var/backups/siem`. La vérification de restaurabilité exige chaque élément de reprise présent sur la source (en-tête LUKS, clé MongoDB, nginx de la console, lookups, services) et refuse tout environnement virtuel. Emplacements surchargeables pour les tests (`OMNI_BACKUP_RACINE`, `OMNI_BACKUP_WORK`, `OMNI_BACKUP_MNT`, `OMNI_BACKUP_GELF_URL`), valeurs de production par défaut. Tests hors ligne `tests/test_backup_config.py`.
- `deploye/systemd/oms-snap-siem.timer` : `Persistent=true`, une nuit de snapshot manquée est rattrapée (`omni-backup-config.timer` l'était déjà ; `oms-maj-siem.timer` reste sans rattrapage).
- Détections Sysmon dont les jokers étaient sensibles à la casse (RAT/RMM T1219, T1203, T1204.002, T1518.001, T1547.001, T1555.004, T1572) : expressions régulières à classes de caractères, sans changement de mapping (`85-detections-backlog.sh`, `86-detections-backlog2.sh`). RAT/RMM : 15 -> 315 messages sur 30 jours (AnyDesk sous `Program Files (x86)`, Assistance rapide Windows). La requête source de RAT/RMM retire TeamViewer comme en production (`fp-tuning-2026-09.sh`).
- IP malveillante (Tor / Spamhaus) : `action:accept` ignorait les sessions autorisées terminées en `close`, `timeout`, `server-rst` ou `client-rst` ; la requête exige la destination listée et toute issue autorisée (`13-graylog-alerts.sh`). 6 sessions sortantes du 26/10 au 02/11/2026 n'avaient pas été signalées.
- SEAL HYP-002 : l'étiquette `seal_bf_then_success` n'avait aucun producteur ; détection autonome sur `severity_num` (`seal/detections/provision_detections.py`, nouveau type de condition `sum_ge_min_le`).
- Définitions sans flux : C2 connu, domaine malveillant (`66-threatintel.sh`), comptes exposés, mention ransomware (`72-leak-darkweb.sh`) et fuite GitHub (`70-leak-github.sh`) sont créées sur les flux où leur étiquette peut apparaître.
- Validateur de détections : un joker en casse mixte est aussi signalé ; un champ émis par un robot GELF du dépôt (clé `_champ`) est reconnu comme produit (cas de `TEST_SIEM`, marqueur de test de `seal_sla_poller.py`).
- `docs/exploitation/REPONSE-AUTOMATISEE.md` : l'alerte « SOAR : IP bloquée automatiquement » n'envoie pas de courriel (traçabilité seule, `36-soar.sh`).
- Logstash : drop-in `deploye/systemd/logstash.service.d/50-attente-graylog.conf` (ordre après `graylog-server`, attente bornée de l'input GELF TCP 12202) ; cause des 4 relances du 17/11/2026 : sortie GELF de la collecte SEAL refusée (`ECONNREFUSED`) tant que Graylog n'écoutait pas.
- `omni-ti-feeds` (miroir `deploye/sbin` et script 66) : URLhaus a fermé ses exports publics (HTTP 410 depuis le 21/10/2026, 553 domaines figés) ; le robot utilise l'API authentifiée avec la clé abuse.ch (`ABUSECH_AUTH_KEY`, ou `THREATFOX_AUTH_KEY`) et dit explicitement pourquoi il ignore la source sans clé. Tests `tests/test_ti_feeds.py`.
- `49-enrich-lots.sh` : la règle `omni-extra-10-explicit-cred` était écrite dans un heredoc non cité, si bien que bash remplaçait `$message` par une chaîne vide et `\\` par `\`. Le heredoc est désormais cité ; la source produite est identique à celle en service (vérifié par GET le 22/11/2026).

### Supprimé

- Scripts retirés archivés sous `tools/ponctuel/` sans changement de nom : `15-rapport-hebdo.sh` (doublon de `34-weekly-report.sh`), `22-alert-routing.sh`, `31-retention-iso.sh`, `44-incidents.sh`, `sync-deploye.sh`. Aucun appel actif trouvé en production ni dans le dépôt.

## [2026-11-22] - Administration, déploiement et maintenance

### Ajouté

- Espace Administration de la console : simulation, autorisations, double validation et audit. Son exécuteur et les accès réseau demandent une configuration propre au site ; publier le code ne les active pas en production.
- Déploiement transactionnel des composants maison, contrôle de santé et migration préparée vers le dépôt canonique, avec sauvegardes et retours arrière.
- Inventaire unifié des mises à jour système, pile SIEM et dépendances Python ; procédures distinctes des mises à jour de code.
- Contrôle automatique des liens internes de la documentation
  (`tools/check-doc-links.py`), exécuté par `run-tests.sh`.
- Index unique de la documentation `docs/README.md`, organisé par parcours.
- Inventaire des scripts de provisioning (`docs/reference/SCRIPTS-PROVISIONING.md`),
  feuille de route (`docs/ROADMAP.md`), guide d'exploitation
  (`docs/exploitation/GUIDE-EXPLOITATION.md`), aperçu visuel
  (`docs/demarrage/APERCU-VISUEL.md`).
- Fichiers de gouvernance : `CONTRIBUTING.md`, `SECURITY.md`, `.github/CODEOWNERS`,
  modèle de demande de fusion, modèles de tickets, `.editorconfig`.

### Modifié

- Documentation rangée par usage sous `docs/` (démarrage, architecture,
  exploitation, sécurité et conformité, sources, détection, référence, archives).
- Scripts ponctuels datés regroupés dans `tools/ponctuel/` avec leur statut.
- `README.md` et `README.fr.md` réécrits en présentations concises, avec des
  chiffres relevés en lecture seule et les limites connues.
- `RESTORE.md` : versions de la pile alignées sur MongoDB 8.0, OpenSearch 2.19
  et Graylog 7.2.
- `.gitignore` : copies datées `*.avant-*`, environnements virtuels, rapports
  d'intégration continue.
- Politique linguistique : le français est la langue de référence ; les
  traductions anglaises non maintenues sont archivées dans `docs/archives/en/`.
- `68-iso-evidence.sh` écrit les dossiers de preuves dans
  `docs/archives/preuves-iso/` ; `57-mitre-coverage.sh` écrit le calque
  ATT&CK Navigator dans `docs/detection/`.

### Supprimé

- Index concurrents supprimés : `INDEX-DOCUMENTATION.md`, sa traduction et l'index anglais `00-INDEX.en.md` ;
  `docs/00-INDEX.md` et `docs/DEMARRER.md` deviennent des redirections.
- Émojis retirés de la documentation.

### Corrigé

- Inventaire Python de la console aligné sur `mobile/requirements.txt`, sans imposer les outils de tests navigateur au runtime ; procédure et feuille de route actualisées.
- La migration refuse un plan de déploiement en échec avant toute archive, copie de configuration ou bascule de service.
- Le plan CI utilise un runtime SEAL fictif dans sa racine isolée, sans assouplir le contrôle des exécutables réels.
- Reprise limitée aux collisions de métriques du seul input appartenant au nouveau module ; les erreurs de port, de configuration et les entrées existantes restent inchangées.
- Huit tentatives maximum, couvrant les sept jauges du transport Graylog 7.2.2, avec attente de l'arrêt complet entre les tentatives.
- Recette Ubuntu 26.04 du correctif réussie : trois modules, dix messages normalisés et routés, dix-huit recherches de widgets et sauvegarde réelle.

## [2026-11-21] - Recette native des trois modules

- Révision 2 des packs : schéma natif Graylog 7.2 corrigé sans écraser les anciennes révisions.
- Démarrage du seul input nouvellement créé après arrêt complet et nettoyage du transport ; entrées existantes conservées.
- Recette Ubuntu 26.04 réussie : socle complet, dix messages normalisés et routés, dix-huit recherches de widgets, session console et sauvegarde réelle.
- Filtres de dates du banc de test explicites en epoch millisecondes ; les recherches partielles en échec ne sont plus assimilées à zéro message.
- Préservation des processeurs désactivés dans les étapes pipelines et enrichissement ; sources attendues configurables par site.

## [2026-11-20] — Console et documentation opérateur

- Présentation revue pour `/soc/` : navigation regroupée, recherche visible, titres de page, thèmes clair/sombre et affichage mobile.
- Erreurs et réponses OpenSearch incomplètes distinguées d’un résultat vide ; affichage explicite des indisponibilités, du cache et du dernier rafraîchissement réussi.
- Journaux des modules natifs inclus dans le périmètre configurable des vues globales ; identité du site sans repli sur l’installation de référence.
- Cache PWA versionné avec les nouveaux assets ; publication des dépendances avant la page et le service worker.
- Parcours documentaire unique, guide utilisateur de la console actualisé et procédure de comparaison du code avec les fichiers réellement servis.

## [2026-11-20] — Qualification de l'installation Ubuntu 26.04

- Correction du faux refus des noyaux Ubuntu corrigés, des droits hérités d'un umask privé et de l'attente du PRIMARY MongoDB.
- Notifications natives sans triage optionnel, ordre des phases corrigé, enveloppes API Graylog 7 réessayées correctement et refus explicite des dashboards absents.
- Pare-feu persistant sans effacement des tables tierces ; préflight IPv4 et connectivité adaptés.
- Recette finale obligatoire des services et entités, contrôle des assets HTTPS, workflow VM Ubuntu 26.04 et tests des trois packs sur dix messages synthétiques réellement indexés.
- Première connexion des pipelines et sources facultatives absentes traitées explicitement ; sauvegarde réelle contrôlée, secrets du site inclus et rétention limitée aux sauvegardes natives réussies.

## [2026-11-19] — Installation Ubuntu et correctifs locaux

- Parcours Ubuntu ligne par ligne ; Ubuntu 24.04 conseillé, Ubuntu 26.04 explicitement expérimental avec dépôt MongoDB noble et limites éditeur documentées.
- Génération locale des secrets techniques manquants, valeurs existantes conservées ; aucun contournement CPU, RAM ou noyau incompatible MongoDB.
- Option pour des sources locales examinées sans commit imposé, archive privée du diff, empreinte des fichiers et contrôle à la reprise et entre phases.
- Mêmes options dans le menu SSH, avec tests des choix de plateforme, du noyau, des secrets et d'une installation simulée sans mutation système.

## [2026-11-19] — Administration dans le terminal SSH

- Nouveau lanceur `tools/omni-manager.py`, sans dépendance Python supplémentaire ni serveur web : configuration du site et saisie masquée des secrets, installation/reprise, mises à jour préparées et retour arrière, publication de la console, modules et historique.
- Réutilisation des outils existants avec des arguments contrôlés, confirmation des mutations, verrou partagé, configuration sauvegardée et journaux privés expurgés des secrets connus. Aucun script de purge lancé depuis le catalogue.
- Inventaire de tous les fichiers suivis par composant, avec distinction entre opérations automatisées et extensions nécessitant des accès ou une recette du site ; guide `INTERFACE-ADMINISTRATION.md` et tests de régression.

## [2026-11-19] — Déploiement portable, console et modules d'intégration

- Installation neuve Debian/Ubuntu par phases explicites, versions centralisées et paramètres réseau/stockage conservés sans activation explicite.
- Publication de tous les assets SOC et des routes nginx manquantes, activation du backend géré avec contrôle de santé et retour arrière ; droits et chargement des secrets corrigés pour Docker.
- Mise à jour du code depuis GitHub : révision figée, préparation isolée, détection de conflits, sauvegarde, retour arrière et reprise après interruption ; aucune migration implicite de base.
- Modules Content Pack natifs WatchGuard, UniFi et Palo Alto, dashboards et tests d'exemples ; limites de format et de qualification documentées.
- README, procédures d'installation/mise à jour/intégration et audit de portabilité daté actualisés ; suites hors ligne et CI. Installation de production non modifiée pendant ce travail.

## [2026-11-12] — Soir : console SOC, SOAR, synchronisation du dépôt
- Console SOC : politique de sécurité du contenu stricte (`script-src 'self'`, plus aucun script en ligne). Les scripts sont dans `app*.js` et les anciens gestionnaires `onclick`/`oninput`/`onchange`/`onkeydown`/`onsubmit` sont exécutés par délégation (`app-csp.js`, analyseur restreint, sans `eval`). Le service worker met ces fichiers en cache, versionnés.
- Console SOC : `SOC_ADMINS` renseigné ; notifications push réservées aux administrateurs SOC (abonnement, test et envoi), compte enregistré avec chaque abonnement.
- SOAR : nouvelle détection « balayage IKE » (négociations de phase 1 sans tunnel correspondant, ≥ 10 par IP en 6 h, BX, IV et Lançon). Elle alimente le SOAR en simulation uniquement (`SOAR_DETECTIONS_SIMULATION`) : aucun blocage avant validation.
- Dépôt : `sync-deploye.sh` est retiré. `synchro-manifeste.sh` ne recopie que les fichiers listés dans `manifeste-deploye.txt` après comparaison SHA-256, `scan-depot.sh` bloque les commits contenant un secret ou une mention d'outillage (crochets pre-commit et commit-msg). Aucun commit automatique.
## [2026-11-12] — SOAR, sauvegardes
- Cohérence du SIEM : nouvelle sentinelle `omni-siem-coherence` (toutes les 5 min) qui signale cache fielddata `_id` ou breaker saturés, définitions en échec répété, notifications abandonnées, blocklist SOAR figée ou non lue par les pare-feu, journal Sécurité muet alors que Sysmon arrive ; `indices.id_field_data.enabled=false` côté OpenSearch.
- Tri des alertes : réception asynchrone des notifications Graylog (acquittement immédiat, classement inchangé et en série).
- Performances : base de référence complète et mise en cache pour la détection « nouveau pays », lecture des seuls index FortiGate utiles pour la détection de beaconing (module commun `omni_cible`).
- Routage des messages de surveillance interne vers `omni-interne` ; retrait du jeu d'index Cert Orchestrator (serveur décommissionné).
- Console SOC v3 : application installable (PWA) avec raccourcis, mode hors ligne et notifications push vers la fiche de l'incident ; navigation mobile, filtres et recherche des incidents, titres d'incidents lisibles, états de chargement et d'erreur, thème clair finalisé.
- SOAR : le nombre d'occurrences d'une IP bloquée reprend la valeur calculée par Graylog (`count()`), au lieu d'une valeur fixe tirée du backlog. Aucune décision de blocage ne change.
- SOAR : récapitulatif quotidien en HTML (indicateurs, tableaux par section, liens vers l'historique de chaque IP dans Graylog, commandes de déblocage), avec une version texte de secours.
- Sauvegardes de configuration, certificats et chaîne d'intégrité déplacées vers le partage Informatique (`SIEM-Sauvegardes`, compte de service dédié) ; le repli en accès invité est supprimé.

## [2026-11-11] — Socle, détection v3, tri des alertes, SOAR, console
- Socle mis à jour (Graylog 7.1.12, OpenSearch 2.19.7, MongoDB 8.0.38, Logstash 8.19.25) et mises à jour automatiques hebdomadaires dans des séries épinglées (`oms-maj-siem`).
- Snapshots OpenSearch sélectifs et incrémentaux chaque nuit, avec test de restauration hebdomadaire (`oms-snap-siem`).
- Couche de corrélation v3 : 14 règles, 11 définitions, table des actifs critiques.
- Tri des alertes : signatures de faux positifs, regroupement des alertes ÉLEVÉ, récapitulatif quotidien.
- SOAR remis en route sur les deux sites, avec exclusion automatique des IP légitimes et expiration à 24 h.
- Console SOC : bande « À traiter », page SOAR avec déblocage, page Exploitation. Quatre nouveaux dashboards.
- Correctifs : plugin GELF de Logstash, magasin de confiance hors paquet, robot DHCP (encodage), contrôle de dérive (lecture nftables).

## [2026-06-22] — Couche ML, console enrichie, qualité

### Couche d'apprentissage `oms-ml`
- **Détection d'anomalie non-supervisée** (IsolationForest, log1p + StandardScaler)
  par entité (hôte/compte) — score 0-100 explicable (z-score), réinjecté en GELF
  (`event_source=ml_anomaly`). Déployé (`77-ml-scoring.sh`, timers).
- **Réduction de faux positifs supervisée** : labels = **disposition Vrai/Faux
  positif** posée à la clôture des cas dans la console (boucle fermée) ; s'entraîne
  dès ~30 cas qualifiés.
- **`79-interne-indexset.sh`** : index set dédié `omni-interne` pour le stream
  interne — corrige un angle mort : `ueba_score` (74 k), `collecte_sla`, `siem_health`,
  `xdr_incident`, `ml_anomaly` étaient écrits dans `graylog_0`, invisibles à la console.

### Console SOC — refonte visuelle premium + enrichissements
- Interface premium (glassmorphism, glow, KPI métalliques teintés, micro-interactions).
- **Vue d'ensemble** : cartes **Anomalies ML** + **Risque UEBA** (vrais scores),
  **tendances KPI** (▲/▼ % vs période précédente).
- **Détections** : recherche libre + export CSV + **sévérité réelle** (`risk_severity`
  au lieu de `priority`, absent) + score de risque.
- **Palette ⌘K** : recherche live d'entités → Entité-360.
- **Incidents** : disposition VP/FP (alimente le ML) + verrou `cases.json` (race).
- **Santé** : robots d'auto-supervision (X/Y), couverture de collecte (SLA),
  liste des hôtes go-dark.
- **Graphe d'attaque** filtrable (tactique / volume / centrage d'entité).
- **Entité-360** : score ML + UEBA + pagination des événements.
- **Fuites & Dark Web** : synthèse par catégorie + état « aucune fuite » rassurant.
- **Rapport exécutif** enrichi (posture opérationnelle, entités à risque ML/UEBA).

### Ergonomie / UX / mobile
- Accessibilité clavier (focus visible, focus-trap, ARIA), **toasts** de feedback,
  squelettes de chargement, **cadence de rafraîchissement** réglable, **panneau d'aide
  (?)** + **bascule de densité**.
- **PWA mobile** : onglet **Menace** (parité console : menace, KPI, ML/UEBA, détections).

### Qualité / performance / corrections d'audit
- **Cache mémoire à TTL** sur les agrégations lourdes (matrice ATT&CK ~783→7 ms,
  rapport ~811→3 ms).
- **Suite de tests** hors-ligne (`run-tests.sh`, 23 tests : rédaction + oms-ml).
- **Mode rédaction** (`MOBILE_REDACT`) pour captures anonymisées.
- Corrections de l'audit multi-agents : robots de supervision **versionnés**
  (`61-supervision-robots.sh`), `ensure_lookup` **centralisé** dans `lib-graylog.sh`
  (corrige l'échec silencieux du lookup m365), alerte **`service_stop_securite`**
  (T1489, précurseur ransomware) câblée (`78`), honnêteté de la doc d'intégrité
  (clé HMAC co-localisée).

### Détections prêtes à déployer (NON déployées — `80-detection-extra2.sh`)
3 tripwires 0 faux positif validés par sondage OpenSearch (30 j) : `defender_tamper`
(T1562.001), `schtask_payload` (T1053.005), `amsi_bypass` (T1562.001). À déployer
après revue (relancer ensuite `57` puis `14`).

### Durcissement Graylog (streams / index / dashboards / corrélation / FP)
- **Réduction des faux positifs (`81-fp-allowlist.sh`, déployé)** : pipeline
  « OMNI - Allowlist FP » (stage 25) — pour des motifs bénins **mesurés**
  (scheduled_task 97 % FP, service_install 86 % FP, dont nos propres agents
  winlogbeat/Sysmon), pose `fp_allowlist=true` et **retire `alert_tag`** (l'alerte
  ne tire plus ; l'événement reste indexé). Réversible (lookup `fp-allowlist.csv`).
- **Dashboard « OMNI - Analytics » (`82-...`, déployé)** : 5 onglets — vue
  d'ensemble, anomalies ML, UEBA, couverture & santé, bruit/FP.
- **Corrélation kill-chain (`oms-xdr/rules.yaml`)** : 4 règles multi-signaux
  (vol LSASS→persistance, PowerShell offensif→persistance, usage creds→partage
  admin, LSASS→latéral 6 h) + 6 signaux + fenêtre par signal. Additif, réponse
  dry-run préservée ; live au prochain cycle du timer `oms-xdr`.
- **Rétention consolidée (`83-...`, dry-run par défaut)** : source unique de
  vérité (valeurs = `POLITIQUE-RETENTION.md`) ; corrige le routage
  `OMNI - FortiManager` (graylog_0 → `omni-fortimanager`). `APPLY=1` pour appliquer
  (0 suppression immédiate ; auto-purge au-delà des seuils ensuite).
- **Consolidation alertes Kerberos (`84-kerberoast-dedup.sh`, dry-run par défaut)** :
  kerberoasting/RC4 ×3 et AS-REP ×2 sur le même événement → **5 alertes → 2**
  (source canonique = `73`), garde-fou anti-perte de couverture. Posture AES
  confirmée (zéro RC4/0x17 en 90 j → bruit latent). `APPLY=1` pour consolider.

## [2026-06-14] — Audit de cohérence & nouvelles sources

### Nouvelles sources intégrées (`52-new-sources.sh`)
- **ESET PROTECT** (10.33.50.20) : input Syslog TCP 1515 (514 redirigé par le
  pare-feu), stream « OMNI - ESET », `event_source=eset` (+ tag menace). Index set
  dédié `omni-eset` (rétention 365 j). Alerte « ESET : détection » (route mail).
- **BunkerWeb WAF** (10.33.70.1) : Filebeat → Beats 5044, stream « OMNI - BunkerWeb »
  (routage par `event_source=bunkerweb` posé par Filebeat), tag WAF, champs `http_*`/`waf_*`.
  Index set dédié `omni-bunkerweb` (rétention 90 j), page dashboard « WAF BunkerWeb ».
- **NPS** (10.33.50.247) : déjà mappé côté SIEM (lookup `win-events.csv` 6272/6273/6274
  + alerte ajoutée en 13). Reste à déployer Winlogbeat côté serveur — **pas encore
  remonté côté client**.

### Bugs corrigés (audit de cohérence 2026-06-14)
- **Timestamp FortiGate** : pose du `timestamp` depuis `eventtime` (epoch
  nanosecondes) — règle `omni-forti-05-eventtime`, conforme A.8.17 (synchro horaire).
- **Faux positifs brute-force** : exclusion des comptes machine (`*$`) et des comptes
  de service bruyants (`ninjaone`, `ADSyncMSA_*`) qui échouent en boucle.
- **PowerShell** : exclusion de `wakeup-ssrs.ps1` (tâche légitime récurrente).
- **vSphere brute-force** : exclusion de `vpxuser` / `dcui` / `localhost` ; **(2026-06-15)** exclusion du **bruit des services cluster ESXi** (`clusterAgent`/gRPC « authentication handshake failed », jeton **SAML expiré**) qui était mal tagué `auth_echec` (user/src_ip vides) → générait de **faux brute-force** (par IP nœud ESXi et « (Empty Value) ») et de **faux « Hôte à risque » UEBA** sur l'infra. Corrigé à la racine (`19-vsphere.sh`, règle `omni-vsphere-10-auth-fail`).
- **Déduplication des incidents** : `event_source=incident` routé vers « OMNI - Interne
  SIEM » avec exclusion symétrique côté M365 (anti-dup) — `44-incidents.sh`.
- **cert-check** passé en télémétrie permanente.

### Architecture & rétentions
- **Index sets dédiés** ESET et BunkerWeb (séparation des flux et des rétentions).
- Rétentions actuelles : **FortiGate = 180 j** ; Windows/Sysmon/vSphere/M365/ESET = 365 j ;
  **BunkerWeb = 90 j**. Disque `/data` : 7,3 To.
- FortiGate : `source` = nom de l'équipement (host).

### Routage des alertes (2 tiers — `22-alert-routing.sh`)
- **Teams = firehose** : toutes les alertes.
- **Mail = critique « réveille-moi »** uniquement (compromission confirmée + santé
  SIEM), 26 alertes. Grâce des alertes mail récurrentes relevée à ≥ 60 min.
- Templates mail/Teams enrichis et *source-aware* (script 13).

### Outillage de purge
- `53-purge-clean.sh` : purge des **données** (logs + historique d'alertes) en
  conservant **toute la configuration** (méthode : cycle deflector + suppression des
  anciens index via l'API). Enchaîne sur `54-post-purge-repopulate.sh` (reconstruction
  des ranges, re-fetch M365, relance des robots d'analyse).

### Vérifications (live)
- Dashboard unique **« OMNI - SOC » à 24 pages**, `requires={}` (100 % OSS, pas
  d'Enterprise).
- 144 règles de pipeline, 88 définitions d'événements, 13 streams actifs (dont
  ESET, BunkerWeb, FortiGate).

### Sources & enrichissements ajoutés (suite de journée)
- **Vaultwarden** (BX-VAULTWARDEN, Docker → Filebeat) : stream + pipeline dédiés
  (`55-vaultwarden.sh`), **index set dédié `omni-vaultwarden`** (90 j) — évite
  l'éviction des events internes du SIEM. Kit client `/kit/vw-filebeat.sh`
  (anti-rejeu : `ignore_older 72h` + registry persistant). Détections coffre :
  `vault_auth_fail` (brute-force avec src_ip/compte), MITRE T1555.
- **Attribution DHCP FortiGate** (`56-fortidhcp.sh`) : collecteur API REST
  (token lecture seule) → lookup `omni-dhcp-attribution` (ip→hostname/MAC), timer
  15 min. Le pipeline FortiGate pose `src_hostname`/`dest_hostname` sur les IP
  internes (règles `omni-forti-06-dhcp-src/dest`) → « qui est derrière 10.33.x.x ».
- **Identité unifiée** (`58-identity-correlation.sh`) : champs `identity`
  (compte canonique : sans domaine/upn, minuscules) + `identity_human` (regroupe
  `adm-X`/`svc-X` sous la personne) sur winsec/sysmon/winother/M365/FortiGate/vSphere.
  Page dashboard **« Identité »** (pivot 1 personne, toutes sources). Corrèle déjà
  jmorin/adm-jmorin sur FortiGate+AD+Sysmon.
- **M365 / Entra ID Protection** : ingestion des `riskDetections` (permission
  `IdentityRiskEvent.Read.All`) → `m365_type:risk`, tag `m365_risque` (atRisk),
  alerte mail. A révélé le compte **jaubert** flaggé atRisk (attaque cloud étrangère).
  Détection `m365_brute_externe` (échecs M365 hors-FR, T1110).

### Détection — couverture MITRE & nouvelles règles
- **Carte de couverture MITRE ATT&CK** (`57-mitre-coverage.sh`) : calque
  `docs/detection/mitre-navigator-layer.json` (à charger dans ATT&CK Navigator) + bilan.
  **58 détections / 44 techniques / 12-14 tactiques** (cf. COUVERTURE-MITRE-ATTACK.md).
- **Privilege Escalation comblée** (`47-detections-extra.sh`) : `uac_bypass`
  (T1548.002), `scheduled_task` (T1053.005), `service_install` (T1543.003). +
  `remote_discovery` (T1018), `service_stop_securite` (T1489).
- **Audit fichiers sensibles** (`59-file-audit.sh`) : parse 4663/5145, tags
  `file_sensitive_access` (T1039) / `file_delete_sensible` (T1485), alertes accès/
  suppression de masse (exfil/ransomware). *Armé* — nécessite les SACL côté serveurs.

### Intégrité & chiffrement (piliers ISO)
- **Intégrité des logs** (`60-integrity.sh`, A.8.15) : registre quotidien
  **haché-en-chaîne + signé HMAC** de l'état du corpus, copie hors-SIEM (SMB),
  `omni-integrity --verify` (hebdo + alerte mail si chaîne rompue — testé : une
  falsification est détectée). **Rôle Graylog « OMNI - Analyste (lecture seule) »**
  (moindre privilège, A.8.2).
- **Chiffrement au repos** `/data` (A.8.24/A.5.33) **réalisé le 2026-06-14** :
  **LUKS2 (header inline, aes-xts 512 bits) + déverrouillage TPM2/PCR7**. Reformatage
  chiffré à neuf (config hors `/data` préservée, logs repeuplés). Voir PROCEDURE-CHIFFREMENT-REPOS.md.
- **Supervision du chiffrement** : `omni-self-health` vérifie désormais que `/data`
  (chiffré) est bien ouvert + monté (alerte si le TPM échoue au boot ou si le volume
  est démonté) ; le **header LUKS est inclus dans la sauvegarde config quotidienne**
  (chiffrée, hors-bande `/SIEM/luks/`) → recovery toujours à jour.
- **SOAR avancé** : cadrage des playbooks (isoler hôte / désactiver compte /
  ticket) en attente de l'API NinjaOne. Voir SOAR-PLAYBOOKS.md.

### Audit multi-agent & corrections (cohérence)
- **Halt-traps de pipeline corrigés** (un stage « match either » sans règle
  satisfaite stoppe le pipeline) : Exposition réseau (privflags + 4ᵉ direction
  `transit`), Sources externes (règle pass-through), Identité (pass-through/stage).
- **Veeam** : `veeam_job_echec` = échec **final** du job (eid 190) seulement ;
  les retries transitoires (eid 450, « restore point locked ») → `veeam_job_warn`
  (visu, pas d'alerte). Fini les faux « backup échoué ».
- **SOAR rebranché et rendu permanent** (le sync de 13 le préservait désormais),
  **champs ESET** corrigés (`eset_action`), **boucle Vaultwarden** droppée
  (~9k/j de bruit), **`vw_level`** unifié, **faux « robot en panne »**
  (omni-self-health : calcul d'âge robuste) supprimés. Nouveaux robots supervisés.
- **Mail anti-spam** : 26 alertes critiques en mail (tier « réveille-moi »),
  tout le reste en Teams (firehose). Ajout « Sabotage de l'audit » au mail.

### Hygiène données
- **Purge du rejeu Vaultwarden** : Filebeat avait rejoué tout l'historique
  conteneur (2023→2026). ~23 M docs antidatés purgés de l'index Default `graylog_*`
  **et** ~23 M de l'index Windows `omni-winother_*` (double routage corrigé). Les
  événements internes/Windows réels sont préservés.

## [2026-06-12] — Après-midi — corrections, audit & optimisations

### Bugs corrigés (audit de cohérence)
- **vSphere ne parsait rien** : le stage 0 du pipeline ne contenait que la
  règle « drop bruit » en *match either* — tout message non-bruit était bloqué
  avant la normalisation (0 host/event_action sur 44k logs/15 min). Corrigé.
- **Collecteur M365 Activité planté** (datetime naive vs aware) : crashait à
  chaque exécution après la première → page M365 Activité vide. Corrigé +
  reset des curseurs → 53 000+ events M365 (Exchange/SharePoint/OneDrive/Teams).
- Correctif appliqué au binaire **et** au script source (anti-régression).

### Optimisations
- **vSphere −87 %** : filtrage du bruit stockage ESXi (traces vSAN, osfsd,
  envoy-access, vmkwarning ; application_name vide côté ESXi → filtrage sur le
  contenu). 26k → 3,4k logs/5 min, événements de sécurité conservés.
- **SOAR whitelist** renseignée (IP VPN France légitimes + IP site Ivry),
  testée. À compléter par les IP publiques des sites Bordeaux/PACA.

### Vérifications
- Audit complet : 56 règles pipeline (0 erreur), 0 échec d'indexation, tous
  services/timers OK, 43 définitions, throughput nominal.
- Veeam confirmé fonctionnel (canal « Veeam Backup » + alerte d'échec active).
- Purge des logs (base saine) : collecte temps réel vérifiée sur tous les flux.

## [2026-06-12] — Consolidation

### Sécurité / détection
- **SOAR-light** : blocage automatique d'IP attaquantes (alertes VPN/spraying)
  via threat feed lu par le FortiGate. Sécurités : jamais d'IP interne/whitelist,
  seuil, plafond, expiration 24 h, traçabilité.
- **Compte canari AD** : détection d'intrusion interne (lookup + règle + alerte
  + script de création `New-OmniCanary.ps1` avec SPN piège à Kerberoasting).
- Durcissement VPN FortiGate (géo-restriction FR) — campagne de spraying stoppée.
- UTM FortiGate complet activé sur les 3 clusters (AV/IPS/web/DNS/app-control).

### Résilience / conformité
- Sauvegarde de configuration quotidienne chiffrée (AES-256) externalisée SMB,
  rétention 14 j, auto-surveillée + **PRA** (plan de reconstruction) + RESTORE.md.
- Rétentions alignées ISO (365 j identité/cloud, 180 j réseau/endpoint) + garde-fou
  disque (alerte 80 %, purge d'urgence 88 %).
- **Rapport hebdomadaire automatique** (lundi 08:00) — preuve de revue.
- **Dossier documentaire ISO 27001** : politique, standard, procédure, dossier
  d'architecture, registre de conformité, PRA, LDAPS, synthèse exécutive.
- Authentification console par **LDAPS** restreinte aux Admins du domaine.

### Exploitation
- Intégration **Veeam** (canal Windows) — a révélé un job critique en échec.
- Script d'enrôlement Windows unique `Install-OmniSiem-NinjaOne.ps1`.
- Correctif tempête d'alertes (grâces/clés, détection des comptes de service).
- **Purge des logs** (base saine) après la phase de build/tests.

## [2026-06-13] — UEBA/NDR, MITRE ATT&CK & corrélation d'incidents

### Détection avancée (au-delà de Graylog)
- **Couche UEBA / NDR** (`40-ueba-ndr.sh`) : collecteurs `omni-ueba-volume`
  (anomalie de volume par source, z-score même-heure-du-jour), score, géo, et
  nouveau pays — robots autonomes alimentant le stream interne SIEM.
- **NDR réseau** : détection de scan interne (`48-ndr-scan.sh`, T1046),
  exfiltration/tunneling DNS (`43-ndr-dns.sh`, T1071.004), beaconing, mouvement
  latéral et exfiltration.
- **Reconnaissance LDAP / annuaire** (`49-ldap-recon.sh`) : détection
  BloodHound / SharpHound via le collecteur `omni-ldap-recon`.
- **Corrélation attack-chain → incidents** (`44-incidents.sh`) : le corrélateur
  `omni-incident-correlate` agrège les détections d'une même entité en incidents
  notés (`incident_score`), routés vers « OMNI - Interne SIEM ».
- **Détections complémentaires** (`47-detections-extra.sh`) : 5 règles issues de
  la revue multi-agent, dans un pipeline dédié.

### Cartographie & MITRE
- **Mapping MITRE ATT&CK + score de risque** (`37-mitre-attack.sh`) :
  `alert_tag` → technique (Txxxx) / tactique / sévérité / score, via lookup CSV.
- **Carte cyber temps réel** (`42-carte-cyber.sh`) : arcs de flux animés générés
  hors Graylog (`omni-geo-flux` → `flux.json`).
- **Exposition Internet & classe de port à risque** (`49-expo-port-class.sh`) :
  enrichissement des flux FortiGate.

### Exploitation & supervision
- **Auto-supervision des robots** (`46-self-health.sh`) : `omni-self-health`
  route `event_source=siem_health` → INT, timer 30 min (alerte « Robot d'analyse
  en panne »).
- **Rapport exécutif mensuel** (`45-monthly-report.sh`) : HTML + PDF (weasyprint),
  envoi le 1er du mois à 06:00, archivé sous `/var/www/siem-kit/rapports/`.
- **Ventilation des échecs M365 par code Azure AD** (`48-m365-fail-codes.sh`).

## [2026-06-11] — Mise en production initiale
- Build du SIEM : modèle (index/streams/inputs), 55 règles pipeline,
  détections, dashboard 24 pages, TLS bout-en-bout, collecte M365, FortiAnalyzer,
  vSphere, déploiement des agents Windows (NinjaOne + GPO).

---
*Tenir à jour à chaque évolution. Référence technique détaillée : `docs/archives/CONTEXT.md`
(racine du dépôt). Voir aussi `INTEGRATION-SOURCES.md`, `INVENTAIRE-SOURCES.md`,
`POLITIQUE-RETENTION.md` et `REPONSE-AUTOMATISEE.md` dans `docs/`.*
