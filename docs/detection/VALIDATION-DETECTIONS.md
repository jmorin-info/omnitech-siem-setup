# Validation continue des détections

Outil : `tools/omni-detection-validate.py` (bibliothèque standard Python, aucune dépendance).
Fixtures : `tools/detection-validation/fixtures/*.json`. Tests : `tests/test_detection_validate.py`.
Unité hebdomadaire : `deploye/systemd/omni-detection-validate.service` et `.timer` (non installées).

## Objet

Compter les définitions d'événements ne prouve pas qu'elles détectent encore quelque chose.
L'outil vérifie chaque semaine, sans rien écrire en production, que les définitions actives
de Graylog (type `aggregation-v1`) :

1. sont **bien formées** : requête analysable et acceptée par OpenSearch, flux et index sets
   présents, notifications existantes, planification cohérente, tâche planifiée active ;
2. portent sur des **champs réellement indexés** dans les index des flux visés ;
3. **voient encore des messages** sur une fenêtre longue (30 jours) quand leur source est active ;
4. pour une sélection de détections critiques, **déclenchent toujours** sur un événement
   synthétique minimal et **restent muettes** sur des cas négatifs (exclusions, seuils,
   regroupements, fenêtres).

Ce que l'outil ne prouve pas : la normalisation amont. Les fixtures décrivent le message tel
qu'il est indexé après les pipelines (champ `alert_tag` déjà posé, par exemple). La régression
d'une règle de pipeline est couverte indirectement par le contrôle des producteurs (la règle
existe et son pipeline est connecté) et par la vivacité, pas par les fixtures. L'exécution de
scénarios d'attaque réels (Atomic Red Team, Caldera) reste hors périmètre.

## Garanties de lecture seule

| Cible | Appels émis |
|---|---|
| API Graylog | `GET /events/definitions` (paginé, contexte du planificateur inclus), `GET /events/notifications`, `GET /streams`, `GET /system/indices/index_sets`, `GET /system/pipelines/rule`, `GET /system/pipelines/pipeline`, `GET /system/pipelines/connections` |
| OpenSearch | `GET /<index>/_mapping/field/<champs>`, `GET /<index>/_validate/query`, `POST /<index>/_count`, `POST /gl-events_*/_search` (agrégation, `size: 0`) |

La classe `ClientOpenSearch` refuse toute méthode autre que GET hors `_count` et `_search`
(test `test_client_opensearch_refuse_les_ecritures`). Le client Graylog n'expose que GET.
Aucun message n'est envoyé à Graylog (ni GELF, ni syslog, ni beats). Les rapports ne sont
écrits que si `--sortie` est fourni ; sans option, le rapport Markdown est affiché.

Les comptages utilisent `terminate_after` (10 000 par défaut, option `--plafond`) et l'option
`--pause` espace les requêtes ; le passage complet du 22/11/2026 a duré entre 18 s et 100 s
selon l'état des caches.

## Utilisation

```
# Contrôle complet (statique, vivacité, fixtures rejouées sur les définitions en production)
python3 tools/omni-detection-validate.py --vars /opt/omni-siem/repository/00-vars.env \
        --sortie /chemin/vers/rapports

# Fixtures seules, hors ligne, contre l'instantané embarqué (aucun réseau)
python3 tools/omni-detection-validate.py --hors-ligne

# Sous-ensemble de contrôles
python3 tools/omni-detection-validate.py --controles statique,fixtures
```

Options utiles : `--fenetre-jours` (30), `--recente-jours` (7), `--priorite-critique` (3),
`--json` (rapport JSON sur la sortie standard), `--top` (15), `--exceptions FICHIER`.

Code retour : `0` aucune détection critique cassée ; `2` au moins une détection critique
cassée ; `3` erreur d'usage ou API Graylog injoignable (validation impossible).

Une détection est **critique** si sa priorité Graylog est supérieure ou égale à
`--priorite-critique` (3 par défaut) ou si une fixture la déclare critique.

## Contrôles statiques

| Contrôle | Gravité | Constat |
|---|---|---|
| requete | critique | requête non analysable localement, refusée par `_validate/query` ou par `_count` |
| requete | moyenne | terme sans champ (dépend du champ par défaut d'OpenSearch) |
| requete | faible | joker positif sur un champ keyword de type chemin, ligne de commande ou nom DNS (le joker garde la casse écrite, minuscules comme casse mixte ; correctif : expression régulière à classes, voir « Correctifs de novembre 2026 ») |
| flux | critique | flux inexistant, désactivé, sans index set, ou aucun flux visé n'existe |
| flux | élevée | index set visé vide sur toute la rétention (source jamais reçue) |
| notifications | critique | notification référencée inexistante |
| notifications | élevée / moyenne | aucune notification (élevée si la détection est critique) |
| planification | élevée | `search_within_ms` < `execute_every_ms` (messages jamais évalués) ; tâche absente ; dernière exécution en retard de plus de deux périodes |
| planification | critique | planificateur dans un état autre que `runnable`/`running`, ou définition non planifiée |
| champs | critique | la requête ne peut jamais être satisfaite : champ absent de tous les mappings des index visés et posé par aucune règle de pipeline connectée ; idem pour un champ de regroupement ou de série |
| champs | élevée | même situation, mais le champ est posé conditionnellement par une règle connectée (lookup, enrichissement) : jamais observé, panne non démontrée ; ou branche OR morte |
| champs | faible | exclusion (`NOT`) sur un champ jamais indexé : exclusion inopérante |
| producteur | élevée | valeur `alert_tag`/`v3_tag` posée par une règle qui n'est dans aucun pipeline connecté |
| producteur | moyenne | aucune règle de pipeline ni aucun robot du dépôt ne contient la valeur littérale |
| inventaire | moyenne | titre porté par plusieurs définitions actives |

Statut d'une définition : **CASSEE** si au moins un défaut critique, **DEFAUT** si au moins un
défaut élevé ou moyen, **OK** sinon.

La satisfiabilité est calculée en logique à trois valeurs sur l'arbre de la requête (un terme
sur un champ absent est faux ; `a OR b` reste possible si `b` existe). Le producteur d'un
champ est cherché dans les `set_field("champ"` des règles connectées, puis dans les robots du
dépôt sous la seule forme d'une clé GELF additionnelle (`"_champ":` ou `["_champ"]`) : le nom
nu d'un champ apparaît aussi dans le code qui le lit, une recherche littérale serait
trompeuse. Exemple : `TEST_SIEM`, émis par `seal_sla_poller.py` en mode test seulement.

## Vivacité

Pour chaque définition, la requête est traduite en requête OpenSearch :

```
{"query": {"bool": {
   "must":   [{"query_string": {"query": "<requête Graylog>", "allow_leading_wildcard": true, "analyze_wildcard": true}}],
   "filter": [{"range": {"timestamp": {"gte": "now-30d"}}}, {"terms": {"streams": ["<ids des flux>"]}}]}}}
```

sur les index `<préfixe>_*` des index sets des flux visés (tous les index de messages si la
définition ne vise aucun flux, sans filtre de flux). Une requête vide ou `*` devient
`match_all`. Les flux visés sont comptés sur la fenêtre récente, et les événements émis par
chaque définition sont comptés dans l'index set Events (agrégation sur `event_definition_id`).

| État | Signification |
|---|---|
| vivante | correspondances sur la fenêtre récente (7 j) |
| rare | correspondances sur 30 j, aucune sur 7 j |
| muette | source active, aucune correspondance sur 30 j : attaque absente **ou** détection morte |
| source_absente | les flux visés n'ont reçu aucun message depuis 7 j (défaut élevé) |
| battement_absent | détection d'absence (condition `<`) dont le battement manque depuis 7 j (défaut élevé) |
| non_mesuree | défaut critique de flux ou de requête, ou erreur de comptage |

« Muette » n'est pas un défaut : un compte canari ou un DCSync ne doivent rien voir. Une
détection muette dont l'activité est attendue peut être déclarée dans le fichier d'exceptions
(`vivacite_attendue`), elle devient alors un défaut élevé.

Limites de la traduction :

- la requête est transmise telle quelle ; les options exactes passées par Graylog à
  `query_string` (au-delà de `allow_leading_wildcard_searches = true`, vérifié dans
  `server.conf`) ne sont pas reproduites à l'identique ;
- les paramètres de requête (lookup) et les filtres additionnels ne sont pas traduits (aucune
  définition active n'en utilise au 22/11/2026, information signalée si cela change) ;
- la fenêtre ne tient pas compte de la planification cron ;
- `terminate_after` borne les comptages : une valeur égale au plafond signifie « au moins ».

## Fixtures

Une fixture par détection, au format JSON :

```
{
  "titre": "<titre exact de la définition>",
  "critique": true,
  "mitre": "T1003.006",
  "justification": "<pourquoi cette détection est prioritaire>",
  "capture": "<date et origine de l'instantané>",
  "definition": { "query", "streams" (titres), "group_by", "series", "conditions",
                  "search_within_ms", "execute_every_ms" },
  "cas": [ {"nom": "...", "attendu": {"evenements": 1, "cles": [["jdupont"]]},
            "documents": [{"flux": "OMNI - Windows Security", "age_s": 60, "repeter": 10, "pas_s": 20,
                           "champs": {"event_id": "4625", "user": "user{i}"}}]} ]
}
```

`repeter` duplique le document, `pas_s` vieillit chaque copie, `{i}` est remplacé par le rang
de la copie. Chaque fixture contient au moins un cas positif et un cas négatif (vérifié par
les tests).

L'évaluateur hors ligne reproduit : la fenêtre `search_within_ms`, le filtre de flux, la
sémantique Lucene de `query_string` (clauses MUST/SHOULD/MUST_NOT, requête purement négative
complétée par `match_all`, échappements, jokers, phrases, intervalles, comparaisons,
`_exists_`), la sensibilité à la casse des champs keyword, l'analyse standard de `message`,
le regroupement (pas de seau si un champ de regroupement manque), les séries `count`,
`card`, `sum`, `min`, `max`, `avg` et les conditions composées (`&&`, `||`). Une détection
d'absence sans regroupement produit un événement sur une fenêtre vide, comme Graylog.

En exécution complète, chaque fixture est rejouée **en mémoire** sur la définition lue en
production : un cas en échec rend la définition CASSEE (critique), une différence avec
l'instantané est signalée pour mise à jour de la fixture. Les tests hors ligne rejouent
l'instantané et vérifient en plus, par mutation, qu'une requête cassée, une exclusion perdue
ou un seuil modifié font bien échouer la fixture.

### Sélection (21 détections)

Critère : impact maximal en cas de panne silencieuse, en couvrant la diversité des
mécanismes du moteur (étiquette seule, exclusions, seuil, cardinalité, condition composée,
absence, requête vide, définition sans flux, définition sans agrégation, deux flux).

| Fichier | Détection | Pourquoi |
|---|---|---|
| 01-compte-canari | COMPTE CANARI touché | leurre AD, zéro faux positif, filet de dernier recours |
| 02-dcsync | DCSync suspect | Tier 0, définition sans agrégation |
| 03-ntds-dump | Extraction NTDS.dit | compromission totale du domaine |
| 04-lsass | Accès mémoire LSASS | exclusions (NinjaOne, WerFaultSecure) à tester dans les deux sens |
| 05-kerberoasting | Kerberoasting | précurseur d'escalade |
| 06-ransomware-shadow | Suppression des clichés instantanés | chiffrement imminent |
| 07-inhibit-recovery | Destruction des sauvegardes | chiffrement imminent |
| 08-journaux-effaces | Effacement de journaux Windows | anti-forensique |
| 09-force-brute | Force brute (>= 10 / compte) | seuil, regroupement, liste d'exclusions |
| 10-force-brute-succes | Force brute suivie d'un succès | condition `&&` sur deux séries `sum` |
| 11-pulverisation-mots-de-passe | Password spraying | série `card` |
| 12-admin-hors-heures | Connexion adm-* hors heures | requête la plus complexe, deux flux |
| 13-m365-legacy-auth | Authentification legacy M365 | contournement MFA, valeurs entre guillemets |
| 14-source-silencieuse | Source de collecte silencieuse | SIEM aveugle, définition sans flux |
| 15-backup-config-absent | Backup config absent | détection d'absence (`<`) |
| 16-silence-winlogbeat | Silence Winlogbeat | requête vide et absence |
| 17-rat-rmm | Logiciel d'accès distant (T1219) | constaté en production, exclusions hôte et agent |
| 18-vpn-etranger | VPN monté depuis l'étranger | termes échappés, exclusion par pays |
| 19-ip-malveillante-sortante | IP malveillante (Tor / Spamhaus) | issues de session FortiGate (accept, server-rst), entrant exclu |
| 20-seal-hyp002-force-brute-succes | SEAL HYP-002 | condition `&&` sur `sum` et `min`, regroupement compte et site |
| 21-seal-sla001 | SEAL SLA-001 | exclusion du marqueur de test du poller (`TEST_SIEM`) |

Les fixtures 17, 19 et 20 décrivent la requête **cible** de `tools/maj-detections-2026-11.py`.
Tant que cet outil n'a pas été appliqué en production, l'exécution complète les rejoue sur
l'ancienne requête de production : leurs cas de régression échouent et les trois définitions
apparaissent CASSEE (code retour 2). C'est le comportement attendu ; il disparaît après
`--apply`. Le test `test_fixtures_novembre_echouent_sur_l_ancienne_requete` le vérifie.

### Ajouter ou mettre à jour une fixture

1. Lire la définition (`api_get /events/definitions?query=<titre>`), recopier `query`,
   `streams` (titres des flux), `group_by`, `series`, `conditions`, `search_within_ms`,
   `execute_every_ms` dans `definition`, et dater `capture`.
2. Écrire au moins un cas positif et un cas négatif représentatifs des exclusions.
3. `python3 tools/omni-detection-validate.py --hors-ligne`, puis la suite de tests.

## Mode replay (OpenSearch jetable)

`--replay URL --replay-jetable-confirme` indexe les documents de chaque cas dans un index
temporaire `omni-detval-replay-*` (chaînes en keyword, `message` en texte standard,
`timestamp` au format Graylog), exécute la requête traduite et compare l'ensemble des
documents trouvés par OpenSearch à celui de l'évaluateur hors ligne, puis supprime l'index.
Il valide donc la fidélité de l'évaluateur, pas la production.

Refus systématique si l'URL est la boucle locale sur le port 9200, si le cluster s'appelle
`graylog` ou s'il contient des index `gl-*`, `graylog_*` ou `omni-*`. Ce mode n'a pas été
exécuté : aucune instance jetable n'est disponible sur le serveur, et il ne doit pas l'être
sur la production. Il est couvert par un test hors ligne avec un faux OpenSearch. Procédure
prévue : instance OpenSearch de même version (2.19) sur une VM isolée, puis lancer l'outil
avec son URL.

## Rapport

Avec `--sortie DIR` : `validation-detections-AAAAMMJJ-HHMM.json` et `.md`, et les liens
`dernier.json` / `dernier.md`. Aucune rotation n'est faite (environ 52 paires par an).

Le JSON contient `resume` (compteurs OK / en défaut / cassées / mortes, vivacité, fixtures),
`definitions` (statut, criticité, vivacité, défauts, résultats des fixtures, requête, flux),
`hors_perimetre` (définitions non `aggregation-v1`, fixtures sans définition active) et
`erreurs` de collecte. Le Markdown présente la synthèse, les 15 plus graves, les définitions
cassées et en défaut, et la liste des définitions sans correspondance.

## Exceptions

Fichier optionnel `tools/detection-validation/exceptions.json` (ou `--exceptions`) :

```
{"exceptions": [
  {"titre": "<titre exact>", "ignorer": ["notifications"], "motif": "<justification>"},
  {"titre": "<titre exact>", "vivacite_attendue": true, "motif": "<justification>"}
]}
```

Un contrôle ignoré reste tracé dans le rapport (défaut `info` « exception » avec le motif).
Le fichier livré ne contient que des décisions déjà prises et tracées dans le dépôt :
quatre définitions non alertantes à dessein (contrôle `notifications`) : connexion d'un
compte adm-* hors heures et enregistrement d'appareil ou de méthode MFA M365 (arbitrage RSSI
du 23/09/2026, `tools/ponctuel/fp-tuning4-2026-09-23.sh`), blocage SOAR automatique
(traçabilité sans doublon de notification, `36-soar.sh`) et SEAL EVT-001 (sévérité Info du
catalogue SEAL). Retirer une entrée réactive le contrôle.

## Exécution hebdomadaire

`omni-detection-validate.timer` lance le service le lundi à 05:30 (délai aléatoire de 15 min,
rattrapage au démarrage). Le service s'exécute depuis le dépôt de référence
`/opt/omni-siem/repository` et écrit dans `/var/lib/omni-detection-validate`
(`StateDirectory`). Un code retour 2 met l'unité en échec, visible par
`systemctl --failed`. L'unité n'est pas encore surveillée par `omni-self-health` (liste
`JOBS`) : l'y ajouter est une décision à prendre.

## Premier passage en production (22/11/2026, lecture seule)

214 définitions : 201 actives contrôlées, 12 désactivées et 1 définition système
(`system-notifications-v1`) non contrôlées. 193 OK, 8 en défaut, 0 cassée ; 18 fixtures sur 18 vérifiées sur les définitions en
production. Vivacité : 96 vivantes, 25 rares, 79 muettes, 1 source absente. Les défauts et les
recommandations sont consignés dans le rapport daté produit par l'outil ; ils ne sont pas
recopiés ici pour ne pas figer un état qui évolue.

## Correctifs de novembre 2026

Chantier `correctifs-detections` : correction dans le dépôt des défauts trouvés par le premier
passage, et outil de mise à jour de la production `tools/maj-detections-2026-11.py` (plan en
lecture seule par défaut). Cibles : `tools/maj-detections-2026-11/cibles.json`. Les comptages
ci-dessous sont des `_count` OpenSearch sur 30 jours, mesurés le 22/11/2026 avec la traduction
de requête de l'outil de validation.

### Jokers sensibles à la casse

Les champs Sysmon (`winlogbeat_winlog_event_data_Image`, `ParentImage`, `Details`,
`TargetObject`), `command_line` et `dns_query` sont des `keyword` sans normaliseur : un joker
garde la casse écrite. Constat : `Image:*anydesk*` ne trouve pas
`C:\Program Files (x86)\AnyDesk\AnyDesk.exe`. Le validateur signalait 28 termes répartis sur
4 définitions ; l'inventaire complet des jokers positifs avec lettres sur ces champs en donne 7
(les jokers des exclusions `NOT` ne sont pas modifiés : les élargir masquerait davantage).

Technique retenue : expression régulière Lucene à classes de caractères
(`/.*[aA][nN][yY][dD][eE][sS][kK].*/`). Elle est insensible à la casse, ne touche ni au
mapping ni aux pipelines, et trouve par construction au moins tout ce que trouvait le joker.
Écartées : variantes de casse explicites (`*anydesk* OR *AnyDesk*`, incomplet : `Anydesk`,
`ANYDESK`) ; normaliseur `lowercase` sur ces champs (modification des modèles d'index, effet
au prochain roulement seulement, risque sur les autres usages du champ) ; champ en minuscules
posé par pipeline (coût de traitement sur tout Sysmon) : chantier séparé, non engagé.

| Détection | Avant | Après | Écart expliqué |
|---|---|---|---|
| Logiciel d'accès distant (RAT/RMM) T1219 | 15 | 315 | 300 lancements manqués : AnyDesk.exe sous `Program Files (x86)`, `Downloads`, `WinGet` (au moins 8 postes), Assistance rapide Windows (`MicrosoftCorporationII.QuickAssist`, 58) |
| Persistance autorun (Run key) T1547.001 | 1 | 11 | `/StartHidden` (client Tixeo, 6, faux positif probable) et `-WindowStyle Hidden` (installation Notepad++, 4) |
| Reconnaissance antivirus T1518.001 | 0 | 1 | une commande `pwsh` d'un poste d'administration |
| Vol Credential Manager T1555.004 | 29 | 29 | aucun |
| Binaire déposé via archiveur T1204.002 | 38 | 38 | aucun |
| Navigateur lance un interpréteur T1203 | 0 | 0 | aucun |
| Tunnel ngrok/cloudflared T1572 | 0 | 0 | aucun |

### Autres correctifs

- **IP malveillante (Tor / Spamhaus)** : les 1 761 messages `threat_intel` et `accept` sont
  tous entrants (IP source publique listée ; la recherche threat-intel n'interroge que les IP
  publiques, `src_ip_reserved_ip` n'est vrai que pour une IP privée). Leur exclusion est voulue
  (commit 147ed8d). Le défaut réel : FortiGate journalise une session autorisée en `accept` ou
  `start` puis `close`, `timeout`, `server-rst` ou `client-rst` ; `action:accept` seul ignorait
  6 sessions sortantes autorisées (10.33.60.29 vers des IP d'hébergeur listées, du 26/10 au
  02/11/2026, politique 84). Cible : `dest_ip_threat_indicated:true` et toutes les issues
  autorisées ; 0 -> 6 messages.
- **SEAL HYP-002** : aucun producteur de `alert_tag:seal_bf_then_success`. Une règle de
  pipeline ne peut pas exprimer une séquence ; la définition est rendue autonome sur
  `severity_num` (5 pour `ConnectionFailure`, 0 pour `Connection`, posé par
  `12-seal-audit.rule`) : `sum >= 25` et `min <= 0` par compte et site sur 15 min. Rejeu sur
  30 jours : aucun déclenchement. Limite : `actor_login` n'est pas normalisé (casse, préfixe de
  domaine `BX-QA-SEAL-VM\`), une normalisation par pipeline est un chantier séparé.
- **SEAL SLA-001 / SLA-002** : `TEST_SIEM` est bien le marqueur du poller
  (`seal_sla_poller.py` ajoute `_TEST_SIEM` aux marqueurs émis quand
  `SEAL_SLA_INCLUDE_TEST=1`, désactivé en production). L'exclusion est correcte mais n'a jamais
  servi : le validateur reconnaît désormais ce producteur GELF. Requête inchangée. Les 8
  événements SLA-001 de 30 jours viennent tous de `bx-qa-seal-vm` (banc de test) : exclure ce
  site des SLA est une décision d'exploitation, non prise ici.
- **SEAL ZON-001** : la table `omni-seal-zone.csv` ne contient que son en-tête faute de vue
  `vw_SealZone_SIEM` (étapes SQL opérateur, `seal/docs/ZONES-TOPOLOGIE.md`) ; le plan des zones
  physiques manque. La source la déclare parquée, la production l'avait activée : désactivation
  explicite. Gabarit des 127 portes vues en 30 jours : `seal/graylog/omni-seal-zone.gabarit.csv`,
  générateur `seal/graylog/gabarit_zone_portes.py`.
- **Définitions sans flux** : C2 connu, domaine malveillant (URLhaus), comptes exposés,
  fuite GitHub et mention ransomware rattachés aux flux où leur étiquette peut exister
  (pipeline « OMNI - Threat Intel IOC » ; GELF HTTP 12201 vers le flux OMNI - M365 pour
  `leak_intel`). Comptages inchangés.

### Notifications SEARCH_ERROR (gl-system-events, 30 jours)

52 notifications système, dont 51 `SEARCH_ERROR` et une `OUTDATED_VERSION`. Aucune n'est due
à une requête invalide (toutes les requêtes passent `_validate/query`) :

| Date | Nombre | Cause |
|---|---|---|
| 17/11 14:21 | 36 | file de recherche OpenSearch saturée (`rejected_execution_exception`, 6 121 tâches en attente pour 1 000 places) ; 10 de ces échecs sont remontés sans message (`null`) |
| 15/11 03:xx | 11 | échecs simultanés sans message (`null`), toutes sources confondues |
| 06/11 00:17 | 2 | idem (MFA fatigue, tunnel ngrok) |
| 11/11 19:56 et 20:xx | 2 | disjoncteur `fielddata` sur le champ texte `source` (4,8 Go pour 4,7 Go) : Port-flap Aruba, échec logon service/batch |

Les rafales simultanées désignent la plateforme, pas les définitions. Le disjoncteur
`fielddata` vient des agrégations sur `source` (champ `text` avec `fielddata: true`) : 12
définitions actives regroupent par `source`, ainsi que des tableaux de bord. Remplacer
`source` par un champ `keyword` (`host`, valeurs identiques pour Aruba et vSphere ; FQDN pour
Windows) changerait la valeur de clé des événements et doit être fait avec
`97-enrich-alerts.sh` et les tableaux de bord : chantier séparé, comme le plafonnement de
`indices.fielddata.cache.size`.

### Appliquer en production

```
python3 tools/maj-detections-2026-11.py --vars /opt/omni-siem/repository/00-vars.env
python3 tools/maj-detections-2026-11.py --vars /opt/omni-siem/repository/00-vars.env \
        --apply --sauvegardes /var/backups/omni-maj-detections-2026-11
python3 tools/maj-detections-2026-11.py --vars /opt/omni-siem/repository/00-vars.env \
        --rollback --sauvegardes /var/backups/omni-maj-detections-2026-11
```

`--apply` sauvegarde chaque définition avant de l'écrire (la première sauvegarde est
conservée si l'outil est relancé), applique par PUT une définition à la fois en conservant
son état de planification, relit et compare, et s'arrête au premier échec. Une valeur de
production différente de celle relevée le 22/11/2026 (`attendu_avant`) est une dérive : la
cible est sautée sauf `--forcer`. Seule écriture d'état : la désactivation de ZON-001
(`PUT .../unschedule`).
