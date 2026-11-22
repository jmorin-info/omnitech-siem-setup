# Journal des modifications

Toutes les évolutions notables du dépôt et de la plateforme SIEM OMNITECH sont
consignées ici. Le format suit les principes de
[Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) : entrées les plus
récentes en premier, regroupées par date de livraison, sections « Ajouté »,
« Modifié », « Corrigé », « Supprimé » pour les nouvelles entrées. Le dépôt ne
publie pas de versions numérotées : chaque livraison est identifiée par sa date.

Les entrées antérieures au 21/11/2026 sont reprises de l'ancien journal
tenu dans le dossier `docs` sans réécriture ; elles sont rédigées en liste libre.

## [Non publié] - Décisions d'exploitation du 22/11/2026

### Modifié

- `83-retention-consolidee.sh` ne modifie plus que les réglages des jeux d'index (rotation temporelle héritée, nombre d'index conservés) appliqués aux index futurs : plan par défaut, écriture seulement avec `--apply`, aucune suppression ni réduction d'index existants, aucune réduction de rétention (avertissement explicite), refus si moins d'index conservés que d'index présents ; le routage des streams n'est plus que contrôlé. Tests hors ligne `tests/test_retention_consolidee.py`.
- Redémarrage automatique : la règle retenue est de conserver celui d'`oms-maj-siem` (dimanche 04:30, seulement si `/var/run/reboot-required` existe après contrôles et sauvegarde). `62-auto-security-updates.sh`, le commentaire de `52omni-siem.conf` (script et miroir `deploye/apt`), `docs/UPDATES.md`, le guide d'exploitation et l'inventaire des scripts décrivent ce comportement ; `unattended-upgrades` ne redémarre toujours jamais.
- `39-alert-digest.sh` installe la minuterie du récapitulatif d'alertes du lundi au vendredi à 08:00 (`OnCalendar=Mon..Fri *-*-* 08:00:00`), comme en production.
- Politique de rétention : la rétention effective s'exprime en nombre d'index × période de rotation (P1D ou P1M selon les sources).

### Ajouté

- Fiche de l'incident du 21/11/2026 (tests de la console écrits en production, message de test `soc_admin` conservé dans Graylog) : `docs/archives/INCIDENT-CONSOLE-2026-11-21.md`.

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
