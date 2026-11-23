# Utiliser la console SOC

La console se trouve à `https://VOTRE_FQDN/soc/`, sur le port HTTPS 443.
Utiliser un compte autorisé par Graylog ; les comptes AD fonctionnent lorsque
LDAPS est configuré sur le site. L’accès réseau dépend des ACL de votre installation.
Pour installer la console ou résoudre un `Not Found`, suivre
[le guide de déploiement](CONSOLE-DEPLOIEMENT.md).

## Trouver les bonnes informations

La navigation regroupe les pages en quatre rubriques. Sur mobile, utiliser les
onglets inférieurs et le menu pour accéder à l’ensemble des pages.

| Rubrique | Pages et usage |
|---|---|
| Pilotage | **Vue d’ensemble** : indicateurs et activité ; **Incidents** : cas corrélés et suivi ; **Détections** : événements tagués, filtres et export CSV. |
| Investigation | **Entités** : dossiers comptes et machines ; **ATT&CK** : techniques observées ; **Graphe d’attaque** et **Jumeau d’attaque** : relations et exposition ; **Playbooks** : guides de traitement. |
| Visibilité | **Endpoint (EMS)**, **Réseau & Infra**, **Carte mondiale**, **Fuites & Dark Web** : informations des connecteurs configurés. |
| Administration | **Santé & Collecte** : sources et fraîcheur ; **SOAR** : actions autorisées ; **Exploitation SIEM** : état opérationnel ; **Administration** (administrateurs SOC uniquement) : rôles, faux positifs, SOAR, détections, paramètres, supervision, journal d'audit ; **Déploiement** : enrôlement ; **Rapport** : synthèse imprimable. |

Les pages des extensions restent dépendantes de leur configuration. Le profil
d’installation de base n’active pas à lui seul ML, UEBA, XDR, les scans ou le SOAR.
Un indicateur vide ne prouve pas que sa source est surveillée.

## Rechercher et ouvrir un dossier

La barre de recherche visible et **Ctrl/Cmd + K** ouvrent la recherche globale.
Saisir un compte, une IP, une machine ou une expression, puis choisir la navigation,
une entité ou la recherche dans les journaux. Cette dernière interroge le backend,
avec une fenêtre par défaut de deux jours ; les filtres de la page Détections
restent propres à cette page.

Les résultats et indicateurs cliquables permettent d’ouvrir les événements ou
le dossier de l’entité. Utiliser **Échap** pour fermer une fenêtre,
**Tab** pour parcourir les commandes et **Entrée/Espace** pour activer une commande.
**?** ouvre l’aide et les raccourcis.

Les modules WatchGuard, UniFi et Palo Alto disposent aussi de leurs dashboards
dans **Graylog > Dashboards**. Ils n’ajoutent pas automatiquement une nouvelle page
spécialisée à `/soc/`. Leurs événements normalisés peuvent alimenter les vues
globales et la recherche selon `SOC_LOG_INDICES` ; voir
[les modules](INTEGRATIONS-MODULAIRES.md) et
[le périmètre des indices](CONSOLE-DEPLOIEMENT.md#identité-du-site-et-journaux-affichés).

## Lire les états de disponibilité

La date d’actualisation concerne le dernier chargement réussi des données
principales. Le bouton de rafraîchissement permet de réessayer ; la cadence est
réglable dans l’en-tête.

- **Actualisation échouée / données indisponibles** : la lecture n’a pas abouti.
  Le niveau de menace ne doit pas être interprété comme nominal.
- **Données en cache** : la PWA affiche une ancienne copie, avec sa date. Elle
  permet la consultation hors ligne ; les actions nécessitent une connexion.
- **Session expirée** : se reconnecter. La déconnexion purge le cache des lectures.

Une console connectée n’atteste pas de la bonne santé de toute la collecte.
Contrôler **Santé & Collecte**, puis les inputs, pipelines et erreurs d’indexation
dans Graylog pour vérifier une source.

## Traiter un incident

Lorsque XDR est installé, la page Incidents permet de filtrer les cas, ouvrir leur
dossier, assigner un analyste et ajouter des notes. Qualifier un cas **vrai positif**
ou **faux positif** avant sa clôture ; cette disposition alimente le modèle de
réduction des faux positifs lorsque la couche ML est activée.

Les actions SOAR demandent les droits et services du site, une confirmation et,
selon l’action, un motif. Leur présence dans la navigation ne les active pas.

## Espace Administration

L'entrée **Administration** n'apparaît que pour un administrateur SOC. Le serveur
contrôle le rôle à chaque requête : masquer ou afficher le menu n'accorde aucun droit.
La console étant exposée sur Internet, les écritures d'administration sont en outre
limitées par défaut aux réseaux internes (voir les garde-fous ci-dessous).

### Rôles

| Rôle | Droits |
|---|---|
| Lecteur | Consultation de toutes les pages. Aucune écriture (incidents, notes, faux positifs, surveillance d'entités refusés). |
| Analyste | Lecteur + suivi des incidents, notes, qualification, faux positif depuis la page Détections, surveillance d'entités. |
| Administrateur | Analyste + espace Administration, demandes SOAR, notifications push. |

L'authentification reste déléguée à Graylog. Les comptes listés dans `SOC_ADMINS`
(configuration du serveur) sont administrateurs et ne sont pas modifiables depuis la
console. Les autres rôles explicites sont stockés dans `roles.json` sous `SOC_ADMIN_DIR`.
Un compte authentifié sans rôle explicite reçoit `SOC_DEFAULT_ROLE` (`analyste` par
défaut, pour rester compatible avec le comportement antérieur ; `lecteur` possible ;
jamais `administrateur`). Un administrateur ne peut pas modifier son propre rôle.

### Déroulement d'une action

1. **Simulation** : la console calcule l'effet (avant/après, conséquences, refus
   éventuel) sans rien modifier. La simulation est journalisée.
2. **Confirmation** avec un motif obligatoire (4 caractères minimum).
3. Action à **impact normal** : exécution immédiate. Action à **fort impact** : demande
   placée dans l'onglet **Validations**, à approuver ou rejeter (motif obligatoire pour un
   rejet) par un **autre administrateur** dans le délai `SOC_ADMIN_APPROVAL_TTL` (24 h par
   défaut). Avant exécution, la demande est revalidée et son effet recalculé.

Avec `SOC_ADMIN_DRY_RUN=1`, toute action est simulée et journalisée sans être appliquée.
Une seule personne administratrice ne peut pas valider ses propres demandes à fort impact,
sauf si `SOC_ADMIN_SELF_APPROVE=1` (déconseillé) ; la console le signale.

### Matrice des actions

| Onglet | Action | Impact | Mécanisme réutilisé |
|---|---|---|---|
| Accès | Attribuer lecteur / analyste, retirer un rôle explicite | normal | `roles.json` (écriture atomique) |
| Accès | Attribuer ou retirer le rôle administrateur | fort | idem |
| Faux positifs | Ajouter : entité `clé=valeur` (src_ip, user, host, upn, dest_ip, source ; valeur de 3 caractères min.), étiquette ou extrait de titre facultatifs, durée 1 à 90 jours et justification (10 caractères min.) obligatoires | normal | API du triage `POST /fp` (jeton `TRIAGE_TOKEN`) ; justification conservée dans `fp-meta.json` |
| Faux positifs | Retirer (toutes les règles de l'entité, comportement de `DELETE /fp`) | normal | API du triage |
| SOAR | Débloquer une IP | normal | file `soc-requests` traitée par `omni-soc-actions` (`omni-soar-debloquer`) |
| SOAR | Bloquer manuellement une IPv4 publique (refusé si l'IP est exclue) | fort | API `omni-soar` `POST /block` (mode manuel, sans `force`) |
| SOAR | Ajouter / retirer une exclusion fixe (IPv4 publique ou CIDR /16 minimum) | fort | exécuteur `omni-soc-admin-exec` → `exclusions-statiques.txt` |
| SOAR | Paramètres : `SOAR_MODE` (actif / simulation), `SOAR_MIN_HITS` (1-100), `SOAR_MIN_HITS_PAYS_NORMAL` (1-200), `SOAR_TTL_HOURS` (1-168), `SOAR_MAX` (10-2000) | fort | exécuteur → `/etc/omni-soar/soar.env` |
| Détections | Activer une détection Graylog | normal | API Graylog `PUT /events/definitions/{id}/schedule` |
| Détections | Désactiver une détection | fort | API Graylog `PUT /events/definitions/{id}/unschedule` |
| Paramètres | Triage : `MAIL_SCORE_THRESHOLD` (50-100), `GRAY_SCORE_THRESHOLD` (30-95, inférieur au seuil mail), `TRIAGE_DEDUP_SECONDS` (300-86400), `FP_DEFAULT_TTL_DAYS` (1-90), `KILLCHAIN_COUNT` (2-10), `KILLCHAIN_WINDOW` (300-7200), `MAIL_RECIPIENTS` (1 à 10 adresses) | fort | exécuteur → `/etc/omni-alert-triage.env` |
| Supervision | Redémarrer un service de la liste blanche | fort | exécuteur, liste blanche vide par défaut |
| Apparence | Nom, sous-titre, logo, couleurs, thème par défaut ; retour aux valeurs d'origine | normal | `appearance.json` et `logo.<ext>` sous `SOC_APPEARANCE_DIR` (écriture atomique, droits `640`) |

Lectures seules : liste des utilisateurs et rôles, faux positifs actifs, IP bloquées,
exclusions fixes, paramètres (seules les clés de la liste blanche sont lues : les secrets
des fichiers ne sont ni lus ni affichés), détections Graylog et leur état, unités
`omni-*` / `oms-*` (état, résultat, dernier et prochain déclenchement), empreinte du
backend, dernier passage de l'exécuteur, journal d'audit.

Le blocage manuel d'une IP est appliqué même lorsque le moteur SOAR est en mode
`simulation` (ce mode ne concerne que les blocages automatiques) ; l'aperçu le signale.
`SOAR_WHITELIST` défini uniquement dans `00-vars.env` n'est pas lu par la console : le moteur
SOAR le vérifie de toute façon au moment du blocage. Les paramètres SOAR absents de
`soar.env` affichent « non définie dans ce fichier » : la valeur effective vient alors de
`00-vars.env` ou du défaut du moteur, et une valeur écrite par la console la remplace.
La console n'affiche ni ne pilote la couche LLM du triage.

### Apparence

L'onglet **Apparence** modifie la mise en forme de la console pour tous les utilisateurs :

- **nom** affiché (barre latérale, fil d'Ariane de l'en-tête, titre de l'onglet du
  navigateur, page de connexion) et **sous-titre**, 40 et 60 caractères au plus ; vides,
  ils reprennent « OMNI SOC » et « OMNITECH SECURITY » ;
- **logo** : PNG, JPEG ou WebP uniquement, 512 Ko au plus, 16 à 1024 px de côté. Le
  serveur identifie le format par la signature binaire du fichier (jamais par son nom) et
  lit les dimensions dans l'en-tête ; le SVG est refusé (il peut contenir du script). Le
  logo est servi par `GET /m/api/appearance/logo` avec son type MIME exact,
  `X-Content-Type-Options: nosniff` et `Content-Security-Policy: default-src 'none'; sandbox`.
  Le fichier est recontrôlé à chaque lecture (empreinte SHA-256 enregistrée, signature) :
  un fichier altéré sur le disque n'est pas servi et le logo d'origine reste affiché ;
- **couleurs** des modes sombre et clair : sept variables existantes de
  `app-professional.css` (`--pro-accent`, `--cy`, `--bg`, `--card`, `--fg`, `--mut`,
  `--pro-sidebar`), au format `#rrggbb` validé par le serveur. Un enregistrement est refusé
  si une paire texte/fond qui touche une couleur modifiée descend sous 4,5:1 (WCAG AA) ;
  les paires contrôlées sont affichées dans l'onglet. Les paires restées d'origine ne sont
  pas bloquantes : le texte blanc des boutons sur l'accent sombre d'origine (`#447ce2`)
  est à 4,02:1 ;
- **thème par défaut** (système, sombre, clair) : appliqué aux utilisateurs qui n'ont pas
  choisi de thème ; un choix personnel (menu Thème) reste prioritaire, et l'option
  personnelle « Système » revient au thème par défaut de la console.

**Prévisualiser** applique les valeurs à la page courante seulement ; **Vérifier et
enregistrer** suit le circuit commun (simulation, motif, exécution immédiate, audit avec
avant/après, sans le contenu du logo). **Rétablir les valeurs d'origine** supprime les
surcharges et le logo personnalisé. Les autres utilisateurs voient la modification au
prochain chargement de la console.

Lecture : `GET /m/api/appearance` pour tout utilisateur authentifié (nom, sous-titre,
thème par défaut, couleurs modifiées, adresse du logo). Ni cette route ni le logo ne sont
accessibles sans session : la console est exposée sur Internet et la page de connexion
n'a pas besoin du logo. La page de connexion reprend le nom et les couleurs de la dernière
configuration vue par ce navigateur (copie locale `soc_appearance`), sinon l'origine.
Écriture : `POST /m/api/admin/appearance`, mêmes garde-fous que les autres écritures
d'administration, corps de 720 Kio au plus pour cette seule route (logo en base64).

Robustesse : fichier absent, illisible ou JSON invalide, valeur hors liste blanche ou
contraste devenu insuffisant : le serveur renvoie les valeurs d'origine pour le champ
concerné et l'onglet signale un fichier illisible. Côté navigateur, seules les valeurs
`#rrggbb` des variables connues sont appliquées, par `document.documentElement.style.setProperty`
depuis `app-theme.js` : la CSP n'est pas modifiée (aucun script ni style en ligne ajouté ;
les modifications CSSOM ne relèvent pas de `style-src`).

Non couvert : le nom de l'application installée (manifeste PWA, `apple-mobile-web-app-title`)
et la couleur de la barre du navigateur (`theme-color`) restent ceux d'origine ; les
icônes de la PWA ne sont pas remplacées par le logo.

### Retour arrière

Le journal propose **Préparer le retour arrière** sur chaque exécution réversible
(déblocage après blocage, retrait après ajout, valeur précédente d'un paramètre, état
inverse d'une détection, rôle précédent). Le retour arrière suit le même circuit
(simulation, motif, validation si fort impact). L'exécuteur conserve aussi, à côté de
chaque fichier modifié, les dix dernières sauvegardes `*.bak-soc-AAAAMMJJ-HHMMSS`.

### Journal d'audit

Chaque simulation, demande, approbation, rejet, exécution et refus (rôle, origine, jeton,
réseau) d'un compte authentifié est ajouté à `audit.jsonl` : horodatage, compte, rôle,
IP cliente, action, cible, motif, avant, après, résultat, identifiant de demande. Les
entrées sont chaînées (SHA-256 de l'entrée précédente) ; l'onglet **Journal** vérifie la
chaîne entière et signale la première ligne altérée. Une copie GELF (`event_source:
soc_admin`) est envoyée vers `SOC_ADMIN_GELF_URL` (`http://127.0.0.1:12201/gelf` par défaut)
pour une conservation indépendante dans Graylog. Le fichier n'est pas soumis à rotation
automatique.

### Garde-fous côté serveur

- Rôle administrateur vérifié sur chaque endpoint `/m/api/admin/*` (lecture et écriture).
- Écritures : méthode POST, `Content-Type: application/json`, en-tête `Origin` obligatoire
  et présent dans `SOC_ORIGINS`, jeton anti-CSRF `X-SOC-CSRF` lié à la session, corps de
  16 Kio maximum (720 Kio pour `/m/api/admin/appearance`), 30 écritures par 5 minutes et par compte (`SOC_ADMIN_WRITES_PER_5MIN`).
- Réseau : avec `SOC_ADMIN_INTERNAL_ONLY=1` (défaut), écritures acceptées seulement si l'IP
  cliente (posée par nginx dans `X-Real-IP`, prise en compte uniquement depuis 127.0.0.1)
  appartient à `SOC_ADMIN_NETS` (RFC 1918, boucle locale et fc00::/7 par défaut).
  **Point à vérifier** : les journaux nginx montrent aujourd'hui les clients de `/m/api/`
  sous l'adresse `10.33.70.1`. Si l'accès Internet passe par une traduction d'adresse
  source vers cette adresse, il apparaîtrait comme interne : exclure alors cette adresse
  de `SOC_ADMIN_NETS` (lister précisément les plages internes réelles).
- Entrées validées par listes blanches et bornes (IP, CIDR, clés, identifiants Graylog
  sur 24 caractères hexadécimaux, noms d'unité `omni-*`/`oms-*`), aucune commande shell
  construite à partir d'une entrée, écritures atomiques.
- L'exécuteur privilégié revalide tout : action et paramètres identiques à la demande
  approuvée, approbateur distinct du demandeur, liste blanche de redémarrage propre
  (`SOC_EXEC_RESTARTABLE`), trois redémarrages par heure au plus, rejeu refusé.
- Les réponses de l'espace Administration ne sont pas pseudonymisées (`MOBILE_REDACT`) :
  les actions portent sur les valeurs réelles. Le service worker ne les met jamais en cache.

### Ce qui n'est pas fait

- Pas de gestion des comptes eux-mêmes (création, mot de passe) : ils restent dans
  Graylog / l'annuaire.
- La liste d'allowlist du pipeline Graylog (`lookups/fp-allowlist.csv`, script 81) n'est
  pas modifiable depuis la console.
- Les détections ne sont listées et pilotées que si un jeton Graylog est configuré
  (`SOC_GRAYLOG_TOKEN_FILE`).
- Le bouton « Débloquer » historique de la page SOAR (avec exclusion définitive en une
  étape) est conservé ; il est désormais journalisé dans l'audit, mais n'exige pas de
  seconde validation.

Déploiement et configuration : voir
[CONSOLE-DEPLOIEMENT.md](CONSOLE-DEPLOIEMENT.md#espace-administration).

## Affichage et maintenance

Le thème clair ou sombre et la densité d’affichage sont conservés dans le navigateur.
La langue se choisit avec **FR/EN**. La console `/soc/` est installable comme PWA ;
la page historique `/m/` reste disponible lorsque déployée par le site.

Après une mise à jour, accepter **Recharger** lorsque la PWA propose sa nouvelle
version. Pour publier le code ou diagnostiquer une ancienne copie, suivre
[la mise à jour et l’alignement des fichiers servis](UPDATES.md).
Les administrateurs trouveront la configuration et les contrôles dans
[CONSOLE-DEPLOIEMENT.md](CONSOLE-DEPLOIEMENT.md).
