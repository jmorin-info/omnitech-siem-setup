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
| Administration | **Santé & Collecte** : sources et fraîcheur ; **SOAR** : actions autorisées ; **Exploitation SIEM** : état opérationnel ; **Déploiement** : enrôlement ; **Rapport** : synthèse imprimable. |

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

## Affichage et maintenance

Le thème clair ou sombre et la densité d’affichage sont conservés dans le navigateur.
La langue se choisit avec **FR/EN**. La console `/soc/` est installable comme PWA ;
la page historique `/m/` reste disponible lorsque déployée par le site.

Après une mise à jour, accepter **Recharger** lorsque la PWA propose sa nouvelle
version. Pour publier le code ou diagnostiquer une ancienne copie, suivre
[la mise à jour et l’alignement des fichiers servis](UPDATES.md).
Les administrateurs trouveront la configuration et les contrôles dans
[CONSOLE-DEPLOIEMENT.md](CONSOLE-DEPLOIEMENT.md).
