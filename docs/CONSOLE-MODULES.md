# Pages et widgets propres à votre environnement

La page **Modules**, dans la rubrique **Visibilité** de `/soc/`, permet de composer
des vues à partir des journaux déjà collectés. Les réglages appartiennent au site :
ils restent hors du dépôt Git et ne sont pas remplacés par une mise à jour du code.

## Créer une page

1. Se connecter avec un compte administrateur SOC, puis ouvrir **Modules** >
   **Configurer les pages et widgets**.
2. Choisir **Créer une page** ou un préréglage **WatchGuard**, **UniFi**, **Palo Alto**
   ou **Vulnérabilités**. Un préréglage prépare des widgets ; il n'installe pas de
   collecteur ni de Content Pack.
3. Donner un titre et une description. Choisir la période et le **rôle minimum**.
   Une nouvelle page est réservée aux administrateurs par défaut.
4. Sélectionner au moins un **stream Graylog** dans la liste du serveur.
5. Vérifier les filtres facultatifs : sources normalisées (`event_source`),
   identifiants d'intégration (`omni_integration_id`) et expression Lucene supplémentaire.
   Ils s'ajoutent au périmètre des streams ; ils ne le remplacent pas.
6. Ajouter, renommer, retirer ou réordonner les widgets. Choisir éventuellement un
   **dashboard Graylog associé** pour proposer son ouverture depuis la page.
7. Renseigner un motif, **Simuler le changement**, vérifier le résultat puis
   **Publier ces réglages**. Actualiser les pages publiées pour consulter la vue.

La simulation valide la configuration et présente son changement ; elle ne garantit
pas que des journaux correspondent aux filtres. Si le mode simulation global de
l'administration est actif, la publication ne modifie aucun réglage.
Une modification simultanée est refusée : rouvrir l'éditeur pour récupérer la révision
la plus récente, puis reprendre son changement.

L'écriture suit les contrôles d'administration existants : rôle, origine du navigateur,
réseau autorisé, jeton anti-CSRF, motif et journal d'audit. Les lectures vérifient
également le rôle minimum de chaque page côté serveur.
Ces rôles SOC ne reproduisent pas les permissions par stream de chaque compte Graylog :
ne publier une page qu'aux opérateurs habilités à consulter son périmètre.

## Choisir les widgets

| Type | Résultat |
|---|---|
| Compteur | Nombre exact de messages correspondant aux filtres de la page. |
| Évolution temporelle | Volume horaire jusqu'à deux jours, puis quotidien. |
| Répartition par champ | Principales valeurs d'un champ agrégeable, avec leurs volumes. |
| Journaux | Derniers messages : date, source et contenu, 20 au maximum. |

Une configuration contient au maximum 20 pages et 12 widgets par page, sur une période
de 1 à 30 jours. Une répartition contient au maximum 50 valeurs. Le catalogue propose
les champs agrégeables présents dans les indices accessibles ; un champ texte brut
peut nécessiter son sous-champ de type `keyword`.

Toutes les requêtes conservent les streams sélectionnés, la période et le périmètre
`SOC_LOG_INDICES`. Les erreurs ou réponses partielles sont affichées comme
**indisponibles**, sans les transformer en zéro. Aucun script, URL de requête ou index
arbitraire ne peut être ajouté dans un widget.

Le catalogue utilise le jeton de service `SOC_GRAYLOG_TOKEN_FILE` pour lire les streams
et dashboards Graylog. Un catalogue indisponible est signalé et ne supprime pas la
configuration enregistrée. Le catalogue présente au maximum 100 dashboards.
Le lien vers un dashboard ouvre sa vue native : les graphiques Graylog existants
ne sont pas convertis automatiquement en widgets SOC.

## WatchGuard, UniFi et Palo Alto

Installer d'abord le module et configurer l'envoi des journaux avec
[le guide des intégrations](INTEGRATIONS-MODULAIRES.md).
Dans l'éditeur SOC, choisir le préréglage, sélectionner son stream et associer son
dashboard. Les préréglages appliquent un filtre `omni_integration_id` : le conserver pour
les modules natifs correspondants. Pour un autre collecteur qui ne renseigne pas ce
champ, retirer ce filtre et choisir les champs réellement présents dans ses journaux.

L'installation d'un module ne publie pas automatiquement une page aux utilisateurs.
L'administrateur choisit son périmètre et ses droits avant publication.

## Vulnérabilités du développement

Choisir le préréglage **Vulnérabilités**, le stream de veille concerné et son dashboard.
Adapter les répartitions aux champs du site, par exemple produit ou sévérité s'ils
existent et sont agrégeables. Un tableau de bord créé dans Graylog apparaît dans le
catalogue ; son ajout ne crée pas à lui seul une page SOC ni un collecteur.

## Que se passe-t-il lorsqu'une machine est ajoutée ?

Le chemin est : **agent ou syslog → entrée Graylog → normalisation → stream et index
set → recherche et widgets SOC**.

- Une nouvelle machine qui envoie dans un stream déjà sélectionné est incluse dans
  les widgets dès que ses messages sont indexés et correspondent aux filtres.
- Un nouveau stream doit être ajouté à la page. Un nouveau préfixe d'index doit aussi
  être autorisé dans `SOC_LOG_INDICES` si le périmètre existant ne le couvre pas.
- Un équipement qui n'envoie aucun journal n'est pas découvert par ces widgets.
  Configurer son agent ou son envoi syslog ; vérifier d'abord sa réception dans Graylog.
- `source`, `host`, utilisateur et adresse IP ne sont pas des identifiants interchangeables.
  La normalisation du collecteur détermine les regroupements possibles. La page historique
  **Entités** reste centrée sur les dossiers et événements de sécurité, sans constituer
  un inventaire exhaustif de toutes les machines.

Déclarer séparément les sources dont le silence doit déclencher un avertissement dans
`SOC_EXPECTED_SOURCES` ; une page de widgets ne surveille pas à elle seule leur silence.
Voir [la configuration du site](CONSOLE-DEPLOIEMENT.md#identité-du-site-et-journaux-affichés).

## Stockage, sauvegarde et mise à jour

Le fichier est normalement `/var/lib/omni-mobile/modules/config.json`, avec la version
de schéma `1` et un numéro de révision. Le répertoire par défaut suit celui du fichier
d'abonnements `MOBILE_SUBS_FILE` ; `SOC_MODULES_DIR` permet de le changer explicitement.
En Docker, il appartient au répertoire de données persistant de la console.
L'écriture est atomique et les permissions du fichier sont limitées à `0640`.

Les sauvegardes de configuration des scripts `08` et `30` incluent le répertoire
standard `/var/lib/omni-mobile`. Avec un chemin personnalisé, l'ajouter à la procédure
de sauvegarde du site et vérifier sa présence dans l'archive chiffrée.
Ne pas publier les réglages du site dans GitHub ni sous le répertoire web public.

Une mise à jour ou un retour arrière du code conserve ce fichier. Un ancien backend
sans cette fonction ne l'affichera pas. Un fichier illisible ou de schéma non pris en
charge produit une erreur explicite ; il n'est pas remplacé par une configuration vide.
Pour les profils d'installation et leurs limites de mise à jour, suivre
[le guide des mises à jour](UPDATES.md#13-mise-à-jour-depuis-la-console-soc-en-un-clic).
