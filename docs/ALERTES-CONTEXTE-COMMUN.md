# Contexte commun à toutes les alertes mail

**État : préparé et testé hors ligne, non raccordé aux expéditeurs.** Le chantier
mail parallèle est encore en cours. Cette livraison ne remplace aucun fichier en
service, ne change aucun seuil et ne transmet aucun mail.

## Résultat attendu

Chaque mail de sécurité, immédiat ou regroupé, doit répondre aux mêmes questions :
quel événement, quel compte, quelle machine, de quelle IP vers quelle destination,
sur quel site et environnement, avec quel outil, sur quelle porte physique ou quel
port réseau, avec quel risque et pour quelle raison il faut intervenir.

L’enrichissement commence dans les événements et les règles de corrélation. Une
nouvelle présentation ne peut pas reconstruire un compte ou une porte absent des
données. Un rapprochement temporel ne prouve ni une causalité ni une session commune.

| Bloc | Informations et précautions |
|---|---|
| Événement | Source, identifiant, action et résultat ; dates avec fuseau, fenêtre d’analyse et références des événements |
| Personnes et comptes | Compte observé, acteur, compte ciblé, SID ; domaines et préfixes administrateurs conservés, sans fusion automatique |
| Machines | Machine observée, source et destination lorsque renseignées ; le collecteur reste une notion séparée |
| Réseau | IP source et destination, ports distincts, protocole ; ne jamais compléter un flux avec l’adresse d’un autre événement |
| Environnement | Site, environnement et zone explicitement fournis ; ne pas déduire « production » ou « QA » du nom d’un collecteur |
| Sûreté physique | Porte et identifiant de porte, badge, objet concerné et code de déclenchement distincts ; un code d’alarme ne devient pas un nom de porte |
| Outil | Processus, chemin, parent et outil explicitement nommé ; un processus observé n’est pas une preuve d’utilisation malveillante |
| Risque | Sévérité source, risque métier, échelle éventuelle et priorité de notification séparés ; pas de conversion implicite entre 0–10 et 0–100 |
| Corrélation | Règle et version, relations typées, fenêtre, sources et preuves ; distinguer faits observés, hypothèse et données manquantes |
| Action | Ce que l’analyste doit vérifier et les liens de recherche bornés ; conserver les contrôles de confirmation des actions sensibles |

## Constats vérifiés le 26/11/2026

L’audit de production a été effectué en lecture seule : aucun fetch sur le serveur,
déploiement, redémarrage, envoi de message ou modification de configuration.
Les paramètres protégés et la révision Git n’ont pas changé pendant le contrôle.

- Le dépôt actif était à `28b88c6`, propre. GitHub était à `19d980b` : dix fichiers
  différents et treize absents côté production, concernant la distribution et la
  documentation. Ce retard de révision est distinct des fichiers en service.
- Six cibles du manifeste différaient du dépôt installé : configuration des
  snapshots, minuteur du récapitulatif, expéditeurs triage/récapitulatif/lot et
  contrôle de cohérence. Elles demandent une revue, pas un écrasement automatique.
- Les expéditeurs installés portent déjà une nouvelle charte et importent des
  modules locaux absents du dépôt. Ces changements parallèles sont conservés.
- Sur 25 361 événements tagués des dernières 24 h, `environment` et `site`
  n’étaient pas renseignés ; des champs propres aux sources existent, notamment
  `seal_site` et `fortigate_site`. Tous les événements ne nécessitent pas un compte
  ou une adresse réseau : les absences doivent être interprétées selon la source.
- Les 255 incidents XDR des sept derniers jours portaient `entities`, `signals`
  et `rule_id`, mais aucun champ structuré utilisateur, machine, IP source/IP
  destination ou preuve `xdr_evidence` parmi les champs examinés. Cela ne signifie
  pas qu’aucune information ne figure dans leur texte libre.
- Les événements tagués SEAL observés sur 24 h étaient des dépassements SLA : le
  site était présent, le libellé d’objet absent. Les champs d’accès physiques
  existent dans les indices ; il faut vérifier leur conservation par le producteur
  du dépassement et par la définition Graylog, sans inventer une porte.
- La page Détections ne demande pas plusieurs champs déjà disponibles dans les
  journaux. Le manque de détail se situe donc aussi dans l’API et les vues SOC.

Les nombres portent sur la fenêtre de l’audit, pas sur toute l’histoire du site.
Un service `oneshot` inactif entre deux passages n’est pas une panne : les minuteurs
XDR et corrélation étaient actifs et leurs derniers passages réussis.

## Tous les parcours mail à raccorder

182 définitions Graylog étaient reliées à la notification de triage lors de
l’inventaire. La notification mail native existait mais n’était liée à aucune des
214 définitions examinées. La rendre active partout provoquerait un changement
de politique de notification qui n’est pas demandé ici.

Les 182 définitions de triage demandaient un backlog de 3 à 25 journaux ; 88
n’avaient pas de champs personnalisés dans leur définition. Cela ne signifie pas
que leurs journaux sont vides. En revanche, la fonction actuelle `fields_of`
fusionne les champs des premiers journaux par `setdefault`, sans conserver leur
provenance. Une IP prise dans un journal et un compte pris dans un autre peuvent
ainsi être présentés côte à côte. Le contexte préparé conserve les observations
séparées ; seule une règle avec preuves pourra les relier explicitement.

| Parcours | Raccordement préparé | État |
|---|---|---|
| Mail immédiat du triage | Construire le contexte depuis les champs de l’alerte et chaque événement joint ; compléter la charte existante, en HTML et texte | À intégrer après le chantier parallèle |
| Lot horaire | Enregistrer le contexte de chaque alerte au moment du tri ; ne pas le recalculer à partir du seul texte du lot ; préserver les anciennes entrées de file | À intégrer après revue du format en service |
| Récapitulatif quotidien | Conserver les identifiants d’alertes et le contexte ou une référence durable dès la décision ; le simple événement de décision de triage ne contient pas tout le journal d’origine | À intégrer avec migration additive des données |
| Mail natif Graylog | Utiliser les mêmes champs et les mêmes limites si cette notification est employée sur un autre site | À qualifier sur payload réel |
| Notifications XDR / incidents corrélés | Préserver les références, relations, fenêtres et preuves dans l’événement d’incident avant toute mise en forme | À corriger côté producteurs et API |
| Rapports hebdomadaire, mensuel et SOAR | Partager le vocabulaire et les références ; ne pas transformer une statistique de rapport en preuve d’incident | À revoir avec le chantier mail |

« Toutes les alertes mail » désigne tous les mails réellement retenus par la
politique existante. Cela ne signifie pas envoyer un mail pour chaque détection,
réactiver les alertes de QA ni changer les faux positifs.

## Composant et aperçu hors ligne

[omni_alert_context.py](../triage/omni_alert_context.py) construit un document
versionné, limité à vingt événements joints et huit valeurs par champ source.
Chaque valeur conserve son champ et son identifiant d’événement. Des valeurs
contradictoires restent visibles ; elles ne sont pas résolues arbitrairement.
Les lignes issues d’une agrégation sont explicitement distinguées des journaux.
Les dépassements de limites sont signalés et les entrées ne sont pas modifiées.

Ce module est une fonction pure : aucun appel réseau, accès aux bases, envoi SMTP,
écriture d’état, décision de triage ou action de réponse. Il ne valide pas à lui
seul une chaîne causale ; cette preuve reste à produire par le moteur de corrélation.
Les rendus texte et HTML partagent les mêmes faits, les contenus HTML sont échappés
et les formes évidentes d’identifiants dans les valeurs sont masquées. Ce masquage
n’est pas une garantie de détection de tous les secrets possibles.

Depuis une copie de travail, avec un payload de test ou une copie privée autorisée :

```bash
python3 tools/preview-alert-context.py \
  --payload /CHEMIN/PRIVE/alerte.json \
  --output /CHEMIN/PRIVE/apercu-nouveau
```

Le dossier de sortie doit être neuf. Sur Linux il est créé en mode `0700` et ses
fichiers en `0600` : `context.json`, `alert.txt` et `alert.html`. Le terminal ne
reproduit pas les identités de l’alerte. La commande ne contacte aucun expéditeur.
Un payload peut contenir des données personnelles : ne pas le commiter dans Git.

Pour un premier essai, utiliser la [fixture synthétique](../tests/fixtures/alert-context.json)
à la place de `/CHEMIN/PRIVE/alerte.json`. Les comptes `alice` et `adm-alice`
restent distincts et aucune relation avec la porte physique n’est affirmée.

## Mise en service après le chantier parallèle

1. Relever de nouveau les empreintes des fichiers en service et les dépendances
   locales. Examiner les différences avec le dépôt et intégrer les changements
   autorisés, après contrôle des secrets et des paramètres propres au site.
2. Raccorder le contexte aux trois expéditeurs et à leur stockage, sans retirer la
   charte existante ni modifier la politique de triage. La définition du format
   partagé doit être la même pour le mail et le SOC.
3. Rejouer des fixtures Windows, réseau, M365, SEAL, vulnérabilités et santé ; tester
   aussi domaine homonyme, NAT, machine partagée, absence de session, champs
   contradictoires, plusieurs IP et backlog absent ou tronqué.
4. Vérifier les producteurs : le host d’un DC peut être le serveur qui journalise
   un logon et non le poste d’origine. Une IP derrière NAT, un badge ou une activité
   de service ne doit pas suffire à affirmer une identité humaine.
5. Générer les mails HTML et texte sans SMTP ; vérifier immédiats, lots et
   récapitulatifs, ainsi que les liens et les compatibilités des anciennes files.
6. Publier par transaction avec sauvegarde et refus d’écraser toute modification
   survenue depuis la revue ; contrôler la santé et le résultat après publication.

Le composant n’est volontairement ni importé par les expéditeurs existants, ni
ajouté au manifeste déployé à ce stade. Un `pull` du dépôt ne l’active pas.

Références : [console SOC](CONSOLE-SOC.md), [mises à jour](UPDATES.md),
[guide des signatures](DISTRIBUTION-SIGNATURES.md), [bilan](BILAN-2026-11-26.md).
