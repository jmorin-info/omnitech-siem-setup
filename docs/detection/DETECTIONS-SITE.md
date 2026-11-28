# Détections portables pilotées par le site

`tools/omni-site-detections.py` déploie les détections du catalogue
`objets-graylog/detections-site/catalogue.json` sur une instance, selon la configuration
du site `/etc/omni-siem/detections.json` (hors Git, mode 600, modèle
`objets-graylog/detections-site/site.exemple.json`).

## Principe
- **Source déclarée → détection créée.** Une source à `null` (ou absente) n'est pas reçue :
  ses détections ne sont pas créées.
- **Détection planifiée seulement si tout est prouvé** :
  - le stream de la source a reçu des messages dans les dernières 24 h ;
  - les événements témoins ont été reçus pendant la période du rejeu (exemple : 4799 prouve
    que l'audit de la gestion des groupes est actif) ;
  - les paramètres de site sont renseignés ;
  - les exemples synthétiques passent le simulateur de pipeline de Graylog ;
  - le rejeu sur de vrais messages, avec le planificateur (fenêtre, pas, grâce par entité),
    donne au plus 5 déclenchements par jour.

  Sinon la définition est créée **désactivée**, avec la raison dans sa description.
- Les règles écrivent `v5_tag`, `v5_severite`, `v5_mitre`, `v5_entite` et `v5_detail`.
  Les règles de threat intel écrivent les champs `ti_*` (liste dans `champs_produits` du
  catalogue, déclarée dans `derived_fields` du module WatchGuard).
- Les titres commencent par `OMNI v5 - ` : le tri les met en rodage (`OMNI_RODAGE_*` dans
  `/etc/omni-alert-triage.env`), récapitulatif seulement, sauf une CRITIQUE listée dans
  `OMNI_RODAGE_IMMEDIAT`.
- Les détections fondées sur une étiquette du socle (`alert_tag`) ne sont créées que si une
  règle de l'instance pose cette étiquette et qu'elle est connectée aux streams du site.

## Chaîne interne
Le tri trace ses décisions (dont le rodage), et les robots écrivent leur état, en GELF sur
127.0.0.1:12201 ; le récapitulatif relit ces décisions dans `omni-interne*`. `appliquer-regles`
pose donc, s'ils manquent, une entrée GELF HTTP sur la boucle locale, l'index set `omni-interne`
(90 jours) et le stream « OMNI - Interne SIEM » (entrée GELF interne, hors `event_source` M365).
Un objet déjà présent (même port, même préfixe, même titre) est réutilisé tel quel.

## Commandes
```
python3 tools/omni-site-detections.py valider                     # hors ligne (CI)
python3 tools/omni-site-detections.py plan
python3 tools/omni-site-detections.py appliquer-regles [--simuler]
python3 tools/omni-site-detections.py rejeu --jours 30
python3 tools/omni-site-detections.py appliquer-definitions [--simuler]
python3 tools/omni-site-detections.py verifier                    # après déploiement, code 1 si défaut
python3 tools/omni-site-detections.py mesure --minutes 30
python3 tools/omni-site-detections.py retour [--simuler]          # par ID, fichier d'état
```
L'état (ID créés) est conservé dans `/var/lib/omni-siem/site-detections-etat.json` et le
rejeu dans `/var/lib/omni-siem/site-detections-rejeu.json`. L'outil s'arrête sur tout objet
de même nom qu'il n'a pas créé lui-même.

## Exclusions
Une exclusion n'est ajoutée (paramètres `exclusions_services`, `exclusions_taches`,
`lecteurs_lsass`, `comptes_replication`) qu'après un faux positif prouvé au rejeu. Elle reste
dans la configuration du site, jamais dans le dépôt.

## Threat intel
`deploye/sbin/omni-v5-ti-fetch` alimente `/etc/graylog/lookup/ti/*.csv`. Sans clé abuse.ch,
seuls Feodo Tracker et la liste des nœuds de sortie Tor sont téléchargés. ThreatFox, URLhaus
et MalwareBazaar apparaissent alors « désactivés », et la table des domaines reste vide : les
définitions qui en dépendent sont créées désactivées.

## Anti-récidive
- `valider` refuse une règle qui lit un champ que sa source ne produit pas, une définition
  qui interroge un champ que personne ne produit, et un titre hors rodage.
- `verifier` contrôle sur l'instance que chaque définition planifiée a un stream actif, une
  règle connectée et des champs réellement présents dans les messages des 7 derniers jours.
  Il contrôle aussi que chaque table de correspondance lue par une règle connectée existe :
  une table absente fait écrire à Graylog un avertissement par message traité.
