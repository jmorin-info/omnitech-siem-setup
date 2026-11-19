# Intégrations modulaires : WatchGuard, UniFi et Palo Alto

Ces modules ajoutent chacun un input, un stream, un pipeline de normalisation et
un dashboard Graylog. Ils s'installent séparément du socle et de la console `/soc/`.
Ils ne nécessitent pas de JAR additionnel ni de redémarrage de Graylog.

**État : préversion.** Les exports et contrats de parsing sont testés hors ligne.
Le 19 novembre 2026, les 41 règles générées et les trois pipelines ont également
été acceptés par les endpoints de validation syntaxique `/parse` de Graylog 7.2.2,
sans enregistrer d'entité. Les 10 exemples synthétiques ont ensuite été évalués
en mémoire par son simulateur : 136 appels, sans écart sur les champs attendus.
Aucun pack ni message n'a été installé ou indexé. Ces validations ne constituent
pas un test d'import complet.
L'import natif, l'exécution sur des flux collectés et la collecte sur les équipements
doivent être qualifiés sur une instance de recette avant emploi en production.
Les fixtures sont synthétiques, avec des adresses de documentation ; elles ne
constituent pas une preuve de compatibilité avec toutes les versions constructeur.

## Catalogue livré

| Module | Format couvert par la révision 1 | Port UDP proposé | Dashboard |
|---|---|---|---|
| `watchguard` | Trafic Fireware IPv4 TCP/UDP, variante syslog `firewall: msg_id=...` ou Traffic Monitor | 1521 | OMNI - WatchGuard Firebox |
| `unifi` | Export SIEM CEF, vendor `Ubiquiti`, product `UniFi Network` | 1522 | OMNI - Ubiquiti UniFi Network |
| `paloalto` | CSV standard PAN-OS `TRAFFIC`, au moins les 31 premières colonnes jusqu'à `action` | 1523 | OMNI - Palo Alto PAN-OS |

Le dashboard de chaque source contient six widgets : volume reçu, formats non
reconnus, équipements émetteurs, actions, adresses sources et table des journaux.
Il filtre explicitement sur le stream du module. Les UUID d'entités du pack sont
reproductibles et résolus par Graylog à l'installation ; aucun identifiant d'une
installation OMNITECH n'est embarqué.

Cette première révision ne couvre pas les anciens syslogs texte UniFi, les logs
PAN-OS `THREAT`/`SYSTEM`/`CONFIG`, ni les événements WatchGuard VPN/authentification
et les nombreuses variantes IPv6. Ils restent consultables avec
`omni_parse_status:unparsed`. Les messages bruts sont conservés ; aucun `drop_message`
n'est exécuté. La date d'indexation est celle de réception : les horodatages
constructeur ne remplacent pas encore `timestamp`.

Les champs normalisés sont `event_source`, `event_id`, `event_action`, `host`,
`src_ip`, `dest_ip`, `src_port`, `dest_port`, `network_protocol` et, selon la
source, `user`, `network_rule`, `network_application`, `src_zone`, `dest_zone`.
Les champs bruts parsés sont préfixés par `watchguard_`, `unifi_` ou `paloalto_`.
`omni_parse_status` vaut `parsed` pour les formats reconnus et `unparsed` sinon.

**Ces modules n'activent aucune notification, réponse SOAR ou détection automatique.**
Ils ne rendent pas automatiquement les détections FortiGate compatibles avec
d'autres pare-feu. Les recherches multi-constructeurs doivent utiliser les champs
normalisés et être validées sur leurs données.

## Lister, valider et exporter sans serveur

Python 3.10 ou supérieur suffit ; le gestionnaire n'a pas de dépendance tierce.
Depuis la racine du dépôt :

```bash
python3 tools/omni-integrations.py list
python3 tools/omni-integrations.py validate
python3 tools/omni-integrations.py export watchguard --output /tmp/watchguard-r1.json
python3 tools/omni-integrations.py export unifi --output /tmp/unifi-r1.json
python3 tools/omni-integrations.py export paloalto --output /tmp/paloalto-r1.json
```

L'export refuse d'écraser un fichier existant. Le JSON est un Content Pack natif,
importable dans **System > Content Packs > Upload**. Les valeurs `port` et
`bind_address` sont des paramètres natifs. Le bind par défaut est `127.0.0.1` :
pour recevoir des équipements distants, choisir explicitement l'adresse de
l'interface de collecte. Pour Docker, l'input doit écouter sur `0.0.0.0` dans
le conteneur et le port UDP doit également être publié sur l'hôte.

Après une installation manuelle par l'interface, vérifier le stream et le reprendre
avec **Start Stream** si nécessaire : Graylog 7.2 crée les streams de Content Packs
en pause. Le gestionnaire ci-dessous reprend seulement le stream neuf qu'il vient
d'installer et dont l'appartenance est confirmée par Graylog.

## Préparer et installer via l'API

Le gestionnaire cible **Graylog 7.2.x**. L'export déclare une contrainte minimale
7.2.0 ; une nouvelle version majeure doit être qualifiée séparément. Utiliser
un jeton d'accès d'un compte autorisé à gérer les Content Packs, inputs, streams,
pipelines et dashboards. Le jeton reste dans une variable d'environnement et
n'apparaît ni dans les arguments de processus ni dans les plans imprimés.

```bash
read -rs -p 'Jeton API Graylog : ' GRAYLOG_API_TOKEN; echo
export GRAYLOG_API_TOKEN

python3 tools/omni-integrations.py plan watchguard \
  --api https://siem.example.net/api --ca /etc/ssl/certs/siem-ca.crt \
  --bind 192.0.2.10 --port 1521

# Même plan en lecture seule tant que --apply n'est pas fourni.
python3 tools/omni-integrations.py install watchguard \
  --api https://siem.example.net/api --ca /etc/ssl/certs/siem-ca.crt \
  --bind 192.0.2.10 --port 1521 --apply

unset GRAYLOG_API_TOKEN
```

Remplacer l'adresse de documentation `192.0.2.10` par l'interface réelle. Le
certificat serveur et son nom sont vérifiés ; aucun mode TLS non vérifié n'est
proposé. `--ca` est inutile si l'autorité est déjà approuvée par le système.
Une URL HTTP est acceptée uniquement sur `localhost`, `127.0.0.1` ou `::1`, par
exemple pour un tunnel SSH vers un serveur dont l'API locale utilise HTTP.
Les redirections HTTP sont refusées pour empêcher la transmission du jeton
à une autre destination.

Le plan n'effectue que des GET. Il contrôle la version, l'ordre des processeurs,
les installations antérieures, l'empreinte SHA-256 du pack enregistré et les
conflits de port UDP/titres de streams/pipelines/règles. L'installation explicite
ajoute le pack si nécessaire, l'installe avec l'enveloppe API Graylog 7.2, puis
reprend son stream neuf. Une deuxième exécution avec le même pack et les mêmes
paramètres n'écrit rien et renvoie `already-installed`.

Les contrôles de port portent sur les inputs Graylog déclarés, pas sur les autres
processus de l'OS. Ils ne remplacent pas `ss -lunp`, le pare-feu ou les règles de
routage. Les erreurs HTTP ne sont pas assimilées à une absence de ressource.
Un pack différent portant la même identité/révision est refusé ; il faut publier
une nouvelle révision. Un module déjà installé avec une autre révision ou d'autres
paramètres nécessite une migration préparée, et n'est pas réinstallé automatiquement.

**Stockage :** les Content Packs natifs Graylog 7.2 créent le stream dans l'index
set par défaut. Sa politique de rétention s'applique donc à ces journaux. Aucun
index set ni profil de champ dédié n'est créé par ces modules. Définir un index
set adapté puis y affecter le stream si une rétention différente est requise,
avant d'envoyer des données. Vérifier aussi que les types de champs de cet index
sont compatibles avec les IP et ports normalisés.

Le gestionnaire ne modifie pas l'ordre global des processeurs. La chaîne de
filtres et le routage des streams doivent précéder **Pipeline Processor**. Il ne
rapproche pas les modifications locales apportées aux entités après installation :
l'empreinte vérifie l'artefact enregistré, pas toute la configuration vivante.

En cas d'erreur après le début d'un `--apply`, inspecter **System > Content Packs**,
les inputs et le stream. Une installation API implique plusieurs opérations :
le gestionnaire ne prétend pas rendre leur ensemble transactionnel. Il n'efface
jamais automatiquement des entités ou des logs pour tenter de réparer l'échec.

## Côté équipements et réseau

1. Installer d'abord dans une instance de recette, sans notifications de production.
2. Ouvrir seulement le port UDP du module aux IP des équipements attendus.
3. WatchGuard : activer l'envoi Syslog dans les paramètres de journalisation et
   sélectionner le format Syslog. Choisir le port du module ; tester les variantes
   reçues et ne pas assimiler la réussite d'un format trafic à celle du VPN/IPS.
4. UniFi Network : activer l'intégration SIEM et sélectionner CEF. Les logs
   historiques du noyau et des équipements ne suivent pas ce même contrat.
5. Palo Alto : configurer un profil serveur Syslog, format standard sans format
   personnalisé, puis le forwarding des logs `TRAFFIC` vers le port choisi.
6. Vérifier l'arrivée de vrais événements, les adresses/ports, l'action et la
   proportion `omni_parse_status:unparsed`. Ouvrir les six widgets du dashboard.
7. Vérifier les erreurs de pipeline et d'indexation, la rétention et le débit.
8. Ajouter la source au mécanisme de surveillance de silence de l'installation
   avec un seuil adapté ; ces modules ne réécrivent pas le watchdog existant.

Le transport livré est UDP, sans chiffrement ni garantie de livraison. Pour un
autre transport, TLS ou une file persistante, utiliser un relais de collecte
et qualifier sa livraison vers l'input ; cette révision ne configure pas le relais.

## Désinstaller une installation précise

L'installation retourne `installation_id`, également disponible dans l'interface
Content Packs. Le gestionnaire vérifie que cet identifiant appartient au module
et affiche d'abord les détails natifs de désinstallation :

```bash
python3 tools/omni-integrations.py uninstall watchguard \
  --api https://siem.example.net/api --installation-id <ID_INSTALLATION>

# Ajouter --apply uniquement après lecture des entités concernées.
```

Graylog gère les entités créées ou réutilisées par le Content Pack. La
désinstallation retire la configuration concernée ; les messages déjà indexés
restent soumis à la politique de rétention existante. Ce mécanisme n'est pas une
sauvegarde des personnalisations locales ni un retour arrière des données.

## Ajouter un constructeur ou étendre une révision

- Créer `integrations/<id>/manifest.json` avec un identifiant unique, une révision
  entière, un format précisément borné et la référence constructeur.
- Utiliser un parser déclaratif `regex`, `cef` ou `csv`. Ajouter les champs au
  mapping canonique ; conserver les champs constructeur préfixés.
- Ajouter `fixtures.json` : cas valides, formats inconnus, valeurs limites et
  échappements pertinents. Ne jamais déposer de logs clients ou de secrets.
- Déclarer le module dans `integrations/catalog.json` et lancer `validate` puis
  `python3 -m pytest tests/test_integrations.py`.
- Vérifier l'import sur une instance Graylog de recette, l'exécution de chaque
  règle et les widgets sur de vrais logs anonymisés. Documenter les modèles,
  firmware et résultats réellement qualifiés avant de retirer le statut preview.
- Incrémenter `revision` quand l'artefact change. Préparer une migration explicite
  pour les anciennes installations ; le gestionnaire refuse leur remplacement
  implicite et les entités ne portent pas toutes une identité distincte par révision.

Les UUID stables, les dépendances de stream et les références de règles sont
générés dans `omni_integrations/core.py`. Ne pas remplacer ces dépendances par
des identifiants MongoDB copiés depuis un serveur.

## Packs officiels et sources techniques

Les packs officiels Illuminate WatchGuard, Ubiquiti UniFi et Palo Alto sont des
produits distincts nécessitant Illuminate et Graylog Enterprise ou Security.
Ce dépôt ne les embarque pas et ne copie pas leurs parsers/dashboards. Il fournit
son propre contenu et un chemin d'extension utilisable avec Graylog Open.

- [Content Packs natifs : dépendances, paramètres et cycle de vie](https://go2docs.graylog.org/current/what_more_can_graylog_do_for_me/content_packs.html).
- [WatchGuard : lecture des messages](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/logging/read_log-msg.html) et [envoi Syslog](https://www.watchguard.com/help/docs/help-center/en-US/Content/en-us/Fireware/logging/send_logs_to_syslog_c.html).
- [Ubiquiti : System Logs / SIEM Integration et CEF](https://help.ui.com/hc/en-us/articles/33349041044119-UniFi-System-Logs-SIEM-Integration).
- [Palo Alto : ordre des champs des logs TRAFFIC](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields).
- [Modèles natifs et facades Graylog 7.2](https://github.com/Graylog2/graylog2-server/tree/7.2/graylog2-server/src/main/java/org/graylog2/contentpacks).
- [Illuminate WatchGuard](https://go2docs.graylog.org/current/content_packs/watchguard_firebox_content_pack.htm), [UniFi](https://go2docs.graylog.org/current/content_packs/ubiquiti_unifi_content_pack.htm) et [Palo Alto 11](https://go2docs.graylog.org/current/content_packs/palo_alto_11.x_content_pack.htm).
