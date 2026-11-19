# Audit de portabilité et de reproductibilité — 19 novembre 2026

## Périmètre et méthode

Référence initiale : commit `c72d4345e43f12ec6a5333fb85532dd0c42ec102`.
Inventaire des **783 fichiers suivis** (26,9 Mo), contrôles statiques systématiques,
lecture des composants de déploiement, de collecte, de normalisation, d'alerting,
de console, de sauvegarde et de leur documentation. Contrôle SSH et API en lecture
seule de l'installation de référence. Aucun script de provisioning, purge,
notification ou réponse automatisée n'a été exécuté sur cette installation.

Ce travail vérifie la cohérence du projet et les défauts de reproductibilité. Il
ne constitue pas une qualification sur chaque équipement, un audit exhaustif de
sécurité de toutes les lignes du code, ni une restauration complète de production.

## État observé de l'installation de référence

| Élément | Observation |
|---|---|
| Système | Debian 13.7, noyau 6.12, environ 32 Gio de RAM |
| Graylog | paquet 7.2.2-1, API `7.2.2+94adc86` |
| OpenSearch | 2.19.7, un nœud, état `green`, 492 shards actifs, aucun non assigné |
| MongoDB | 8.0.38, écoute locale uniquement |
| Nginx | 1.26.3 ; `/soc/` répond en HTTP 200 sur le frontal HTTPS |
| Ingestion | 14 inputs configurés, tous `RUNNING` |
| Configuration Graylog | 21 streams, 40 pipelines, 277 règles de pipeline |
| Détection | 211 définitions, dont 11 désactivées lors de l'observation |
| Dashboards | 13 vues de type `DASHBOARD` |
| Stockage | `/data` chiffré, 7,3 To dont environ 54 % occupés ; `/home` environ 67 % |
| Services | aucun service signalé en échec par systemd ; sauvegardes et snapshots avec dernier résultat systemd `success` |

Un dernier résultat `success` ne prouve pas à lui seul une restauration complète,
ni une couverture de tous les journaux. Les snapshots sélectifs, la sauvegarde de
configuration et la reprise complète sont des contrôles distincts.

Les nouveaux modules ont également été contrôlés via les endpoints sans
persistance de parsing et de simulation de Graylog 7.2.2 : 44 sources acceptées,
10 exemples synthétiques, 136 évaluations sans écart sur les champs attendus.
Aucune entité ni message n'a été créé ou indexé par ces validations. L'import
complet des packs et les formats d'équipements réels restent à qualifier.

Trois copies du dépôt existent sur le serveur. La copie `omnitech-siem-merge`
correspond à la référence GitHub et est propre. La copie `omnitech-siem-setup`
repose sur un ancien commit avec des modifications locales et des suppressions.
Le service de sauvegarde référence cette dernière copie. Le binaire de triage
installé correspond à la copie fusionnée, et diffère du fichier dans l'ancienne
copie. Il faut donc inventorier les chemins réellement exécutés avant toute mise
à jour ; un simple `git pull` dans un répertoire supposé canonique ne suffit pas.

La sauvegarde historique `30-backup-config.sh` cherche également un header LUKS
sur `/dev/sda1`, alors que le volume chiffré observé utilise `/dev/sdb1`. Ce point
doit être corrigé et la présence du header restaurable vérifiée lors de la revue
du PRA du site. Un statut de sauvegarde `success` ne garantit pas sa présence.

## Constats prioritaires

| Priorité | Constat initial et preuve | Conséquence / traitement |
|---|---|---|
| Haute | Le démarrage rapide n'installe pas la console ; `71-soc-console.sh` ne copie que `index.html` et Chart.js | Installation possible de Graylog avec `/soc/` absent, puis scripts/icônes absents même après une copie partielle. Publication complète des assets et installation des routes/backend à partir d'un point d'entrée commun. |
| Haute | `docker/Dockerfile.console` utilise un compte non privilégié, mais l'entrypoint écrit dans `/etc/default` | La console ne peut pas démarrer. Configuration privée dans le volume de données accessible à son compte. |
| Haute | L'entrypoint retourne un statut d'échec lorsque `*_FILE` est absent, sous `set -e` | Les secrets fournis par variables d'environnement font sortir le script. Chargement explicite des deux modes, sans `eval`. |
| Haute | Le backend refuse HTTP vers `graylog`, alors que Compose utilise ce nom de service | Conflit de transport au démarrage Docker. Dérogation explicite limitée à ce nom dans le réseau interne Docker ; les autres hôtes HTTP restent refusés. |
| Haute | La documentation décrit tous les scripts numérotés comme rejouables, mais `40-purge-logs.sh` et `53-purge-clean.sh` détruisent les journaux | Interdire l'exécution globale par joker ; utiliser des listes explicites de phases. Les opérations de maintenance restent hors installation/mise à jour. |
| Haute | `14-graylog-dashboards.sh` supprime puis recrée des dashboards ; plusieurs helpers créent sans réconcilier toutes les différences | Les favoris, personnalisations et identifiants ne sont pas préservés par un rejeu arbitraire. Installation neuve et mise à jour de code doivent avoir des chemins distincts. |
| Haute | Les copies de travail et services exécutés divergent | Métadonnées d'instance, révision source, inventaire, stage séparé, sauvegarde et contrôles d'intégrité avant application. Ne pas écraser les configurations locales. |
| Haute | Scripts Graylog 7.1 et Docker Graylog 7.1.3/MongoDB 7, mais référence en Graylog 7.2/MongoDB 8 | Versions centralisées ; ne pas restaurer un dump MongoDB 8 sur une cible MongoDB 7. Pas de migration de base ou de retour de version implicite. |
| Moyenne | Dépôt MongoDB Debian codé en dur, réseau ifupdown et `http2 on` dépendant d'un Nginx récent | Adapter le dépôt à Ubuntu, préserver la gestion réseau de l'hôte et produire une syntaxe Nginx compatible avec sa version. |
| Moyenne | `04-graylog.sh` démarre une API HTTP locale, mais les helpers suivants exigent HTTPS et une CA propre au site | Décrire et configurer le transport réellement installé ; vérifier TLS lorsqu'il est utilisé. |
| Moyenne | Paramètres de disque, chemins, sous-réseaux, identifiants de streams et inventaires propres au site | Paramétrage explicite et séparation des profils. Les connecteurs externes demandent toujours des données opérateur. |
| Moyenne | Les sauvegardes, le triage, le graphe et les robots ont des dépendances que le bundle Docker ne reproduit pas toutes | Ne pas annoncer une équivalence complète après un simple démarrage Compose. Qualifier chaque profil et chaque module. |
| Moyenne | Les tests du backend importent la configuration de production et échouent sur un poste neuf | Configuration de test temporaire ; clients simulés ; toutes les suites exécutées et dépendances manquantes signalées comme erreurs. |
| Moyenne | Mentions de versions et de quantités divergentes dans les procédures et README | Les chiffres de production deviennent des observations datées, pas des critères universels d'installation. |

## Résultats de l'analyse statique initiale

- Syntaxe Python : 97 fichiers, sans erreur détectée.
- Syntaxe shell : 154 scripts/exécutables, sans erreur détectée après normalisation de lecture des fins de ligne.
- JSON / manifestes : 4 fichiers, sans erreur de syntaxe.
- Liens documentaires relatifs explicites : aucun lien cassé détecté par le contrôle automatisé.
- Références à des réseaux du site dans 104 fichiers, noms du site dans 161 fichiers.
- Identifiants littéraux ressemblant à des identifiants d'objets dans 11 fichiers.
- Désactivation possible de vérification TLS dans 15 fichiers : candidats à revue, pas 15 vulnérabilités automatiquement confirmées.
- Opérations de disque dans 4 fichiers : opérations à isoler des mises à jour ordinaires.
- Neuf préfixes de scripts sont partagés par plusieurs fichiers : 38, 39, 40, 48, 49, 84, 85, 86 et 97.

L'outil `tools/audit-portability.py` reproduit cet inventaire sans exécuter le
provisioning ni lire les fichiers de secrets non suivis. Les références littérales
restantes dans les modules historiques ne sont pas toutes converties par les
changements de ce lot.

## Intégrations et schéma commun

Les sources existantes normalisent déjà `event_source`, `event_action`, `src_ip`,
`dest_ip`, `user`, `host` et `alert_tag`. Cette convention permet des dashboards
transverses, mais les widgets FortiGate/VPN, les robots et le SOAR ne deviennent
pas automatiquement compatibles avec un autre pare-feu.

Les nouveaux modules doivent contenir ensemble : formats et versions supportés,
input paramétré, reconnaissance/routage, règles de parsing, types de champs,
stream, dashboard, exemples anonymisés, tests négatifs et limites connues. Un
format inconnu doit rester visible ; il ne doit pas être présenté comme parsé avec
succès. Les règles de réponse et de notification sont des capacités séparées.

Les Content Packs natifs sont le format d'échange retenu. Leurs dépendances doivent
inclure les streams utilisés par les dashboards. Les tables de lookup et patterns
Grok ne sont pas nécessairement ajoutés automatiquement. Le modèle de stream des
packs natifs de cette version utilise l'index set par défaut : la rétention et
les types doivent être contrôlés avant d'annoncer une isolation par source.

Les packs Illuminate officiels pour WatchGuard, UniFi et Palo Alto demandent une
licence adaptée ; ils ne sont pas redistribués avec le projet. Les modules du
dépôt ont leur propre périmètre et ne sont pas déclarés équivalents à Illuminate.

## Ubuntu et qualification

Ubuntu 22.04 et 24.04 figurent dans la matrice officielle Graylog. Ubuntu 24.04 est
une cible pertinente pour une installation neuve de ce projet. Le fonctionnement
de Graylog sur Ubuntu ne suffit cependant pas à certifier toute la plateforme :
réseau, paquets, TLS, rétention, sauvegarde, collecte et restauration doivent être
testés ensemble sur une machine neuve.

La syntaxe Nginx et la publication complète de `/soc/` sont testées localement
avec Nginx 1.24 sur Ubuntu 24.04. Ce contrôle ne vaut pas recette de la pile de
production complète. MongoDB 8 recommande désormais les THP ; le réglage global
doit tenir compte de la cohabitation avec OpenSearch, pas d'un ancien commentaire
annonçant que MongoDB les exige toujours désactivées.

## Critères de validation avant généralisation

1. Installation neuve sur VM Debian et Ubuntu avec les seules valeurs d'exemple adaptées ; aucune donnée ni identité OMNITECH requise.
2. `/soc/`, ses assets et `/m/api/` accessibles sur le frontal HTTPS ; authentification valide et refus d'accès cohérents.
3. Import de chaque pack, vérification des dépendances, réception d'événements réels de la version annoncée, contrôles de parsing et widgets renseignés.
4. Réinstallation et mise à jour sans doublon ni perte de personnalisation ; collisions signalées explicitement.
5. Mise à jour interrompue/échouée : fichiers restaurés et état lisible ; pas de promesse de rollback des bases par une sauvegarde de code.
6. Sauvegarde puis restauration réelle en environnement isolé aux mêmes versions compatibles.

## Validation du lot livré

| Contrôle | Résultat |
|---|---|
| Suites hors ligne Python 3.12 / Ubuntu 24.04 | 138 tests : 84 au niveau du dépôt, 17 ML, 25 XDR et 12 graphe |
| Inventaire statique du code final | 114 fichiers Python, 157 scripts shell et 11 JSON/manifestes, sans erreur de syntaxe détectée |
| Liens documentaires relatifs explicites | Aucun lien cassé détecté |
| Nginx 1.24 réel | Console, assets, manifeste et refus des ressources absentes vérifiés |
| Compose standard et variante secrets | `docker compose config --quiet` réussi pour les deux configurations |
| Graylog 7.2.2 sans persistance | 44 sources acceptées ; 10 exemples et 136 évaluations conformes |
| Index Git préparé | Scan des secrets et des attributions réussi |

Limites maintenues : aucune installation complète de la pile sur VM vierge,
aucun démarrage complet de Docker, aucun import complet des nouveaux packs,
aucune recette sur des équipements physiques et aucune restauration complète
de production n'ont été réalisés dans ce lot. Les changements sont publiés dans
le dépôt ; ils n'ont pas été appliqués à la configuration du SIEM de référence.

## Sources officielles

- [Matrice de compatibilité Graylog](https://go2docs.graylog.org/current/downloading_and_installing_graylog/compatibility_matrix.htm)
- [Installation Ubuntu avec OpenSearch](https://go2docs.graylog.org/current/downloading_and_installing_graylog/ubuntu_installation_os.html)
- [Content Packs natifs](https://go2docs.graylog.org/current/what_more_can_graylog_do_for_me/content_packs.html)
- [Pack WatchGuard officiel](https://go2docs.graylog.org/current/content_packs/watchguard_firebox_content_pack.htm)
- [Pack UniFi officiel](https://go2docs.graylog.org/current/content_packs/ubiquiti_unifi_content_pack.htm)
- [Pack Palo Alto 11 officiel](https://go2docs.graylog.org/current/content_packs/palo_alto_11.x_content_pack.htm)
- [MongoDB 8 sur Ubuntu](https://www.mongodb.com/docs/v8.0/tutorial/install-mongodb-on-ubuntu/)
- [MongoDB 8 et THP](https://www.mongodb.com/docs/v8.0/administration/tcmalloc-performance/)
- [Directive HTTP/2 de Nginx](https://nginx.org/en/docs/http/ngx_http_v2_module.html)
