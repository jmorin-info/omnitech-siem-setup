# Qualification de l'installation Ubuntu 26.04

Ubuntu 26.04 demande `--experimental-ubuntu-2604`. Cette option conserve les
versions épinglées et les contrôles réels ; elle ne constitue pas un engagement
de support des éditeurs. Voir [le parcours opérateur](UBUNTU-DEMARRAGE.md).

## Recette reproductible sur une VM isolée

Le workflow [Ubuntu 26.04 fresh VM](https://github.com/jmorin-info/omnitech-siem-setup/actions/workflows/ubuntu-vm.yml)
exécute [tools/test-ubuntu-vm.sh](../tools/test-ubuntu-vm.sh) :

1. Téléchargement de l'image cloud officielle Ubuntu 26.04 amd64 et vérification
   SHA-256 contre la somme publiée sur le même site HTTPS.
2. Démarrage par QEMU/KVM d'une VM jetable de 16 Gio, deux vCPU avec AVX et un
   disque virtuel de 60 Gio. Aucune connexion au SIEM de production.
3. Transfert d'un bundle Git du commit testé, sans configuration Git locale,
   fichier privé `00-vars.env` ou identifiant de production.
4. Configuration fictive du laboratoire, génération de secrets locaux et plan
   sans blocage ; exécution intégrale du profil `core-soc`.
5. Vérification des services, des versions des paquets, de l'authentification
   MongoDB et du PRIMARY `rs0`, de l'API Graylog, des inputs RUNNING, streams,
   règles, connexions des pipelines, détections et dashboard SOC.
6. Vérification HTTPS avec certificat contrôlé et comparaison SHA-256 des assets
   publiés à leurs sources ; vérification du backend et du timer de sauvegarde,
   puis connexion/déconnexion de la console avec une vraie session HTTPS.
7. Installation native des trois packs WatchGuard/UniFi/Palo Alto, vérification
   de leurs entités et six widgets par dashboard, envoi des dix fixtures UDP,
   contrôle des champs réellement indexés et de leur routage vers les streams.

Le rapport `ubuntu-2604-acceptance` contient le commit, le noyau, l'empreinte de
l'image, les résultats des contrôles et des modules. Le résultat global n'est
positif que si l'installation **et** toutes les vérifications réussissent.
En cas d'échec, le rapport indique la dernière phase et une fin de journal
expurgée des secrets du laboratoire. Les journaux bruts et les secrets ne sont
pas publiés. La VM et son espace privé sont supprimés en fin d'exécution.

Un échec de prérequis, de téléchargement, de démarrage ou de test reste un échec
de recette : il n'est jamais transformé en validation ou en étape ignorée.

Pour reproduire sur un hôte Linux dédié disposant de KVM, 16 Gio de RAM et au
moins 20 Gio libres, installer QEMU, `cloud-image-utils`, `genisoimage`, Git,
OpenSSH, curl et Python, puis lancer depuis un clone propre :

```bash
bash tools/test-ubuntu-vm.sh
```

Le compte doit pouvoir accéder à `/dev/kvm`. Le script refuse d'écraser un
ancien `ubuntu-vm-report.json`. Archiver le rapport précédent ou choisir un
nouveau chemin avec `OMNI_VM_REPORT=/chemin/rapport-neuf.json`.
`tools/test-integration-vm.py` écrit des données et exige l'identité et le marqueur
du laboratoire ; ce n'est pas un diagnostic à exécuter sur un SIEM existant.

## Corrections contrôlées

- Le garde noyau tient compte de la version amont dans `/proc/version_signature`
  pour les noyaux Ubuntu `7.0.0-*`, comme MongoDB 8.0.38. Une ABI Ubuntu courte
  ne doit pas provoquer de faux refus d'un noyau corrigé.
- L'héritage d'un `umask` privé ne rend plus les clés APT et les répertoires des
  services illisibles. Les secrets et l'état d'installation gardent leurs droits
  privés explicites. MongoDB attend un PRIMARY avant de créer ses comptes.
- L'API garde le corps d'un rejet 400 pour réessayer l'enveloppe Graylog 7 quand
  elle est requise. Les autres erreurs restent des erreurs.
- Sans triage optionnel, une instance neuve utilise les notifications natives.
  Si le triage est choisi, sa phase précède le routage des détections.
- Une création de dashboard refusée et une recette finale échouée arrêtent
  l'installation ; elles ne sont plus présentées comme une réussite.
- Le préflight examine IPv4 sans confondre une réponse AAAA, et distingue un
  filtrage ICMP d'une absence de connectivité HTTPS.
- Le pare-feu conserve le fichier de démarrage et les tables tierces, applique
  uniquement sa table et restaure les fichiers en cas d'échec.

Le comportement du garde noyau suit le
[code MongoDB 8.0.38](https://raw.githubusercontent.com/mongodb/mongo/r8.0.38/src/mongo/db/startup_check_rseq.cpp)
et [SERVER-131779](https://jira.mongodb.org/browse/SERVER-131779).

## Périmètre de la preuve

Une recette sur une image, un noyau et un commit donnés ne certifie pas toutes
les variantes Ubuntu, tous les hyperviseurs ni les charges de production.
Les fixtures ne remplacent pas les journaux de versions matérielles réelles.
Le SMTP de laboratoire ne valide pas le relais du client. Les connecteurs M365,
SEAL, les réponses SOAR, les restaurations complètes et les extensions analytiques
demandent leur configuration et leur propre recette.

Les modifications publiées sur GitHub ne sont pas automatiquement appliquées
aux services d'une production existante. Suivre [UPDATES.md](UPDATES.md), examiner
les modifications locales et publier chaque composant concerné explicitement.
