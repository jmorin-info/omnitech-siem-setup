# Installer proprement sur Ubuntu, ligne par ligne

Parcours conseillé : **Ubuntu Server 24.04 LTS amd64 sur une VM neuve**,
avec CPU AVX exposé, au moins 16 Go de RAM (32 Go conseillés), une IP stable,
un DNS et un stockage dimensionné pour les journaux et sauvegardes.
Ce guide installe le profil `core-soc` décrit dans [INSTALLATION.md](INSTALLATION.md).
Les connecteurs et réponses propres au site se configurent ensuite.

Ubuntu 26.04 reste une option expérimentale, décrite plus bas : lever un contrôle
d'OS ne rend pas les composants officiellement compatibles.

## 1. Vérifier la machine

Depuis le terminal SSH du nouveau serveur :

```bash
cat /etc/os-release
uname -r
uname -m
free -h
lscpu | grep -i avx
ip -br address
ip route
printf '%s\n' "$SSH_CONNECTION"
df -h
```

Relever l'interface, l'adresse IP, la passerelle et l'adresse du poste SSH.
Sur Proxmox, si AVX manque, choisir un CPU de type `host` compatible, puis arrêter
et redémarrer complètement la VM. Supprimer le contrôle AVX ne corrige pas un
processeur incompatible. Le contrôle de RAM tient compte de la réserve du système.

## 2. Récupérer le projet

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv curl ca-certificates nano
git clone --branch main --single-branch https://github.com/jmorin-info/omnitech-siem-setup.git
cd omnitech-siem-setup
git log -1 --oneline
cp 00-vars.env.example 00-vars.env
chmod 600 00-vars.env
nano 00-vars.env
```

Ces commandes concernent un nouveau dossier et une machine sans installation
MongoDB/OpenSearch/Graylog. Si le dossier existe déjà, le conserver et examiner
son état ; ne pas supprimer les fichiers ou les bases pour recommencer.

Dans `00-vars.env`, remplacer les exemples avec les valeurs du site :

| Paramètres | À renseigner |
|---|---|
| `SIEM_HOSTNAME`, `SIEM_DOMAIN`, `SIEM_FQDN` | Nom de machine, domaine et nom complet résolu par le DNS des utilisateurs |
| `SIEM_IP`, `SIEM_PREFIX`, `SIEM_GW`, `SIEM_IFACE` | IP du serveur, préfixe réseau, passerelle et interface relevés à l'étape 1 |
| `DNS1`, `DNS2`, `NTP1`, `NTP2` | Serveurs DNS et NTP accessibles |
| `NET_ADMIN` | Sous-réseau autorisé à administrer le serveur, contenant le poste SSH actuel |
| `WEB_NET`, `NET_BEATS`, `VSPHERE_NET`, `IP_FAZ`, `IP_CENTREON` | Sources réellement autorisées ; vider les sources facultatives absentes |
| `GRAYLOG_ADMIN_PASS` | Mot de passe unique d'au moins 12 caractères choisi pour le compte `admin` |
| `SMTP_RELAY`, `SMTP_PORT`, `SMTP_FROM`, `ALERT_EMAIL` | Relais et destinataires du site ; la notification demande un relais opérationnel |
| `OS_HEAP`, `GL_HEAP`, `MONGO_CACHE_GB` | L'exemple vise 32 Go : sur une VM de 16 Go, partir de `4g`, `2g`, `1`, puis ajuster à la charge |
| `DATA_MOUNT`, `BACKUP_DIR`, `JOURNAL_SIZE`, `RETENTION_DAYS` | Emplacements, capacité et rétention adaptés au site |

Conserver `APPLY_NETWORK="0"` si le réseau Ubuntu est déjà configuré.
Conserver `DATA_DISK=""` et `ALLOW_FORMAT_DATA_DISK="0"` pour utiliser le stockage
existant sans formatage. Conserver `THP_MODE="preserve"` tant que la politique
mémoire de l'hôte n'a pas été validée. Les paramètres des extensions inutilisées
(M365, LDAP, SOAR, etc.) n'activent pas ces extensions à eux seuls.

Dans nano : `Ctrl+O`, Entrée, puis `Ctrl+X`. Mettre les secrets entre guillemets
simples ; le fichier est une configuration shell de confiance, jamais à publier.

## 3. Générer les secrets techniques puis lire le plan

```bash
sudo bash install.sh --generate-secrets
sudo bash install.sh --plan
```

La première commande génère uniquement les valeurs absentes ou `CHANGEME` de
`MONGO_ADMIN_PASS`, `MONGO_GRAYLOG_PASS` et `OPENSEARCH_BOOTSTRAP_PASS`.
Elles sont distinctes, fortes, conservées uniquement dans `00-vars.env` en mode
`600` et ne s'affichent pas. Les valeurs déjà renseignées et le mot de passe
Graylog choisi restent conservés. Une valeur existante trop courte doit être
corrigée manuellement avant l'installation. La génération est refusée si des
services de la pile sont déjà configurés ; elle ne fait pas de rotation de compte.

Le plan ne modifie aucun service. Continuer seulement lorsque `"blockers": []`.
Le fichier privé reste exclu de Git : aucun `git add` ou commit local n'est requis.
Conserver les secrets au coffre et sauvegarder cette configuration hors du serveur.

## 4. Installer et contrôler

```bash
sudo bash install.sh --apply
sudo systemctl is-active mongod opensearch graylog-server nginx omni-mobile-api
sudo systemctl status siem-backup.timer --no-pager
curl -fsS http://127.0.0.1:8090/m/api/vapid
sudo python3 tools/verify-installation.py --output /var/lib/omni-siem/acceptance.json
```

Ouvrir ensuite `https://VOTRE_FQDN/soc/` depuis un poste autorisé par `WEB_NET`.
L'interface Graylog est sur `https://VOTRE_FQDN/`, compte `admin` et mot de passe
choisi à l'étape 2. Remplacer `VOTRE_FQDN` par la valeur de `SIEM_FQDN`.
Un certificat auto-signé provisoire est généré : installer un certificat approuvé
pour l'exploitation. Le port `9000` n'héberge pas `/soc/`.

Si une phase échoue, lire l'erreur et les journaux du service concerné. Après
correction de la cause, reprendre avec les mêmes sources, configuration et options :

```bash
sudo bash install.sh --apply --resume
```

Ne pas régénérer les secrets, modifier la configuration ou changer de révision
pendant une reprise. L'état est enregistré dans
`/var/lib/omni-siem/install-state.json`. Une reprise saute le provisioning déjà
terminé et rejoue les contrôles finaux ; examiner l'état laissé par la phase en erreur.

## 5. Interface dans le terminal et WatchGuard

```bash
sudo python3 tools/omni-manager.py
```

Le menu propose configuration, installation, reprise, mises à jour du code,
publication de la console et modules WatchGuard/UniFi/Palo Alto. Le menu
d'installation permet aussi de générer les secrets techniques manquants.
Voir [l'interface SSH](INTERFACE-ADMINISTRATION.md) et
[la procédure WatchGuard et autres modules](INTEGRATIONS-MODULAIRES.md).
Les modules sont des préversions : configurer le syslog de l'équipement, le port
d'entrée, le pare-feu et vérifier des journaux réels avant la mise en production.
Leurs dashboards se remplissent seulement après réception du format pris en charge.

## Ubuntu 26.04 : essai explicite, hors support de cette pile

Graylog 7.2 et MongoDB 8 ne listent pas Ubuntu 26.04 comme OS pris en charge.
MongoDB annonce Ubuntu 26.04 à partir de MongoDB 9.0.4 ; MongoDB 9 dépasse la
compatibilité actuelle de Graylog 7.2. Le projet conserve MongoDB 8.0.38 et utilise
le dépôt Ubuntu 24.04 `noble` uniquement après accord explicite de l'opérateur :

Sur une VM 26.04 neuve issue d'une ancienne image, appliquer d'abord les mises
à jour Ubuntu, puis redémarrer pour charger le noyau corrigé :

```bash
sudo apt-get update
sudo apt-get upgrade -y
sudo reboot
```

Après reconnexion SSH, revenir dans le dossier du dépôt, vérifier `uname -r`
et `cat /proc/version_signature`, puis poursuivre :

```bash
sudo bash install.sh --generate-secrets
sudo bash install.sh --plan --experimental-ubuntu-2604
# Uniquement si blockers est vide et après lecture des avertissements :
sudo bash install.sh --apply --experimental-ubuntu-2604
# Reprise éventuelle avec la même option :
sudo bash install.sh --apply --resume --experimental-ubuntu-2604
```

**Le noyau reste un prérequis réel.** MongoDB documente une incompatibilité des
noyaux Linux 6.19 à 7.0.13 inclus, corrigée à partir de 7.0.14. L'installateur
refuse cette plage avant le provisioning, même avec l'option expérimentale.
Pour les noyaux Ubuntu `7.0.0-*`, il vérifie la version amont enregistrée dans
`/proc/version_signature` : une ABI courte ne signifie pas que le correctif manque.
Utiliser Ubuntu 24.04 avec un noyau compatible ou faire valider un noyau corrigé
par l'administrateur du système. Docker ne contourne pas cette incompatibilité.

Références vérifiées le 19 novembre 2026 :

- [Matrice Graylog](https://go2docs.graylog.org/current/downloading_and_installing_graylog/compatibility_matrix.htm).
- [Plateformes MongoDB Community](https://www.mongodb.com/docs/community-platform-support/).
- [Notes MongoDB 8.0 et incompatibilité noyau](https://www.mongodb.com/docs/v8.0/release-notes/8.0/).

La [procédure de qualification sur VM](QUALIFICATION-UBUNTU2604.md) décrit les
contrôles et donne accès aux rapports du workflow. Vérifier le résultat du commit
concerné : un plan vide ou des tests de syntaxe ne constituent pas une recette complète.

## Correctif ZIP ou fichiers locaux modifiés

Pour une installation neuve depuis un clone récent de `main`, cette option est
inutile. Si un correctif a été extrait dans un dépôt Git existant, examiner les
modifications avant de les autoriser :

```bash
git status --short
git diff --stat
git diff
sudo bash install.sh --plan --allow-local-changes
sudo bash install.sh --apply --allow-local-changes
```

Sur Ubuntu 26.04, ajouter également `--experimental-ubuntu-2604` aux deux dernières
commandes. Pour une reprise, garder ces options et ajouter `--resume` à `--apply`.
Aucun commit local n'est nécessaire. L'installateur conserve les fichiers, archive
leur différence Git et leur manifeste sous
`/var/lib/omni-siem/install-sources/<empreinte>/`, puis enregistre leur empreinte.
Des sources modifiées ensuite bloquent la reprise. Ce mécanisme ne permet pas de
réinstaller une instance existante ni de contourner AVX, RAM, secrets ou noyau.

## Installation déjà terminée avec des correctifs manuels

Si une ancienne installation affiche `finished_at`, cela indique la fin du
parcours enregistré, sans prouver que les étapes contournées ont réussi.
Un timer actif ne prouve pas qu’une sauvegarde a été produite ; un HTTP 200
sur `/soc/` ne prouve pas que les détections sont installées.

Conserver les sources modifiées et le fichier privé `00-vars.env`. Après
rapprochement du code selon [la procédure de mise à jour](UPDATES.md), exécuter
le vérificateur de la révision examinée :

```bash
sudo python3 tools/verify-installation.py --output /var/lib/omni-siem/acceptance.json
sudo systemctl status siem-backup.service --no-pager
```

Réparer les contrôles en échec un par un, avec sauvegarde et examen du script
concerné. Ne pas effacer l’état, changer son empreinte à la main, relancer toute
l’installation ou rendre une erreur de notification silencieuse pour forcer
une validation. `--resume` exige les mêmes sources et paramètres ; il ne reprend
pas automatiquement une installation modifiée avec une nouvelle révision.

Le profil de base livre ses détections et son dashboard SOC. Les nombreuses
détections de l’installation de référence proviennent aussi des extensions,
qui demandent leurs sources et une configuration propre au site.
WatchGuard s’ajoute séparément avec [le gestionnaire de modules](INTEGRATIONS-MODULAIRES.md).
