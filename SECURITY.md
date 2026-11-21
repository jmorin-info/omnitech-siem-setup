# Politique de sécurité

Ce dépôt décrit et provisionne le SIEM de production d'OMNITECH SECURITY.
Une vulnérabilité dans son code ou une fuite d'information par son contenu
peut affecter directement la supervision de sécurité de l'entreprise.

## Signaler une vulnérabilité

- **Ne pas ouvrir de ticket ni de demande de fusion publique** décrivant la
  vulnérabilité.
- Utiliser un canal privé : l'avis de sécurité privé de GitHub (onglet
  « Security » du dépôt, si la fonction est activée) ou un contact direct
  avec le RSSI d'OMNITECH SECURITY.
- Décrire : le composant concerné (chemin dans le dépôt), la version (commit),
  le scénario d'exploitation, l'impact estimé et, si possible, une
  reproduction sur un environnement de test.
- Ne jamais tester une vulnérabilité sur la production ni joindre de
  journaux réels non pseudonymisés.

Le RSSI accuse réception, qualifie la gravité et décide du traitement :
correctif, mesure compensatoire ou acceptation du risque, consignée dans le
[registre d'amélioration continue](docs/securite-conformite/REGISTRE-AMELIORATION-CONTINUE.md).

## Périmètre

Dans le périmètre :

- les scripts de provisioning et les bibliothèques (`NN-*.sh`, `lib-*.sh`, `tools/`) ;
- les services maison : triage (`triage/`), SOAR (`soar-v2/`), `oms-xdr`,
  `oms-ml`, `oms-graph`, robots déployés (`deploye/`) ;
- la console SOC, la PWA et leur backend (`mobile/`) ;
- les modules d'intégration, le kit d'enrôlement et les configurations
  versionnées (`integrations/`, `kit/`, `windows/`, `fortigate/`, `docker/`).

Hors périmètre : les produits tiers eux-mêmes (Graylog, OpenSearch, MongoDB,
nginx, Fortinet, etc.), à signaler à leur éditeur ; l'infrastructure
d'OMNITECH SECURITY non décrite par ce dépôt.

## Gestion des secrets

**Aucun secret n'est versionné.** Les valeurs réelles résident uniquement sur
le serveur :

- `00-vars.env` (permissions 600, ignoré par Git) pour la configuration du site ;
- fichiers d'environnement des services sous `/etc` (permissions restreintes) ;
- clés TLS, fichier de clé MongoDB, secret Graylog et clé HMAC d'intégrité
  sous `/etc` et `/root`.

Mesures dans le dépôt :

- `.gitignore` exclut `00-vars.env`, ses copies de sauvegarde, `SECRETS.md`,
  les clés, certificats et fichiers d'identifiants ;
- seuls des gabarits à valeurs factices sont versionnés :
  `00-vars.env.example` et [SECRETS.example.md](docs/securite-conformite/SECRETS.example.md) ;
- les crochets Git installés par `./scan-depot.sh --installer` bloquent tout
  commit contenant un motif de secret ;
- la recopie du code en service vers `deploye/` (`synchro-manifeste.sh`)
  lance ce même contrôle et annule la copie en cas d'alerte.

**En cas de fuite** (secret commité, journal exposé) :

1. révoquer ou changer immédiatement le secret concerné, avant toute autre action ;
2. retirer le secret de l'historique Git si le dépôt a été poussé, puis
   prévenir les détenteurs de clones ;
3. rechercher dans le SIEM toute utilisation du secret depuis la fuite ;
4. consigner l'incident selon la [procédure de gestion des incidents](docs/exploitation/PROCEDURE-INCIDENT.md).

## Données traitées

- Le SIEM traite des données personnelles (comptes, adresses IP, accès
  physiques). Les captures publiées dans le dépôt sont synthétiques ou
  pseudonymisées.
- Le triage des alertes transmet, pour les seuls cas ambigus, le contexte de
  l'alerte à une API LLM externe. Ce flux, sa finalité et son fournisseur
  doivent figurer au registre des traitements ; le service doit rester
  fonctionnel sans cette API (décision par règles en cas d'indisponibilité).

## Mesures de sécurité de la plateforme

Rappel des mesures en place sur l'installation de référence (détails dans le
[dossier d'architecture](docs/architecture/DOSSIER-ARCHITECTURE-SIEM.md)) :
services internes à l'écoute de l'interface locale, accès HTTPS par nginx,
filtrage nftables, données OpenSearch chiffrées au repos (LUKS2 et TPM2),
durcissement systemd des services maison (`27-harden-services.sh`), en-têtes
de sécurité et politique de contenu stricte pour la console, chaîne
d'intégrité HMAC des journaux (`60-integrity.sh`).
