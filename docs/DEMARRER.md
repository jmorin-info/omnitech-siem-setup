# Commencer avec OMNI SIEM

Choisir le parcours correspondant à votre machine. Les commandes d'installation
ne servent pas à mettre à jour un SIEM déjà en service.

| Votre objectif | Guide à suivre |
|---|---|
| Installer sur une machine Ubuntu neuve | [Ubuntu, ligne par ligne](UBUNTU-DEMARRAGE.md) |
| Vérifier les prérequis et le contenu du socle | [Installation et composants](INSTALLATION.md) |
| Mettre à jour une instance existante | [Mise à jour du code](UPDATES.md) |
| Ajouter WatchGuard, Ubiquiti UniFi ou Palo Alto | [Modules et dashboards](INTEGRATIONS-MODULAIRES.md) |
| Utiliser les menus dans le terminal SSH | [Interface d'administration](INTERFACE-ADMINISTRATION.md) |
| Résoudre un `Not Found` sur `/soc/` | [Console et diagnostic](CONSOLE-DEPLOIEMENT.md) |
| Vérifier les résultats des tests Ubuntu 26.04 | [Qualification et rapports](QUALIFICATION-UBUNTU2604.md) |

## Première installation

Prévoir une machine dédiée amd64 avec AVX, au moins 16 Go de RAM et un stockage
adapté au volume de logs. Ubuntu 24.04 suit les plateformes éditeurs de cette
pile ; Ubuntu 26.04 exige l'option expérimentale et un noyau compatible.

Suivre [le guide Ubuntu](UBUNTU-DEMARRAGE.md) dans l'ordre : récupérer le projet,
renseigner le site, générer les secrets techniques, examiner le plan, installer,
puis vérifier le résultat. Continuer uniquement lorsque `blockers` est vide.
Les secrets restent sur la machine ; aucune création de commit local n'est requise.

Le profil installé comprend MongoDB, OpenSearch, Graylog, les entrées et règles
de base, les détections initiales, le dashboard SOC, nginx, `/soc/`, son backend
et une sauvegarde quotidienne. Il termine par des contrôles de réception.

## Mise à jour d'une instance existante

Le [gestionnaire de mise à jour](UPDATES.md) prépare une révision Git précise,
signale les conflits locaux et conserve les secrets et les bases. La publication
des fichiers servis et l'activation du code des services sont des étapes explicites.
Une mise à jour GitHub ne modifie pas automatiquement la production ni ses packs.

Les changements de versions MongoDB/OpenSearch/Graylog ont leur procédure de
migration ; une sauvegarde de code ne permet pas d'annuler une migration de base.

## Sources et extensions

Après le socle, installer les modules souhaités et configurer l'envoi de logs
depuis les équipements. Chaque [module](INTEGRATIONS-MODULAIRES.md) indique les
formats couverts, le port, les champs et le dashboard. Les autres connecteurs
(M365, SEAL, etc.) nécessitent les accès et paramètres de votre site.
Les fonctions ML/XDR, SOAR et scans actifs ont leur propre activation.

Les captures et descriptions détaillées des README présentent l'installation
de référence, avec ses extensions. Elles ne constituent pas une liste de services
automatiquement activés sur une machine neuve. Un dashboard vide peut simplement
attendre sa source ; une page sans source est indiquée comme non configurée.

## Où trouver le reste

Les guides ci-dessus sont les parcours opérateur. [L'index documentaire](00-INDEX.md)
rassemble ensuite les références techniques, procédures d'exploitation et documents
ISO. Les audits datés décrivent l'état observé à leur date ; pour connaître la
validation d'une version, consulter le rapport correspondant à son commit.
