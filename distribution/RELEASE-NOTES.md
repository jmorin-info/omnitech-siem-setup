Première distribution complète du dépôt : archive source avec révision Git réelle,
paquet Debian/Ubuntu, paquet RPM, catalogue de tous les fichiers et commande `omni-siem`.
Les paquets ne contiennent aucun secret de site ni bases de données préremplies.
Le parcours `adopt` prépare une installation existante dans le chemin canonique,
avec détection bornée, conservation de la révision et des secrets, adaptation des
références reconnues et retour arrière. Les données des bases ne sont pas déplacées.

Le socle serveur (MongoDB, OpenSearch, Graylog, collecte de base, détections,
dashboards, console SOC et sauvegarde) s'installe explicitement après configuration.
Les extensions figurent dans le catalogue ; leurs dépendances, identifiants et
actions restent propres au site. Aucun script de purge ni de réponse active n'est
lancé globalement.

Consulter `docs/DISTRIBUTION.md` pour les commandes, les plateformes, la reprise et
les limites. Ubuntu 26.04 reste expérimental. Le RPM distribue le projet et les
outils ; il ne qualifie pas le serveur SIEM sur RHEL/Rocky/Fedora.

Cette livraison est une préversion. La publication du brouillon attend les
contrôles du commit retenu et la recette VM avec l'option `package_install`.
Le canal de préversion APT/DNF signé est préparé par un workflow séparé, qui exige
les preuves du commit exact et vérifie les fichiers hébergés avant publication.
Suivre `docs/DISTRIBUTION-SIGNATURES.md` après sa réussite. Les versions publiques
antérieures restent inchangées. Cette signature ne qualifie pas une version 1.0 stable.
