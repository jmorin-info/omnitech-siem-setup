Première distribution complète du dépôt : archive source avec révision Git réelle,
paquet Debian/Ubuntu, paquet RPM, catalogue de tous les fichiers et commande `omni-siem`.
Les paquets ne contiennent aucun secret de site ni bases de données préremplies.

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
Un téléchargement GitHub n'est pas encore un dépôt APT/DNF signé ; aucune commande
`apt install omni-siem` sans fichier local n'est annoncée.
