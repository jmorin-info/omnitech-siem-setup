# Déployer ou réparer la console SOC

La console du projet est publiée par **nginx sur HTTPS, port 443**, sous `/soc/`.
Le port 9000 sert Graylog et son API ; il ne sert pas les fichiers de cette console.
Une page Graylog fonctionnelle n'implique donc pas que `/soc/` soit installé.

## Installation native

Sur une installation neuve, `sudo bash install.sh --apply` inclut la console.
Sur un SIEM existant, depuis sa copie du dépôt mise à jour :

```bash
# Inspecter les routes à ajouter et les fichiers à publier (aucune modification).
sudo bash tools/install-console.sh

# Installer les composants manquants et publier la console.
sudo bash 71-soc-console.sh
```

L'opération copie tous les assets publics de `mobile/soc/` : scripts `app*.js`,
bibliothèques, images de carte, icônes, manifeste et service worker. Elle ajoute
les routes manquantes dans `/etc/nginx/sites-enabled/graylog`, sans remplacer
les locations ni les restrictions d'accès qui existent déjà. Pour un autre vhost,
définir `NGINX_SITE=/chemin/du/vhost` explicitement.

La configuration nginx modifiée est sauvegardée hors des répertoires inclus,
validée par `nginx -t`, puis rechargée. Si la validation ou le rechargement échoue,
le fichier est restauré. Les assets publics déjà copiés ne sont pas annulés par
ce retour arrière de configuration.

Si le backend est absent, il est installé sous `/opt/omni-siem/console` avec un
compte système dédié, des secrets générés localement et une configuration dans
`/etc/default/omni-mobile`. Les accès Graylog existants servent à l'authentification ;
AD/LDAPS n'est pas un prérequis imposé à tous les sites. L'API locale HTTP permet
le bootstrap ; une API TLS exige son FQDN et sa CA (`SIEM_FQDN`, `GRAYLOG_API_CA`).

Un backend installé et identifié par ce mécanisme possède `backend.json` sous
son répertoire applicatif. Lors d'une publication ultérieure, son empreinte est
contrôlée, l'ancien code sauvegardé, le nouveau code activé et sa santé vérifiée.
En cas d'échec, l'ancien code est restauré et le service redémarré. Un changement
local du backend bloque cette activation. Les secrets et données ne sont pas remplacés.

Pour un **ancien service personnalisé**, son code et sa configuration restent en
place. Vérifier `systemctl cat omni-mobile-api` et adapter sa procédure de mise en
service ; une mise à jour du dépôt ne met pas nécessairement à jour son `ExecStart`.
Les endpoints de SOAR, graphe ou supervision qui dépendent d'autres services peuvent
rester indisponibles tant que ces extensions ne sont pas configurées.

## Distinguer les erreurs

| Symptôme | Vérifications et action |
|---|---|
| `404 Not Found` sur `/soc/` | Vérifier l'URL sans `:9000`, le bon vhost nginx et la présence de `/var/www/siem-soc/index.html`. Publier avec le script ci-dessus. |
| Page présente, écran vide ou JS en 404 | Vérifier `app-boot.js`, `app-loader.js`, `app.js`, icônes et bibliothèques. Une copie du seul HTML est insuffisante. |
| `502 Bad Gateway` sur `/m/api/` | Vérifier `omni-mobile-api`, le port local 8090 et les logs du backend. Une correction des fichiers statiques ne répare pas son transport Graylog. |
| Réponse `401` sans connexion | Comportement normal pour un endpoint protégé ; vérifier ensuite le login avec un compte Graylog valide. |
| Login refusé / TLS | Vérifier la CA et le nom du serveur utilisés par le backend ; ne pas désactiver la validation TLS pour contourner l'erreur. |
| Page 200 mais graphiques vides | Vérifier les sources, pipelines, champs et extensions. HTTP 200 n'atteste pas que les données arrivent. |

```bash
systemctl status nginx omni-mobile-api --no-pager
nginx -t
nginx -T 2>/dev/null | rg 'location|siem-soc|8090'
ls -l /var/www/siem-soc/index.html /var/www/siem-soc/app-boot.js
curl -fsS http://127.0.0.1:8090/m/api/vapid
journalctl -u omni-mobile-api -n 50 --no-pager
```

Depuis le navigateur ou avec la CA approuvée du site, contrôler `/soc/`,
`/soc/app-boot.js`, `/soc/app-loader.js`, `/soc/icons/icon-192.png` et
`/soc/manifest.webmanifest`. Les anciennes versions mises en cache par un service
worker peuvent nécessiter un rechargement ou l'effacement des données du site.

## Docker

La console est un service Compose distinct du service Graylog :

```bash
cd docker
docker compose ps
docker compose logs --tail=80 console nginx
docker compose config --quiet
```

Le frontal reste `https://<SERVER_NAME>/soc/` sur le port 443. Le port Graylog 9000
est publié sur loopback pour le diagnostic. Les scripts natifs de configuration
nginx/systemd ne doivent pas être exécutés dans cette variante.

L'entrypoint écrit sa configuration privée dans le volume de données avec les
droits de l'utilisateur du conteneur ; il accepte secrets d'environnement et
fichiers `*_FILE`. Le transport HTTP vers le seul nom de service interne `graylog`
est une option explicite du conteneur. Le navigateur continue d'utiliser HTTPS.

## Vérifications automatisées et limites

Les tests couvrent les assets, les routes absentes, la préservation des ACL,
le rollback nginx, le lancement de l'entrypoint avec les deux modes de secrets,
le refus HTTP vers d'autres serveurs et le rollback du backend géré.
Un test réel de Nginx 1.24 sur Ubuntu 24.04 vérifie les réponses 200 et 404 des
ressources. La pile Docker complète et la collecte de chaque équipement doivent
encore faire l'objet d'une recette sur l'environnement cible.
