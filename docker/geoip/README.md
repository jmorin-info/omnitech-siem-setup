# Bases GeoIP (DB-IP Lite) — montées dans Graylog

Placer ici `dbip-city-lite.mmdb` + `dbip-asn-lite.mmdb` pour que le **processeur GeoIP**
de Graylog enrichisse les IP publiques (`*_country_code`, `*_geolocation`) → **carte 3D vivante**.

Deux façons :
- **Copier** depuis la prod : `cp /var/lib/graylog-server/geoip/*.mmdb ./`
- **Télécharger** (DB-IP Lite, gratuit, sans compte) : `./fetch-geoip.sh`

Les `.mmdb` ne sont pas versionnés (volumineux, régénérables). Après dépôt, `./deploy.sh up`
puis dans Graylog : System ▸ Configurations ▸ GeoIP Resolver = activé (déjà restauré par le dump).
