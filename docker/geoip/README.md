# GeoIP databases (DB-IP Lite) — mounted into Graylog

Place here `dbip-city-lite.mmdb` + `dbip-asn-lite.mmdb` so that Graylog's **GeoIP processor**
enriches public IPs (`*_country_code`, `*_geolocation`) → **living 3D map**.

Two ways:
- **Copy** from production: `cp /var/lib/graylog-server/geoip/*.mmdb ./`
- **Download** (DB-IP Lite, free, no account): `./fetch-geoip.sh`

The `.mmdb` files are not versioned (large, regenerable). After placing them, `./deploy.sh up`
then in Graylog: System ▸ Configurations ▸ GeoIP Resolver = enabled (already restored by the dump).
