# RESTORE.md — Restauration complète du SIEM depuis une sauvegarde config

> Les sauvegardes : `\\10.33.50.5\Public\SIEM\omni-siem-config_YYYY-MM-DD.tar.gz.enc`
> (quotidiennes 03:15, rétention 14 j, copie locale dans `/var/backups/siem/`).
> **Passphrase de déchiffrement : `BACKUP_PASSPHRASE` (coffre-fort / 00-vars.env).**
> Les LOGS (indices OpenSearch) ne sont PAS sauvegardés : après restauration,
> l'historique repart de zéro mais toute la configuration et la collecte
> reprennent à l'identique (les agents pointent sur le même FQDN/IP).

## 1. Préparer la VM de remplacement

Debian 12+, même IP **10.33.220.10**, même hostname `bx-it-graylog-vm`,
disque data monté sur **/data**. Installer la même pile (versions au moment
de la sauvegarde — vérifiables dans l'archive `root/omnitech-siem-setup/CONTEXT.md`) :

```bash
# dépôts MongoDB 7, OpenSearch 2.x, Graylog 7.1 (cf. docs officielles), puis :
apt install -y mongodb-org opensearch graylog-server nginx cifs-utils
systemctl stop graylog-server opensearch mongod
```

## 2. Récupérer et déchiffrer l'archive

```bash
mount -t cifs //10.33.50.5/Public /mnt -o guest,vers=3.0   # ou credentials=
cp /mnt/SIEM/omni-siem-config_<DATE>.tar.gz.enc /root/
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
  -in omni-siem-config_<DATE>.tar.gz.enc -out omni-siem-config.tar.gz \
  -pass 'pass:<BACKUP_PASSPHRASE>'
```

## 3. Restaurer les fichiers

```bash
tar xzf omni-siem-config.tar.gz -C /restore
# tout remettre en place (ecrase les confs fraiches) :
cp -a /restore/etc/graylog /etc/
cp -a /restore/etc/default/graylog-server /etc/default/
cp -a /restore/etc/opensearch /etc/
# (mongod.conf : remis a l'etape 4c, APRES le mongorestore)
cp -a /restore/etc/nginx /etc/
cp -a /restore/etc/hosts /etc/
cp -a /restore/etc/nftables.conf /etc/ && systemctl restart nftables
cp -a /restore/etc/systemd/system/omni-* /etc/systemd/system/
cp -a /restore/usr/local/sbin/* /usr/local/sbin/
cp -a /restore/var/www/siem-kit /var/www/
cp -a /restore/root/omnitech-siem-setup /root/
mkdir -p /data/opensearch /data/graylog-journal
chown -R opensearch:opensearch /data/opensearch
chown -R graylog:graylog /data/graylog-journal
systemctl daemon-reload
```

## 4. Restaurer la configuration Graylog (MongoDB)

```bash
# 4a. demarrer mongod SANS auth (mongod.conf par defaut du paquet) :
systemctl start mongod
mongorestore --drop --db graylog /restore/mongodump/graylog

# 4b. recreer l'utilisateur applicatif (user/pass = ceux de mongodb_uri
#     dans le server.conf RESTAURE, visible : grep mongodb_uri /etc/graylog/server/server.conf)
mongosh admin --eval 'db.createUser({user:"<USER>",pwd:"<PASS>",roles:[{role:"readWrite",db:"graylog"}]})'

# 4c. seulement APRES : remettre notre mongod.conf (auth) et redemarrer
cp -a /restore/etc/mongod.conf /etc/ && systemctl restart mongod
```

## 5. Démarrer et vérifier

```bash
systemctl start opensearch && sleep 20
systemctl start graylog-server nginx
systemctl enable --now omni-backup-config.timer omni-m365-*.timer 2>/dev/null
# verifs :
curl -sk https://bx-it-graylog-vm.omnitech.security/api/system/lbstatus --cacert /etc/graylog/certs/omnitech-rootca.crt
ss -tlnp | grep -E "5044|1514|1516|12201"   # inputs a l'ecoute
```

Les agents Winlogbeat / le FAZ / vSphere se reconnectent seuls (même IP/FQDN,
même CA). Console : https://bx-it-graylog-vm.omnitech.security (admin habituel).

## 6. Points d'attention

- `password_secret` (server.conf) est restauré avec l'archive : indispensable,
  c'est lui qui déchiffre les secrets stockés en base (SMTP, etc.).
- Si l'IP devait changer : adapter /etc/hosts (FQDN -> 127.0.0.1 conservé),
  le DNS interne, et rien d'autre (les agents utilisent le FQDN).
- Tester la restauration UNE FOIS sur une VM jetable (exigence ISO A.12.3 :
  un backup non testé n'est pas un backup).
