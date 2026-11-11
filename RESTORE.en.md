# RESTORE.md — Full SIEM restore from a config backup

> The backups: `\\10.33.50.5\Public\SIEM\omni-siem-config_YYYY-MM-DD.tar.gz.enc`
> (daily 03:15, 14-day retention, local copy in `/var/backups/siem/`).
> **Decryption passphrase: `BACKUP_PASSPHRASE` (vault / 00-vars.env).**
> The LOGS (OpenSearch indices) are NOT backed up: after a restore, the history
> starts from scratch but all configuration and collection resume identically
> (agents point to the same FQDN/IP).

## 1. Prepare the replacement VM

Debian 12+, same IP **10.33.220.10**, same hostname `bx-it-graylog-vm`,
data disk mounted at **/data**. Install the same stack (versions as of the
backup — verifiable in the archive `root/omnitech-siem-setup/CONTEXT.md`):

```bash
# MongoDB 7, OpenSearch 2.x, Graylog 7.1 repositories (see official docs), then:
apt install -y mongodb-org opensearch graylog-server nginx cifs-utils
systemctl stop graylog-server opensearch mongod
```

## 2. Retrieve and decrypt the archive

```bash
mount -t cifs //10.33.50.5/Public /mnt -o guest,vers=3.0   # or credentials=
cp /mnt/SIEM/omni-siem-config_<DATE>.tar.gz.enc /root/
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
  -in omni-siem-config_<DATE>.tar.gz.enc -out omni-siem-config.tar.gz \
  -pass 'pass:<BACKUP_PASSPHRASE>'
```

## 3. Restore the files

```bash
tar xzf omni-siem-config.tar.gz -C /restore
# put everything back in place (overwrites the fresh configs):
cp -a /restore/etc/graylog /etc/
cp -a /restore/etc/default/graylog-server /etc/default/
cp -a /restore/etc/opensearch /etc/
# (mongod.conf: restored at step 4c, AFTER the mongorestore)
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

## 4. Restore the Graylog configuration (MongoDB)

```bash
# 4a. start mongod WITHOUT auth (package-default mongod.conf):
systemctl start mongod
mongorestore --drop --db graylog /restore/mongodump/graylog

# 4b. re-create the application user (user/pass = those of mongodb_uri
#     in the RESTORED server.conf, visible: grep mongodb_uri /etc/graylog/server/server.conf)
mongosh admin --eval 'db.createUser({user:"<USER>",pwd:"<PASS>",roles:[{role:"readWrite",db:"graylog"}]})'

# 4c. only AFTER: put our mongod.conf back (auth) and restart
cp -a /restore/etc/mongod.conf /etc/ && systemctl restart mongod
```

## 5. Start and verify

```bash
systemctl start opensearch && sleep 20
systemctl start graylog-server nginx
systemctl enable --now omni-backup-config.timer omni-m365-*.timer 2>/dev/null
# checks:
curl -sk https://bx-it-graylog-vm.omnitech.security/api/system/lbstatus --cacert /etc/graylog/certs/omnitech-rootca.crt
ss -tlnp | grep -E "5044|1514|1516|12201"   # inputs listening
```

The Winlogbeat agents / the FAZ / vSphere reconnect on their own (same IP/FQDN,
same CA). Console: https://bx-it-graylog-vm.omnitech.security (usual admin).

## 6. Points of attention

- `password_secret` (server.conf) is restored with the archive: essential, it is
  what decrypts the secrets stored in the database (SMTP, etc.).
- If the IP had to change: adapt /etc/hosts (FQDN -> 127.0.0.1 kept), the
  internal DNS, and nothing else (agents use the FQDN).
- Test the restore ONCE on a throwaway VM (ISO A.12.3 requirement: an untested
  backup is not a backup).
