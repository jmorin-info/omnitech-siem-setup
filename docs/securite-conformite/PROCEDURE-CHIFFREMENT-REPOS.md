# Chiffrement des données au repos — /data (OpenSearch) · OMNITECH SIEM

> ISO/IEC 27001 **A.8.24** (cryptographie) / **A.5.33** (protection des enregistrements). · **Réalisé le 2026-06-14.**
> Dispositif en production : **LUKS2 (header inline) + déverrouillage automatique TPM2**.

## Ce qui protège quoi
- ✅ Vol de disque, mise au rebut / SAV, vol du **serveur éteint** : `/data` illisible sans la clé (le TPM ne la libère jamais hors de cette plateforme ; passphrase de secours au coffre).
- ❌ Root compromis **machine allumée** (FS monté en clair) → couvert par ailleurs : RBAC (rôle lecture seule), intégrité signée des journaux, TLS console/Beats.
- Périmètre : seul `/data` (les **logs** OpenSearch) est chiffré. Le rootfs (OS + config) ne l'est pas — la config sensible y vit (`00-vars.env` chmod 600). Durcissement futur possible : chiffrer le rootfs.

## Configuration en place (référence)
| Élément | Valeur |
|---|---|
| Device | `/dev/sda1` (7,3 To) |
| Conteneur | **LUKS2 header inline**, `aes-xts-plain64`, clé 512 bits, PBKDF argon2id |
| LUKS UUID | `ff2e8939-9317-4932-a120-71113bb9d839` |
| Mapper | `/dev/mapper/cryptdata` |
| Filesystem | XFS (label `omni-data`), `path.data: /data/opensearch` + `/data/graylog-journal` |
| Keyslot 0 | **passphrase de secours** (→ Vaultwarden) |
| Keyslot 1 | **TPM2** (token `systemd-tpm2`, PCR 7) — déverrouillage auto au boot |
| `/etc/crypttab` | `cryptdata UUID=ff2e8939-… none luks,tpm2-device=auto,nofail` |
| `/etc/fstab` | `/dev/mapper/cryptdata /data xfs defaults,noatime,nofail 0 2` |
| Sauvegarde header | chiffrée AES-256 → `//10.33.50.5/Public/SIEM/luks/omni-luks-header-AAAA-MM-JJ.img.enc` + copie locale `/root/` |

> ⚠️ **TPM en banque PCR SHA-1** (ce TPM n'expose pas SHA-256) → scellement un peu moins robuste, sans impact sur la protection au repos. Durcissement : activer la banque PCR SHA-256 au BIOS Dell, puis ré-enrôler (cf. *Recovery*).

## Sécurité des clés (ordre d'importance)
1. **Passphrase de secours** (keyslot 0) → **Vaultwarden uniquement**, jamais en clair sur le serveur. Seul moyen de rouvrir `/data` si le TPM / la carte mère change. Le fichier temporaire `/etc/luks/.data-pass` est **détruit (`shred`) après enrôlement TPM + mise au coffre**.
2. **Sauvegarde du header** (`luksHeaderBackup`, chiffrée, hors-bande SMB) : un header corrompu = `/data` irrécupérable même avec la passphrase. → restaurable (cf. *Recovery*). Re-sauvegarder après **tout** changement de keyslot.
3. **TPM2** = confort (déverrouillage transparent au boot) ; disque illisible si sorti/volé (autre plateforme).

## Recovery — exploitation courante
```bash
# Ouverture MANUELLE (TPM indisponible) — demande la passphrase de secours (Vaultwarden)
cryptsetup open /dev/sda1 cryptdata
mount /data
systemctl start opensearch graylog-server

# Le TPM ne déverrouille plus au boot (MAJ firmware / Secure Boot / banque PCR) :
#   au boot, saisir la passphrase à l'invite, puis ré-enrôler le TPM :
systemd-cryptenroll /dev/sda1 --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7

# Restaurer le header depuis la sauvegarde hors-bande (header corrompu) :
#   1) récupérer le .enc sur le partage SMB, le déchiffrer (BACKUP_PASSPHRASE : 00-vars.env / coffre)
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in omni-luks-header-AAAA-MM-JJ.img.enc -out hdr.img
#   2) restaurer :
cryptsetup luksHeaderRestore /dev/sda1 --header-backup-file hdr.img

# Ajouter / changer la passphrase de secours :
cryptsetup luksAddKey /dev/sda1            # (puis luksRemoveKey pour l'ancienne)

# Re-sauvegarder le header après TOUT changement de keyslot :
cryptsetup luksHeaderBackup /dev/sda1 --header-backup-file /root/omni-luks-header-$(date +%F).img
```

## Comment ç'a été déployé (2026-06-14)
Méthode **reformatage chiffré à neuf** (rapide, ~10 min) plutôt qu'un rechiffrement in-place (≈ **21 h** pour 7,3 To au niveau bloc). Possible parce que **toute la config est hors `/data`** (MongoDB `/var/lib/mongodb`, scripts `/root/omnitech-siem-setup`, lookups, `data_dir` Graylog `/var/lib/graylog-server`) : seuls les **logs indexés** vivaient sur `/data`, jugés reconstituables (purge/repeuplement déjà pratiqués).
```bash
systemctl stop graylog-server opensearch          # /data libéré
umount /data
cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 \
   --pbkdf argon2id --batch-mode --key-file /etc/luks/.data-pass /dev/sda1
cryptsetup open --key-file /etc/luks/.data-pass /dev/sda1 cryptdata
mkfs.xfs -f -L omni-data /dev/mapper/cryptdata
# /etc/fstab -> /dev/mapper/cryptdata ; mount /data
mkdir -p /data/opensearch /data/graylog-journal
chown opensearch:opensearch /data/opensearch ; chown graylog:graylog /data/graylog-journal ; chmod 750 /data/*
systemd-cryptenroll /dev/sda1 --tpm2-device=auto --tpm2-pcrs=7 --unlock-key-file=/etc/luks/.data-pass
# /etc/crypttab (cf. tableau) ; systemctl daemon-reload
systemctl start opensearch graylog-server
bash 54-post-purge-repopulate.sh                  # reconstruit les index ranges + repeuple
# validation du TPM par reboot (avec opérateur, console accessible)
```

## Annexe — alternative « préserver les données » (rechiffrement in-place, **non utilisé ici**)
Si un jour il faut chiffrer **sans perdre** les données d'un volume, en acceptant la durée (≈ 21 h / 7,3 To) :
- XFS ne rétrécit pas → **header détaché** obligatoire (jamais `--reduce-device-size`, qui casse le remontage XFS) :
  `cryptsetup reencrypt --encrypt --header /etc/luks/hdr.img --type luks2 --resilience checksum /dev/sdX`
  (reprenable via `--resume-only --header …`), puis `open --header` / `mount` / `systemd-cryptenroll --header`.
- Le **chiffrement online** (`cryptsetup open` d'abord, puis `reencrypt --resume-only --active-name cryptdata`) permet de garder le volume **monté et en service** pendant l'opération.
- ⚠️ On **ne peut pas annuler nativement** un `--encrypt` partiel (`--decrypt` le refuse : *« option --decrypt conflictuelle »*) : il faut soit le mener à terme, soit recopier la zone de tête en clair via le mapper ouvert. *(Validé sur loopback le 2026-06-14.)*

## Complémentaire (transit — priorité moindre, VLAN SIEM isolé = palliatif)
ESET (1515) / vSphere (1516) / FortiGate-FAZ (1514) en syslog **clair** → migrer en **syslog-over-TLS** (supporté par ESET PROTECT, vSphere, FortiGate) quand possible. Beats (5044) et console (9000) sont déjà en TLS.
