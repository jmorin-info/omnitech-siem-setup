# Encryption of data at rest — /data (OpenSearch) · OMNITECH SIEM

> ISO/IEC 27001 **A.8.24** (cryptography) / **A.5.33** (protection of records). · **Completed on 2026-06-14.**
> Production mechanism: **LUKS2 (inline header) + automatic TPM2 unlock**.

## What protects what
- ✅ Disk theft, decommissioning / RMA, theft of the **powered-off server**: `/data` unreadable without the key (the TPM never releases it outside this platform; recovery passphrase in the vault).
- ❌ Root compromised on a **powered-on machine** (FS mounted in clear) → covered elsewhere: RBAC (read-only role), signed log integrity, console/Beats TLS.
- Scope: only `/data` (the OpenSearch **logs**) is encrypted. The rootfs (OS + config) is not — sensitive config lives there (`00-vars.env` chmod 600). Possible future hardening: encrypt the rootfs.

## Configuration in place (reference)
| Item | Value |
|---|---|
| Device | `/dev/sda1` (7.3 TB) |
| Container | **LUKS2 inline header**, `aes-xts-plain64`, 512-bit key, PBKDF argon2id |
| LUKS UUID | `ff2e8939-9317-4932-a120-71113bb9d839` |
| Mapper | `/dev/mapper/cryptdata` |
| Filesystem | XFS (label `omni-data`), `path.data: /data/opensearch` + `/data/graylog-journal` |
| Keyslot 0 | **recovery passphrase** (→ Vaultwarden) |
| Keyslot 1 | **TPM2** (token `systemd-tpm2`, PCR 7) — automatic unlock at boot |
| `/etc/crypttab` | `cryptdata UUID=ff2e8939-… none luks,tpm2-device=auto,nofail` |
| `/etc/fstab` | `/dev/mapper/cryptdata /data xfs defaults,noatime,nofail 0 2` |
| Header backup | AES-256 encrypted → `//10.33.50.5/Public/SIEM/luks/omni-luks-header-YYYY-MM-DD.img.enc` + local copy `/root/` |

> ⚠️ **TPM on SHA-1 PCR bank** (this TPM does not expose SHA-256) → slightly less robust sealing, with no impact on protection at rest. Hardening: enable the SHA-256 PCR bank in the Dell BIOS, then re-enroll (see *Recovery*).

## Key security (in order of importance)
1. **Recovery passphrase** (keyslot 0) → **Vaultwarden only**, never in clear on the server. The only way to reopen `/data` if the TPM / motherboard changes. The temporary file `/etc/luks/.data-pass` is **destroyed (`shred`) after TPM enrollment + vaulting**.
2. **Header backup** (`luksHeaderBackup`, encrypted, out-of-band SMB): a corrupted header = `/data` unrecoverable even with the passphrase. → restorable (see *Recovery*). Re-back up after **any** keyslot change.
3. **TPM2** = convenience (transparent unlock at boot); disk unreadable if removed/stolen (another platform).

## Recovery — routine operation
```bash
# MANUAL open (TPM unavailable) — requires the recovery passphrase (Vaultwarden)
cryptsetup open /dev/sda1 cryptdata
mount /data
systemctl start opensearch graylog-server

# The TPM no longer unlocks at boot (firmware update / Secure Boot / PCR bank):
#   at boot, enter the passphrase at the prompt, then re-enroll the TPM:
systemd-cryptenroll /dev/sda1 --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7

# Restore the header from the out-of-band backup (corrupted header):
#   1) retrieve the .enc from the SMB share, decrypt it (BACKUP_PASSPHRASE: 00-vars.env / vault)
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in omni-luks-header-YYYY-MM-DD.img.enc -out hdr.img
#   2) restore:
cryptsetup luksHeaderRestore /dev/sda1 --header-backup-file hdr.img

# Add / change the recovery passphrase:
cryptsetup luksAddKey /dev/sda1            # (then luksRemoveKey for the old one)

# Re-back up the header after ANY keyslot change:
cryptsetup luksHeaderBackup /dev/sda1 --header-backup-file /root/omni-luks-header-$(date +%F).img
```

## How it was deployed (2026-06-14)
**Fresh encrypted reformat** method (fast, ~10 min) rather than an in-place re-encryption (≈ **21 h** for 7.3 TB at the block level). Possible because **all the config is outside `/data`** (MongoDB `/var/lib/mongodb`, scripts `/root/omnitech-siem-setup`, lookups, Graylog `data_dir` `/var/lib/graylog-server`): only the **indexed logs** lived on `/data`, deemed reconstructible (purge/repopulation already practiced).
```bash
systemctl stop graylog-server opensearch          # /data freed
umount /data
cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 \
   --pbkdf argon2id --batch-mode --key-file /etc/luks/.data-pass /dev/sda1
cryptsetup open --key-file /etc/luks/.data-pass /dev/sda1 cryptdata
mkfs.xfs -f -L omni-data /dev/mapper/cryptdata
# /etc/fstab -> /dev/mapper/cryptdata ; mount /data
mkdir -p /data/opensearch /data/graylog-journal
chown opensearch:opensearch /data/opensearch ; chown graylog:graylog /data/graylog-journal ; chmod 750 /data/*
systemd-cryptenroll /dev/sda1 --tpm2-device=auto --tpm2-pcrs=7 --unlock-key-file=/etc/luks/.data-pass
# /etc/crypttab (see table) ; systemctl daemon-reload
systemctl start opensearch graylog-server
bash 54-post-purge-repopulate.sh                  # rebuilds the index ranges + repopulates
# TPM validation via reboot (with an operator, console accessible)
```

## Appendix — "preserve the data" alternative (in-place re-encryption, **not used here**)
If one day it becomes necessary to encrypt a volume **without losing** its data, accepting the duration (≈ 21 h / 7.3 TB):
- XFS does not shrink → **detached header** mandatory (never `--reduce-device-size`, which breaks the XFS remount):
  `cryptsetup reencrypt --encrypt --header /etc/luks/hdr.img --type luks2 --resilience checksum /dev/sdX`
  (resumable via `--resume-only --header …`), then `open --header` / `mount` / `systemd-cryptenroll --header`.
- **Online encryption** (`cryptsetup open` first, then `reencrypt --resume-only --active-name cryptdata`) makes it possible to keep the volume **mounted and in service** during the operation.
- ⚠️ You **cannot natively cancel** a partial `--encrypt` (`--decrypt` refuses it: *"conflicting --decrypt option"*): you must either see it through, or copy back the head zone in clear via the open mapper. *(Validated on loopback on 2026-06-14.)*

## Complementary (in transit — lower priority, isolated SIEM VLAN = mitigation)
ESET (1515) / vSphere (1516) / FortiGate-FAZ (1514) in **clear** syslog → migrate to **syslog-over-TLS** (supported by ESET PROTECT, vSphere, FortiGate) where possible. Beats (5044) and the console (9000) are already on TLS.
