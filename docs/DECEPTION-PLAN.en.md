# OMNI Sentinel — Decoy seeding plan (DECEPTION)

> **Status: DRY-RUN — Julien's action (CISO).** The *detection* layer (the trap) is
> already **armed and verified** (script `88-deception-honeytokens.sh`, lookup `omni-deception`,
> 5 rules, 3 alerts). This document describes the **bait** to be placed so the traps
> snap shut. **Collision verified = 0** over 30 days for all decoys below.

## Golden rules (otherwise false positive or risk)

1. **Co-managed tenant `invissys.com`: FORBIDDEN.** All the decoys below are placed
   exclusively on the **OMNITECH.SECURITY** AD / infrastructure.
2. **Dormancy discipline (the only FP vector).** A decoy account must remain
   **inert**: never wired to a sync (MSOL/ADSync), an RMM (ninjaone), a backup
   tool, or an authenticated scanner. *No usage = no event = no FP.*
3. **Disabled account + long random password.** The decoy must never be usable for
   real; only the attacker who *attempts* to use it does so → that is the signal.
4. **Adding a decoy = 1 line in `lookups/deception-decoys.csv`** (key,type) →
   active in < 60 s (CSV re-read), without touching the code. Re-run `88` to redeploy the CSV.

## Environment map (derived live from the data)

- **Host naming**: Dominant scheme: <site>-<function|service>-<token>-<type>, all lowercase. Site: 'bx' (Bordeaux, HQ, ~90% of the estate), 'iv'/'in' (secondary site), 'lc', 'vm-paca' (PACA site), 'vm-bdx'/'vm-dev' (Bordeaux/dev VMs). Function/service (2nd 
- **Account naming**: AD domain: OMNITECH.SECURITY (NetBIOS OMNITECH), DNS domain omnitech-security.fr. Three clear classes: (1) human USERS = lowercase login, two coexisting formats -> old format 'initial+surname' sticks (jmorin, psoubieille, v
- **Service accounts**: Dominant pattern 'svc_<service>' lowercase with underscore: svc_siem, svc_intranet. Minority variant with hyphen 'svc-<service>': svc-fortimanager. For a credible decoy: favor 'svc_' (
- **Domain controllers**: bx-ad-01-it-vm, bx-ad02-it-vm, vm-paca-ad1 (PACA site, derived from the machine account VM-PACA-AD1$; not a 4768 log emitter in the SIEM but authenticates as a remote DC)
- **Crown jewels (targets protected by the decoys)**:
  - `bx-ad-01-it-vm + bx-ad02-it-vm (OMNITECH.SECURITY AD domain controllers)` — Exclusive emitters of EID 4768/KDC (144k + 118k). Compromise = full domain control (DCSync, Golden Ticket, account creation). 
  - `vm-paca-ad1 (DC of the remote PACA site)` — Machine account VM-PACA-AD1$ authenticates as a DC; AD replication = same trust level as the Bordeaux DCs, inter-site pivot point
  - `bx-it-graylog-vm (Graylog SIEM)` — The SIEM itself. Its compromise blinds detection and allows trace erasure. Associated account svc_siem. (NB MEMORY designates bx-it
  - `bx-veeam-it-sv + bx-veeam-prx1 + bx-veeam-prx2-it-vm (Veeam backup infrastructure)` — Prime ransomware target: destroying/encrypting backups removes restore capability and maximizes extortion leverage. Com
  - `vaultwarden.omnitech-security.fr (Vaultwarden password vault)` — Centralized storage of secrets/passwords (451k evts). A single compromise exposes credentials across the whole estate = massive escalatio
  - `bx-pki2022 + bx-info-eset-vm / ADCS (PKI/ESET)` — PKI 2022 (ADCS): abuse of certificate templates (ESC1-8) = persistence and identity impersonation at domain scale. ESET = EDR console
  - `bx-files-it-vm (file server) + Omnitech-SSRS (SQL Server Reporting Services)` — Sensitive centralized business data (SMB shares) and application SQL database. Direct targets for exfiltration and encryption.
  - `vcenter + bx-esxi-01..04-it (vSphere / ESXi)` — Hypervisors hosting all the VMs (DC, SIEM, Veeam, files). Compromise of vCenter/ESXi = encryption of all VMs in one 
- **Likely footholds (attack origin)**:
  - bx-dev-* (the largest class ~13.6M evts: dev workstations/VMs, bx-dev-tca1/2/3-pc, bx-dev-dell1/2-pc, bx-dev-seal-vm, bx-dev-repo-vm — broad right
  - bx-qa-* (~8.2M: QA benches bx-qa-seal-vm, bx-qa-rle-lt, bx-qa-test-vm — often lightly hardened)
  - bx-com/bx-comm-* (~5.1M: sales bx-com-jma-lt2, bx-com-vle-lt2 — phishing-exposed, roaming)
  - bx-dom-user1..4-lt (generic standard user workstations — large and homogeneous population)
  - iv-tech-* / in-dev-* (~3.8M: secondary site, roaming technician workstations, inter-site lateral surface)

## Decoy AD accounts (type `identity`)

### `svc_veeam`  ·  lookup key = `svc_veeam`
- **Blends in as**: AD service account for the Veeam backup infrastructure (dominant svc_ underscore pattern, like svc_siem/svc_intranet). Highly enticing name: a 'backup service' account implies extended rights on the servers and 
- **Attack path intercepted**: Kerberoasting / service account recon -> the attacker enumerates SPNs or lists svc_* accounts from a foothold (bx-dev-*, bx-qa-*), spots 'svc_veeam' as a gateway to the Veeam backup infrastructure (bx-veeam-it-sv, bx-veeam-prx1/2) and attempts a TGS-RE
- **Fires on**: Any 4768 (AS-REQ/TGT) or 4769 (TGS-REQ) or 4624/4625 where winlogbeat_winlog_event_data_TargetUserName == 'svc_veeam' (4768) or winlogbeat_winlog_event_data_ServiceName == 'svc_veeam' (4769). The rul
- **How to plant it (dry-run)**: Julien creates the account in DRY-RUN on the OMNITECH.SECURITY AD (never the co-managed tenant invissys.com): New-ADUser -WhatIf 'svc_veeam' in a service-account OU, long random password never distributed, attach an attractive SPN to it (e.g. setspn -A VEEAM/bx-veeam-it-sv svc_veeam) so it is kerberoastab

### `svc_sql`  ·  lookup key = `svc_sql`
- **Blends in as**: AD service account for an application SQL database (svc_ underscore pattern). Blends alongside the real Omnitech-SSRS (SQL Server Reporting Services) and bx-files-it-vm: a 'svc_sql' is exactly what an attacker 
- **Attack path intercepted**: Kerberoasting of a classic SQL service account (SQL svc accounts often have weak passwords and an MSSQLSvc SPN). The attacker cracks the ticket offline then targets the business data of bx-files-it-vm / the SSRS database (Omnitech-SSRS) for exfiltration or encryp
- **Fires on**: 4769 with winlogbeat_winlog_event_data_ServiceName == 'svc_sql' (TGS request, kerberoasting signature), or 4768 with winlogbeat_winlog_event_data_TargetUserName == 'svc_sql', or 4625/4624. Match via th
- **How to plant it (dry-run)**: DRY-RUN on the OMNITECH AD only: New-ADUser -WhatIf 'svc_sql' with SPN MSSQLSvc/bx-sql-it-vm:1433 (setspn -A ...), description 'SQL Server service account', strong password never used, interactive logon denied. No real SQL service runs under this account. Add key 'svc_sql' -> 'ad_account' to the CSV o

### `svc_backup`  ·  lookup key = `svc_backup`
- **Blends in as**: Generic 'backup' AD service account (dominant svc_ underscore pattern). Universally enticing name: an attacker assumes a 'svc_backup' holds broad read rights (often a backup operato
- **Attack path intercepted**: High-privilege account recon -> abuse of the Backup Operators group (raw reading of protected files, even SeBackupPrivilege to dump SAM/NTDS.dit). Path toward DCSync / extraction of the AD database from the DCs (bx-ad-01-it-vm, bx-ad02-it-vm) or toward the serve
- **Fires on**: 4768 (TGT) or 4769 (TGS) or 4624 (logon) or 4672 (special privileges assigned) with winlogbeat_winlog_event_data_TargetUserName == 'svc_backup' (or _ServiceName on 4769). lookup_value('omni-deception
- **How to plant it (dry-run)**: DRY-RUN OMNITECH AD: New-ADUser -WhatIf 'svc_backup', add it NOMINALLY (in dry-run/-WhatIf) as a decoy member of a privileged-sounding group (e.g. a fake 'Backup Operators Svc' group), description 'Scheduled backup service', credentials never distributed, interactive logon denied. Key 'svc_backup'

### `adm-sql`  ·  lookup key = `adm-sql`
- **Blends in as**: Delegated administration account (dominant adm- pattern: adm-jmorin, adm-aculleron, adm-retevenard...). 'adm-sql' reads as the designated admin of the SQL databases — a direct target for anyone seeking to control the data tie
- **Attack path intercepted**: After compromising a workstation, the attacker enumerates adm-* (privileged) accounts and targets 'adm-sql' to pivot toward the SQL / SSRS servers (Omnitech-SSRS) and bx-files-it-vm. Any auth or Kerberos attempt on this account = lateral movement toward the
- **Fires on**: 4768/4769/4624/4625 with winlogbeat_winlog_event_data_TargetUserName == 'adm-sql'. Any appearance is abnormal (account never used). Match lookup omni-deception == 'ad_account'.
- **How to plant it (dry-run)**: DRY-RUN on the OMNITECH AD: New-ADUser -WhatIf 'adm-sql' in the delegated-admin OU, description 'Delegated SQL Admin', register it (dry-run) as a nominal member of a decoy privileged group, strong password never communicated, deny interactive logon. Add 'adm-sql' -> 'ad_account' to the omni-deception CSV. Nev

### `adm-backup`  ·  lookup key = `adm-backup`
- **Blends in as**: Delegated 'backup' admin account (dominant adm- pattern). Combines the appeal of admin privilege and of the backup/restore domain: exactly the account a ransomware operator wants to neutralize Veeam before encry
- **Attack path intercepted**: Recon of privileged adm-* accounts -> 'adm-backup' presumed a member of a group with extended rights over the Veeam infrastructure (bx-veeam-it-sv, bx-veeam-prx1/2) and/or Backup Operators. Ransomware path: destroy the backups to maximize extortion leverage (crown jewe
- **Fires on**: 4768 (TGT) / 4769 (TGS) / 4624 / 4672 with winlogbeat_winlog_event_data_TargetUserName == 'adm-backup'. lookup_value('omni-deception', to_lower(<field>)) == 'ad_account'.
- **How to plant it (dry-run)**: DRY-RUN OMNITECH AD only: New-ADUser -WhatIf 'adm-backup', description 'Veeam backup admin', nominal member (dry-run) of a decoy privileged group, random password not distributed, interactive logon denied, never associated with a live service. Key 'adm-backup' -> 'ad_account' to the CSV. Outside invissys.com.

### `BX-SQL-IT-VM$`  ·  lookup key = `bx-sql-it-vm$`
- **Blends in as**: MACHINE account of a fake SQL server following the crown-jewel nomenclature (site bx + segment -it- + suffix -vm + uppercase + '$', like BX-FILES-IT-VM$, BX-VEEAM-IT-SV$, BX-AD-01-IT-VM$). Blends perfectly into the
- **Attack path intercepted**: Lateral reconnaissance / AD scan: the attacker resolves the crown-jewel -it-vm server names and attempts a Kerberos auth against the machine account BX-SQL-IT-VM$ (imaginary SQL server), revealing its intent to pivot toward the database tier (business d
- **Fires on**: 4768 (AS-REQ of a machine account) or 4769 or 4624 with winlogbeat_winlog_event_data_TargetUserName == 'BX-SQL-IT-VM$' (to_lower -> 'bx-sql-it-vm$'). No real host authenticates this way, so any h
- **How to plant it (dry-run)**: DRY-RUN OMNITECH AD: New-ADComputer -WhatIf 'BX-SQL-IT-VM' (decoy computer object, no physical host/VM behind it), optional decoy DNS record bx-sql-it-vm.omnitech-security.fr pointing to a sinkhole/non-routed IP, no service listening. Add key 'bx-sql-it-vm$' (lowercase) -> 'ad_account' to the omni-dece

## Kerberoast SPN decoy accounts (type `identity`, detected via TGS 4769)

### `svc_sql (fake SQL service account with weak/RC4 MSSQLSvc SPN)`  ·  lookup key = `svc_sql`
- **Blends in as**: AD application service account named per the dominant pattern 'svc_<service>' (cf. svc_siem, svc_intranet). It carries an SPN MSSQLSvc/bx-sql-it-vm.omnitech-security.fr:1433 evoking a business SQL instance, consistent with
- **Attack path intercepted**: After a foothold on bx-dev-* / bx-qa-*, the attacker launches a Kerberoast (Rubeus kerberoast / GetUserSPNs.py / Invoke-Kerberoast) to enumerate all SPN accounts and requests an offline-crackable RC4 TGS, targeting the business SQL databases (bx-files-it-vm, SSRS) pu
- **Fires on**: EID 4769 (Kerberos Service Ticket Operations) or winlogbeat_winlog_event_id=4769 with winlogbeat_winlog_event_data_ServiceName='svc_sql' (sAMAccountName of the SPN-bearing account); signal reinforced by
- **How to plant it (dry-run)**: In DRY-RUN on the OMNITECH.SECURITY AD (DC bx-ad-01-it-vm), Julien creates a disabled user object 'svc_sql' (Enabled=$false), sets setspn -S MSSQLSvc/bx-sql-it-vm.omnitech-security.fr:1433 svc_sql and MSSQLSvc/bx-sql-it-vm:1433, forces msDS-SupportedEncryptionTypes=4 (RC4 only), sets a long random passwor

### `svc_veeam (fake Veeam backup service account, SPN-roastable)`  ·  lookup key = `svc_veeam`
- **Blends in as**: 'svc_veeam' account following the svc_ underscore pattern, modeled on the real backup infrastructure (bx-veeam-it-sv, BX-VEEAM-IT-SV$, bx-veeam-prx*). Fake SPN VeeamBackupSvc/bx-veeam-it-sv.omnitech-security.fr and HTTP/bx-v
- **Attack path intercepted**: Ransomware operator seeking to destroy backups: they Kerberoast the 'svc_veeam' account to crack its password and access the Veeam console/repository (bx-veeam-it-sv) in order to delete/encrypt the backups before deploying encryption, maxi
- **Fires on**: EID 4769 with winlogbeat_winlog_event_data_ServiceName='svc_veeam'; any TGS requested on this account (all the more in RC4 0x17) = Kerberoast enumeration, since the account has no legitimate workloa
- **How to plant it (dry-run)**: Dry-run on OMNITECH.SECURITY DC: create disabled user 'svc_veeam' (never on invissys.com), setspn -S VeeamBackupSvc/bx-veeam-it-sv.omnitech-security.fr svc_veeam and HTTP/bx-veeam-it-sv, force RC4 via msDS-SupportedEncryptionTypes=4, strong password + old PasswordLastSet, description 'Veeam service acco

### `svc_backup (fake generic backup service account with weak SPN)`  ·  lookup key = `svc_backup`
- **Blends in as**: 'svc_backup' account with a highly credible generic name (direct recommendation of the env map), dominant svc_ pattern. Carries an SPN HTTP/bx-backup2-it-vm.omnitech-security.fr and cifs/bx-backup2-it-vm, suggesting a host of
- **Attack path intercepted**: Post-foothold lateral reconnaissance: the attacker Kerberoasts the whole domain, spots 'svc_backup' (name evocative of broad storage rights), cracks the ticket and attempts access to the shares/backup server, pivots toward bx-files-it-vm and the infr
- **Fires on**: EID 4769 with winlogbeat_winlog_event_data_ServiceName='svc_backup'; fires on the first TGS requested (Kerberoast), regardless of encryption type, the account being inert by desig
- **How to plant it (dry-run)**: Dry-run OMNITECH.SECURITY AD: disabled user 'svc_backup', setspn -S HTTP/bx-backup2-it-vm.omnitech-security.fr svc_backup + cifs/bx-backup2-it-vm (the host bx-backup2-it-vm does not exist = double decoy), RC4-only encryption, robust password with PasswordLastSet backdated 2-3 years, OU=Honey. CSV omni-deceptio

### `svc_scan (fake scanner/MFP service account with roastable HTTP SPN)`  ·  lookup key = `svc_scan`
- **Blends in as**: 'svc_scan' account typical of scan-to-folder / MFP accounts (recommended by the env map), svc_ underscore pattern. SPN HTTP/bx-scan-it-vm.omnitech-security.fr, profile 'service account with never-changed password' ->
- **Attack path intercepted**: After compromising a standard user workstation (bx-dom-user*-lt) or a sales one (bx-com-*), the attacker Kerberoasts and selects 'svc_scan' as an easy target (scan accounts = historically weak and reused passwords), seeking to pivot toward d
- **Fires on**: EID 4769 with winlogbeat_winlog_event_data_ServiceName='svc_scan'; any TGS on this account signals SPN enumeration, signal increased if TicketEncryptionType=0x17 (RC4).
- **How to plant it (dry-run)**: Dry-run on OMNITECH.SECURITY DC only: create disabled 'svc_scan', setspn -S HTTP/bx-scan-it-vm.omnitech-security.fr svc_scan, force RC4 (msDS-SupportedEncryptionTypes=4), strong password + old PasswordLastSet, description 'Scan to folder service', decoy OU. Insert svc_scan->kerberoast_spns into the CSV o

### `svc_sap (fake ERP application service account with attractive SPN)`  ·  lookup key = `svc_sap`
- **Blends in as**: 'svc_sap' account simulating an ERP/application integration service (consistent with observed application accounts like intranet/owncloud), dominant svc_ pattern. SPN HTTP/bx-erp-it-vm.omnitech-security.fr and MSSQLSvc/bx-
- **Attack path intercepted**: The attacker targets business data: they Kerberoast 'svc_sap', designed to evoke an ERP account with high application privilege and an adjacent SQL database, crack the secret offline and attempt access to the centralized business data (exfiltration) then escalation via 
- **Fires on**: EID 4769 with winlogbeat_winlog_event_data_ServiceName='svc_sap'; the first TGS requested = Kerberoast, the account having no legitimate service session.
- **How to plant it (dry-run)**: Dry-run on OMNITECH.SECURITY AD: disabled user 'svc_sap', setspn -S HTTP/bx-erp-it-vm.omnitech-security.fr svc_sap + MSSQLSvc/bx-erp-it-vm.omnitech-security.fr:1433, RC4-only encryption, long random password, backdated PasswordLastSet, OU=Honey, description 'ERP integration service'. CSV omni-deception: 

### `svc-fortiweb (fake hyphenated service account simulating Fortinet integration)`  ·  lookup key = `svc-fortiweb`
- **Blends in as**: 'svc-fortiweb' account using the actually-observed MINORITY variant 'svc-' (hyphen) (svc-fortimanager) to cover both naming conventions and trap an attacker who enumerates broadly. SPN HTTP/bx-fortiweb-it
- **Attack path intercepted**: After an inter-site pivot (iv-tech-*/in-dev-*) or perimeter compromise, the attacker Kerberoasts the domain and targets 'svc-fortiweb' (appliance integration accounts, often privileged and poorly hardened), cracks the ticket and attempts to reach the console/admin of
- **Fires on**: EID 4769 with winlogbeat_winlog_event_data_ServiceName='svc-fortiweb'; any requested TGS reveals SPN enumeration, structurally zero FP since no legitimate service uses this account.
- **How to plant it (dry-run)**: Dry-run OMNITECH.SECURITY AD: create disabled 'svc-fortiweb' (deliberate hyphen variant), setspn -S HTTP/bx-fortiweb-it-vm.omnitech-security.fr svc-fortiweb, force RC4, robust password + old PasswordLastSet, decoy OU, description 'Fortinet LDAP integration'. Add svc-fortiweb->kerberoast_spns to the omni-d CSV

## Canary tokens (type `canary`)

### `Canary DNS - "backup vault" subdomain embedded in a KeePass bait`  ·  lookup key = `kdbx-restore.bkp-omnitech-vault.net`
- **Blends in as**: A "vault restore" URL stored as a URL/Note field in a KeePass file named 'Sauvegardes-Infra.kdbx' (entry 'svc_backup - restore portal', cf. dominant svc_ pattern). The subdomain looks like a por
- **Attack path intercepted**: Foothold on bx-dev-* / bx-qa-* -> collection of .kdbx files on SMB shares / workstations -> opening the bait KeePass (often weak passphrase or a keyfile next to it) -> the attacker follows the 'restore portal' URL thinking they reach the Veeam backup infrastructure (crown jewel
- **Fires on**: event_source=fortigate, field qname (or hostname) == 'kdbx-restore.bkp-omnitech-vault.net' -> rule lookup_value('omni-deception', to_lower(qname)) == 'canary'. Any contact (DNS resolution or connectio
- **How to plant it (dry-run)**: DRY-RUN on OMNITECH AD/infrastructure only. Julien (1) registers/points the sentinel subdomain to an external canary collector (Canarytokens/DNS sinkhole), (2) creates the bait .kdbx on a bx-dev staging workstation (NO real AD account creation), (3) in dry-run drops a read-only copy on an SM

### `Canary DNS - bait VPN profile (.ovpn) with decoy endpoint`  ·  lookup key = `gw-remote.vpn-omnitech-secure.net`
- **Blends in as**: A VPN config file 'OMNITECH-VPN-Teletravail.ovpn' (or .rdp / FortiClient profile) where the 'remote' directive points to this gateway hostname. Mimics the convention of a roaming remote-access gateway (pop
- **Attack path intercepted**: Compromise of a roaming laptop bx-com-* / bx-adv-* (phishing-exposed) -> retrieval of local VPN configs to pivot toward the internal network / reach the DCs and the file server -> the attacker attempts to connect to the 'gw-remote' gateway of the .
- **Fires on**: event_source=fortigate, qname/hostname == 'gw-remote.vpn-omnitech-secure.net'. The rule lookup_value('omni-deception', to_lower(hostname)) == 'canary' fires on the first DNS/TLS packet. Zero legit usag
- **How to plant it (dry-run)**: DRY-RUN on OMNITECH infrastructure. Julien (1) points the sentinel subdomain to the external canary collector, (2) generates a dummy .ovpn (bogus self-signed certs, no real bx-pki2022 PKI), (3) in dry-run places it in a 'Acces-Distant' folder of a staging bx-adv bait workstation and/or as an attachment to a fake

### `Canary SSH - bait private key with target hostname in comment/known_hosts`  ·  lookup key = `git-deploy.repo-omnitech-ci.net`
- **Blends in as**: An SSH private key 'id_rsa_deploy' + a known_hosts/SSH config where the Host points to 'git-deploy.repo-omnitech-ci.net' (fake CI/CD deployment server, consistent with the very large dev class bx-dev-repo-vm). Th
- **Attack path intercepted**: Foothold on bx-dev-* (ideal initial target, broad rights, dev tools) -> harvest of ~/.ssh/ -> the attacker uses the key to reach the 'deployment server' git-deploy, hoping to pivot toward the repos and the CI infrastructure (path toward source code / secret
- **Fires on**: event_source=fortigate, qname/hostname == 'git-deploy.repo-omnitech-ci.net' (DNS resolution during the ssh) -> lookup_value('omni-deception', to_lower(qname)) == 'canary'. Optionally double coverag
- **How to plant it (dry-run)**: DRY-RUN on OMNITECH AD/infrastructure. Julien (1) points the subdomain to the canary sinkhole/collector, (2) generates a throwaway key pair outside any real infrastructure, (3) in dry-run drops id_rsa_deploy + ~/.ssh/config (Host git-deploy ...) on a bx-dev staging workstation, never on the real bx-dev-repo-vm, (4) adds the key

### `Canary Office - bait Word document with remote image (web bug) to canary subdomain`  ·  lookup key = `assets.dr-omnitech-plan.net`
- **Blends in as**: A document 'PLAN-REPRISE-ACTIVITE-2026-CONFIDENTIEL.docx' (or .xlsx 'Mots_de_passe_Admin') containing a remote image/link (web bug) loaded from 'assets.dr-omnitech-plan.net'. Blends in as a highly at DR/BCP doc
- **Attack path intercepted**: After a foothold (bx-dev / bx-qa / bx-dom-user*), the attacker hunts for sensitive documents on the SMB shares of the file server (crown jewel bx-files-it-vm). Opening the bait BCP to spot the emergency procedures/credentials triggers the loading of
- **Fires on**: event_source=fortigate, qname/hostname == 'assets.dr-omnitech-plan.net' (loaded when the document opens) -> lookup_value('omni-deception', to_lower(hostname)) == 'canary'. The exact event = the reque
- **How to plant it (dry-run)**: DRY-RUN on OMNITECH infrastructure. Julien (1) hosts a 1x1 pixel on the canary collector and points the subdomain to it, (2) builds the .docx with an external image link (Canarytoken Word), (3) in dry-run places it on a staging SMB share with an enticing name and a deliberately permissive/discoverable ACL, never on

### `Canary AD - fake Kerberoastable service account with decoy SPN (canary TGS)`  ·  lookup key = `mssqlsvc/sql-omnitech-rpt.omnitech.security`
- **Blends in as**: A disabled AD service account 'svc_sqlrpt' (dominant svc_ underscore pattern) carrying an attractive SPN of the SQL Reporting service type (echoing the real Omnitech-SSRS without copying it). Deliberately weak/crackab password
- **Attack path intercepted**: Foothold with any domain account -> SPN enumeration (GetUserSPNs/Rubeus) for Kerberoasting -> the attacker requests a TGS ticket (EID 4769) for this decoy SPN to crack the 'SQL account' secret offline. Intercepts the escalatio phase
- **Fires on**: event_source=windows_security, winlogbeat_winlog_event_id=4769, winlogbeat_winlog_event_data_ServiceName matching the decoy account (svc_sqlrpt) -> lookup_value('omni-deception', to_lower(winlogbe
- **How to plant it (dry-run)**: DRY-RUN on the OMNITECH.SECURITY AD. Julien (1) in dry-run prepares the creation of a DISABLED svc_sqlrpt account with SPN setspn 'MSSQLSvc/sql-omnitech-rpt.omnitech.security' (decoy AD object, never a member of a group with real power), a nonexistent name so zero collision, (2) fills the omni-deception CSV in lowercase a

### `Canary share - bait "network drive" .lnk shortcut triggering an SMB/DNS beacon`  ·  lookup key = `fs-archive.share-omnitech-fin.net`
- **Blends in as**: A shortcut 'Comptabilite (Z).lnk' or a desktop.ini/icon file pointing to \\fs-archive.share-omnitech-fin.net\compta -> mimics a finance network drive mapping (credible compta/cmpta segment, consistent suffix)
- **Attack path intercepted**: Foothold + recon of network drives and shortcuts to locate the sensitive finance/accounting shares -> the attacker attempts to reach the 'accounting archive server' fs-archive (path toward sensitive business data, exfiltration, and toward the file serve
- **Fires on**: event_source=fortigate, qname/hostname == 'fs-archive.share-omnitech-fin.net' (DNS resolution during the SMB access attempt / .lnk icon render) -> lookup_value('omni-deception', to_lower(qnam
- **How to plant it (dry-run)**: DRY-RUN on OMNITECH infrastructure. Julien (1) points the sentinel subdomain to the canary sinkhole/collector (the SMB host does not exist, only the resolution is enough to fire), (2) builds the bait .lnk (Canarytoken Windows folder/UNC), (3) in dry-run drops it on a staging share and/or a bx-dom-user bait workstation with a

## Decoy hosts → MACHINE accounts (type `identity`)

### `bx-sql-it-vm`  ·  lookup key = `bx-sql-it-vm$`
- **Blends in as**: Production application SQL server in Bordeaux (crown-jewel segment '-it-', suffix '-vm'), a credible counterpart of the real Omnitech-SSRS/bx-files-it-vm. No SQL database named this way exists = no legitimate traffic.
- **Attack path intercepted**: Lateral recon toward business data: an attacker who has pivoted (bx-dev-*/bx-qa-*) enumerates the juicy servers and attempts Kerberoasting/auth on this 'SQL server'. Intercepts the path toward bx-files-it-vm + Omnitech-SSRS (exfiltration/encryption of the applicatio db
- **Fires on**: Any EID 4768 (TGT) or 4769 (TGS/Kerberoast) or 4624/4625 or DNS query where the key 'bx-sql-it-vm$' (TargetUserName/ServiceName) appears in the telemetry; lookup_value('omni-deception', to_lower(winl
- **How to plant it (dry-run)**: In DRY-RUN on the OMNITECH.SECURITY AD only (never the co-managed tenant invissys.com): Julien creates a disabled computer object BX-SQL-IT-VM in the servers OU (New-ADComputer -Enabled $false with -WhatIf first), attaches an attractive SPN to it (MSSQLSvc/bx-sql-it-vm.omnitech-security.fr:1433) and publishes the recor

### `bx-backup2-it-vm`  ·  lookup key = `bx-backup2-it-vm$`
- **Blends in as**: Second Bordeaux backup server ('-it-vm' convention), a credible logical continuation of bx-veeam-it-sv. Numbering '2' consistent with the estate (bx-ad02, bx-veeam-prx2). No real service = contact = recon.
- **Attack path intercepted**: Priority ransomware target: neutralizing backups before encryption. Intercepts the path toward bx-veeam-it-sv + bx-veeam-prx1/prx2 (destruction of restore capability, extortion leverage).
- **Fires on**: Any 4768/4769/4624/4625 targeting the machine account 'bx-backup2-it-vm$', or DNS resolution/SMB/RDP connection toward this host; rule lookup_value('omni-deception', to_lower(<TargetUserName|ServiceName>))
- **How to plant it (dry-run)**: DRY-RUN OMNITECH AD only (NOT invissys.com): disabled computer account BX-BACKUP2-IT-VM created via New-ADComputer -WhatIf then -Enabled $false, SPN HOST/bx-backup2-it-vm + decoy DNS A record pointing to a non-routed/blackhole IP. Referenced in omni-deception: 'bx-backup2-it-vm$' -> 'decoy_host'.

### `bx-pki2025-it-vm`  ·  lookup key = `bx-pki2025-it-vm$`
- **Blends in as**: New ADCS certificate authority (2025 vintage), a credible and 'more recent' counterpart of the real bx-pki2022. The vintage in the name follows the observed convention (bx-pki2022). No real CA = any contact suspect.
- **Attack path intercepted**: Certificate template abuse (ESC1-8) for domain-scale persistence/impersonation. An attacker enumerating the CAs (certutil, Certify) will hit this 'new PKI' before the real one. Intercepts the path toward bx-pki2022/ADCS and domain escalation.
- **Fires on**: Any 4768/4769 toward 'bx-pki2025-it-vm$', any DNS/LDAP/enrollment request toward this host, or the key appearing in the telemetry; lookup_value('omni-deception', to_lower(<field>)) == 'decoy_host'
- **How to plant it (dry-run)**: DRY-RUN OMNITECH AD (never invissys.com): disabled computer object BX-PKI2025-IT-VM (New-ADComputer -WhatIf), SPN HOST + decoy DNS record; do NOT install a real ADCS role or publish a template (passive decoy). Optional: fake pKIEnrollmentService object in the config partition in an isolated lab only. 

### `bx-fs02-it-vm`  ·  lookup key = `bx-fs02-it-vm$`
- **Blends in as**: Second Bordeaux file server ('fs' abbreviation + '02' numbering consistent with bx-ad02), a credible counterpart of the real bx-files-it-vm. Sensitive SMB shares assumed. No real share = any access = attacker.
- **Attack path intercepted**: Exfiltration/encryption of business data: SMB share enumeration (net view, SharpShares) and access to the 'file server'. Intercepts the path toward bx-files-it-vm (centralized business data).
- **Fires on**: Any 4768/4769/4624 targeting 'bx-fs02-it-vm$', any SMB attempt/connection toward the host, or the key appearing; lookup_value('omni-deception', to_lower(<TargetUserName|ServiceName>)) == 'decoy_host
- **How to plant it (dry-run)**: DRY-RUN OMNITECH AD only (never the co-managed tenant invissys.com): disabled computer account BX-FS02-IT-VM created with -WhatIf then -Enabled $false, SPN cifs/bx-fs02-it-vm.omnitech-security.fr + decoy DNS A record, no real share mounted. Key omni-deception 'bx-fs02-it-vm$' -> 'decoy_host'.

### `bx-esxi-05-it`  ·  lookup key = `bx-esxi-05-it$`
- **Blends in as**: Fifth Bordeaux ESXi host, a direct and credible continuation of bx-esxi-01..04-it (real positives confirmed in telemetry). Exact convention (segment '-it', no -vm suffix since bare-metal). No real hypervisor '05' = a
- **Attack path intercepted**: ESXi ransomware / guest security bypass: an attacker who compromises vCenter enumerates the ESXi hosts to encrypt all VMs at one point. Intercepts the path toward vcenter + bx-esxi-01..04-it (global encryption of DC/SIEM/Veeam/files).
- **Fires on**: Any 4768/4769 toward 'bx-esxi-05-it$', any DNS request/connection (443/902/SSH) toward the host, or the key appearing in the vsphere/security logs; lookup_value('omni-deception', to_lower(<field>)) 
- **How to plant it (dry-run)**: DRY-RUN OMNITECH AD/infrastructure only (never invissys.com): disabled computer object BX-ESXI-05-IT (New-ADComputer -WhatIf), decoy DNS A record bx-esxi-05-it.omnitech-security.fr, and optionally a fake host inventoried in vCenter in disconnected mode (lab/dry-run). No real ESXi deployed. Key omni-dece

### `bx-ad03-it-vm`  ·  lookup key = `bx-ad03-it-vm$`
- **Blends in as**: Third Bordeaux domain controller, a direct and highly credible continuation of bx-ad-01/bx-ad02-it-vm (real DCs, 4768 emitters). The '03' numbering is the exact convention. No real DC '03' = any auth = attack
- **Attack path intercepted**: The #1 target of any AD intrusion: an attacker looks for the DCs for DCSync/Golden Ticket/replication. Any contact with this 'DC' (DRSUAPI, LDAP, machine auth) reveals an ongoing domain compromise. Intercepts the path toward bx-ad-01/bx-ad02-it-vm + vm-paca-ad
- **Fires on**: Any 4768/4769/4624 targeting 'bx-ad03-it-vm$', any LDAP/DNS SRV/DRSUAPI request toward the host, or the key appearing; lookup_value('omni-deception', to_lower(<TargetUserName|ServiceName>)) == 'decoy
- **How to plant it (dry-run)**: DRY-RUN OMNITECH AD only (never invissys.com): disabled computer account BX-AD03-IT-VM (New-ADComputer -WhatIf, NEVER promoted to a real DC), decoy SPN + DNS A record. Do NOT add it to the Domain Controllers group or publish a real _ldap SRV (strict passive decoy). Key omni-deception 'bx-ad03-it-vm$' -> 'd

## Activation

The keys above are **already in the registry** `lookups/deception-decoys.csv` and resolved
by the lookup `omni-deception` (verified: `svc_veeam`→identity, `BX-AD03-IT-VM$`→identity,
`kdbx-restore.bkp-omnitech-vault.net`→canary, `jmorin`→null). **As soon as you plant a bait**,
the corresponding trap fires at ~100 % fidelity (email + SOC Teams, high priority).

> **Canaries**: the FQDNs are **external domains disjoint from the AD zone** (a design
> choice, to avoid auto-resolution by AD scanners). Detection is done on the
> **outbound DNS query** (Sysmon EID22 / FortiGate) — it works even if the domain
> is not registered. For an additional *out-of-band* alert, register the token on a
> service such as Canarytokens (optional).
