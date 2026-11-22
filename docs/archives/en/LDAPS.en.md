# LDAPS — Active Directory authentication on the Graylog console

*Goal: named AD accounts for the console (traceability ISO A.5.16/A.8.5),
with the local `admin` account serving only as a fallback.*

## 0. Chosen options (12/06/2026)

- Bind account: **`svc_siem`** (reused — standard user,
  also used for the backup deposit).
- Test / admin reference account: **`adm-jmorin`**.
- Target DC: **bx-ad-01-it-vm.omnitech.security (10.33.50.250)**.
- Firewall prerequisite: FortiGate rule **425** (ELK network → DC) must
  include the **LDAPS-GC** service (636/3269) — `append service "LDAPS-GC"`.
- **Access restricted to members of the "Admins du domaine" group** (recursive
  `memberOf` LDAP filter): an AD account outside the group cannot
  authenticate at all.
- Automatically assigned role: **Admin** (population already restricted).
- Local `admin` account kept as fallback (vault).

> **STATUS: OPERATIONAL (12/06/2026).** "Active Directory OMNITECH" backend
> active (LDAPS 636, certificate verified by the internal Root CA). Group DN
> confirmed via LDAP: `CN=Admins du domaine,OU=Comptes_Service,OU=_Support,
> OU=Entreprise,DC=omnitech,DC=security`. Filter tested: adm-jmorin (admin)
> admitted, svc_siem (non-admin) rejected. FortiGate rule 425: LDAPS-GC added.

## 1. Prerequisites (AD side — 5 minutes)

1. **Bind account** (read-only, never interactive):
   **`svc_siem`** — existing domain service account (reused,
   it is also used for the backup deposit), strong password, "password
   never expires", no privileged membership. The bind is done in
   UPN format: `svc_siem@omnitech.security`.
2. **LDAPS active on the DCs**: with AD CS + auto-enrollment this is usually already
   the case. Verification from the SIEM (against the DC actually
   targeted):
   ```bash
   echo | openssl s_client -connect bx-ad-01-it-vm.omnitech.security:636 \
     -CAfile /etc/graylog/certs/omnitech-rootca.crt 2>/dev/null | grep "Verify return"
   # expected: Verify return code: 0 (ok)   <- confirmed in prod (14/06/2026)
   ```
   (The Graylog JVM already trusts the Root CA via `cacerts-omni.jks`.)
3. FortiGate rule **425** (ELK network → DC): add the
   **LDAPS-GC** service (TCP 636 + Global Catalog 3269) — `append service "LDAPS-GC"`.
   The rule initially opened only web+ping; the LDAPS-GC service was indeed
   added (see section 0).

## 2. Setup (SIEM side)

```bash
# 1. fill in the variables in 00-vars.env:
LDAP_HOST='bx-ad-01-it-vm.omnitech.security'
LDAP_BIND_DN='svc_siem@omnitech.security'          # bind in UPN format
LDAP_BIND_PASS='********'
LDAP_REQUIRED_GROUP_DN='CN=Admins du domaine,OU=Comptes_Service,OU=_Support,OU=Entreprise,DC=omnitech,DC=security'
# (optional, with default values: LDAP_PORT=636, LDAP_SEARCH_BASE=DC=omnitech,DC=security)

# 2. run:
bash /root/omnitech-siem-setup/33-ldaps-auth.sh
```

The script creates the "Active Directory OMNITECH" backend (Active Directory,
LDAPS :636, `transport_security=tls`, `verify_certificates=true`), applies
the restrictive LDAP filter (see section 3), assigns the default role
**Admin**, then ACTIVATES it. The script is **idempotent** (replays without breaking an
already-created backend). It first verifies the LDAPS certificate against the internal
Root CA; if it is unreachable, it warns but continues (Graylog will simply
refuse connections until it is fixed).

## 3. Behavior and role assignment

- **Access restricted by LDAP filter**: the backend's `user_search_pattern`
  allows ONLY (recursive) members of the "Admins du domaine" group.
  An AD account outside this group is invisible to the backend and **cannot
  authenticate at all**:
  ```
  (&(objectClass=user)
    (|(sAMAccountName={0})(userPrincipalName={0}))
    (memberOf:1.2.840.113556.1.4.1941:=CN=Admins du domaine,OU=Comptes_Service,OU=_Support,OU=Entreprise,DC=omnitech,DC=security))
  ```
  The OID `1.2.840.113556.1.4.1941` (LDAP_MATCHING_RULE_IN_CHAIN) makes
  membership **recursive** (nested groups taken into account).
- Since the population is already restricted to domain administrators, the
  backend assigns the **`Admin` role directly** (`default_roles`) on the
  first login — no manual promotion to do.
  > In the Open Source edition there is no team sync (role ⇄ AD group mapping);
  > the choice "group-restricted filter + default Admin role" is the
  > way to obtain reserved admin access without Enterprise.
- Login with `sAMAccountName` (or UPN) + AD password; the displayed full
  name comes from `displayName`.
- The local `admin` account remains active as a fallback (if AD is unavailable,
  the console stays administrable) — password in the vault.

## 4. Rollback

System → Authentication → disable the backend (local authentication
resumes on its own), or via the API: `POST /system/authentication/services/configuration`
with `{"active_backend": null}`.

---
*Last review: 14/06/2026 — facts verified against `33-ldaps-auth.sh`,
`00-vars.env` and the active backend (Graylog API). Backend OPERATIONAL,
LDAPS certificate verified (`Verify return code: 0`).*
