# SEAL x AD identity bridge — physical access / logical logon correlation (XCO)

## 1. Purpose

Correlate SEAL events (physical access: badge, alarms, hypervisor audit)
with the Windows / M365 logons (logical identity) of the SAME person. The join
key is the canonical UPN (`identity_upn`, lowercase), a field common to both
worlds:

- on the Windows/M365 side: `identity` (already normalized, lowercase UPN);
- on the SEAL side: `identity_upn`, ABSENT in the database (the SQL only provides
  `identity_matricule`, cf. `CONTRACT.md` D4) -> resolved SIEM-side by this bridge.

Resolution chain:

```
badge (EVEN_PHYSICAL_NUMBER) -> identity_matricule (milf.BADGES.MATRICULE, SQL join)
        -> lookup omni-seal-identity (matricule -> UPN, from AD)
        -> identity_upn (canonical lowercase UPN)  ==  identity (Windows/M365)
```

## 2. Architecture

| Component | File | Role |
|-----------|---------|------|
| AD extraction | `seal/graylog/regen-seal-identity.sh` | LDAPS (636, read-only, same bind account as the console) -> CSV `matricule,upn` in `/etc/graylog/lookup/seal-identity.csv`. UPN lowercased (canonical form). Idempotent (atomic write + conditional replacement). |
| Graylog lookup | `omni-seal-identity` (csvfile adapter + guava cache + table) | Provisioned by `provision_seal.py` (`ensure_identity_lookup`). Key `matricule`, value `upn`. Auto-reload <=60 s on each change of the CSV. |
| Pipeline rule | `seal/graylog/pipelines/14-seal-identity-upn.rule` | On any SEAL message carrying `identity_matricule`, sets `identity_upn = lowercase(lookup_value("omni-seal-identity", identity_matricule))`. TERMINAL stage of the 3 SEAL pipelines (after the normalization that sets the `""` placeholder). No ternary. |
| AD/Windows side | `seal/graylog/pipelines/13-identity-mirror.rule` (outside the SEAL scope) | Sets `identity_upn` in the SAME canonical form on the Windows/M365 logons. Must be integrated by the owner of the AD layer for the join to work. |
| XCO correlation | `oms-xdr/oms_xdr/rules.yaml` | Signals `S_SEAL_BADGE_IN`, `S_SEAL_CONSOLE_LOGON` (keyed on `identity_upn`) + rules `CR_XCO_IMPOSSIBLE_PRESENCE`, `CR_XCO_CONSOLE_NO_BADGE`. |

Flow:

```
AD (LDAPS 636) --regen-seal-identity.sh(cron)--> /etc/graylog/lookup/seal-identity.csv
      --csvfile adapter--> lookup omni-seal-identity
      --rule 14 (terminal stage)--> identity_upn on the SEAL events
      --oms-xdr (S_SEAL_* keyed on identity_upn)--> join with S_LOGON_SUCCESS / S_M365_FOREIGN_SIGNIN
```

## 3. Delivered XCO rules

- `CR_XCO_IMPOSSIBLE_PRESENCE` (critical): physical SEAL badge-in
  (`S_SEAL_BADGE_IN`) + M365 sign-in from a country outside the egress
  (`S_M365_FOREIGN_SIGNIN`) for the same `identity_upn`. Physical presence and
  a foreign connection simultaneously = impossible -> probable account compromise.
  Expressible and reliable as soon as the bridge is in place.
- `CR_XCO_CONSOLE_NO_BADGE` (high, to be confirmed): connection to the hypervisor
  console (`S_SEAL_CONSOLE_LOGON`) linked to the Windows logon of the same
  `identity_upn` (`S_LOGON_SUCCESS`). Intent = "console without physical
  badge-in"; see the limitation in §5.

## 4. What must be ADDED ON THE VM (deployment)

1. Populate the lookup: drop in `regen-seal-identity.sh` and schedule it in cron
   (e.g. every night). Prerequisites: `ldapsearch` (package `ldap-utils`),
   `LDAP_BIND_DN` / `LDAP_BIND_PASS` in the environment (never in clear text),
   internal Root CA in `/etc/graylog/certs/omnitech-rootca.crt`, FW rule
   ELK -> DC on TCP 636 (already open for the console, cf. `33-ldaps-auth.sh`).
   Cron example:
   ```
   # /etc/cron.d/seal-identity  (env in /etc/graylog/seal-ldap.env, mode 600)
   17 3 * * *  root  . /etc/graylog/seal-ldap.env; /root/omnitech-siem-setup/seal/graylog/regen-seal-identity.sh >> /var/log/seal-identity.log 2>&1
   ```
2. Provision the lookup + the rule + the connection to the pipelines:
   `provision_seal.py --apply` (creates `omni-seal-identity`, loads rule 14,
   adds it as terminal stage of the 3 SEAL pipelines — idempotent).
3. On the AD layer side (outside SEAL): integrate `13-identity-mirror.rule` (or equivalent)
   to set `identity_upn` on the Windows/M365 logons with the SAME canonical
   form. Without this, the SEAL field has nothing to join with.

## 5. What must be CONFIRMED

- **AD attribute of the matricule.** `regen-seal-identity.sh` reads the
  `SEAL_MATRICULE_ATTR` attribute (default `employeeID`). THIS DEFAULT IS NOT VALIDATED. The
  observed SEAL matricule looks like INITIALS (e.g. `JPA`, `PGE`) and not a
  numeric identifier -> there is NO guarantee that it is `employeeID`.
  Candidates to test on the AD side: `employeeID`, `employeeNumber`,
  `extensionAttribute1..15`, `initials`. Manual verification:
  ```
  ldapsearch -x -H ldaps://bx-ad-01.omnitech.security:636 -D "$LDAP_BIND_DN" -y pw \
    -b "DC=omnitech,DC=security" "(sAMAccountName=<known account>)" \
    employeeID employeeNumber initials extensionAttribute1
  ```
  Adjust `SEAL_MATRICULE_ATTR` once the attribute carrying the matricule is identified.
- **Format and uniqueness of the matricule.** Confirm that the chosen AD value corresponds
  EXACTLY (case included; the lookup is case-insensitive on the Graylog side) to the
  `identity_matricule` produced by the SEAL SQL, and that it is unique per person.
- **Canonical form of the UPN on both sides.** `identity_upn` (SEAL) and `identity`
  (Windows/M365) must be STRICTLY identical (lowercase UPN). A discrepancy in
  case/domain makes the join fail SILENTLY.

## 6. Current limitations (candid)

- **Very low resolution volume.** `identity_matricule` is only populated on
  ~35 events today and `identity_upn`=0. As long as the
  badge -> matricule coverage does not improve on the SQL side (join `milf.BADGES.MATRICULE`),
  the badge -> UPN resolution remains marginal: the XCO rules will produce almost
  no incident. The bridge is wired and correct, but its FEED is the real
  bottleneck -> to be improved on the SEAL extraction side (make the badge/matricule join reliable).
- **No anti-join in the oms-xdr engine.** `CR_XCO_CONSOLE_NO_BADGE` targets an
  ABSENCE ("console connection WITHOUT badge-in"), which is not expressible: the engine only does
  `require_all` / `any_of` (presence). The delivered rule APPROXIMATES the intent
  (console + Windows logon of the same UPN) but does NOT prove the absence of a badge ->
  severity `high` "to be confirmed", badge verification left to the analyst. Possible
  evolution: an enrichment signal `badged_in_today` per identity (lookup), or
  a negation operator in the engine.
- **On the hypervisor audit side, the UPN will depend on an additional bridge.** The
  audit events carry `actor_login` (console account) and not always a
  badge `identity_matricule`. `S_SEAL_CONSOLE_LOGON` will therefore only trigger
  if `identity_upn` could be resolved on these events (possible approach: console accounts marked
  "Windows account", `actor_login` -> AD account). To be wired separately if needed.
- **Dependency on the AD layer.** Without `13-identity-mirror` on the Windows/M365 side, the
  `identity`/`identity_upn` field does not exist on the logon side -> no join possible.
  This layer is outside the SEAL scope and must be delivered in parallel.
