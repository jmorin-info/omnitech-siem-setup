# Entra ID (Azure AD) — SIEM coverage & tenant actions

## Already integrated (nothing to do)
The `omni-m365-fetch` fetcher already collects via Microsoft Graph:
- **Sign-ins** (`/auditLogs/signIns`) → `event_source=m365 m365_type=signin` (measured: 3634+/7d).
- **Directory audits** (`/auditLogs/directoryAudits`) → `m365_type=audit` (1113+/7d).

**Entra detections in place** (11): `m365_brute_externe`, `m365_etranger` (foreign sign-in),
`m365_role` (role change), `m365_oauth_consent`, `m365_mail_forward`, `m365_mailbox_deleg`,
`m365_partage_externe`, `m365_risque`, + **added by `94-entra.sh`**: `m365_app_credential_add`
(secret/cert added to an app = cloud backdoor), `m365_ca_change` (Conditional Access change).

## ⚠️ Action 1 — unlock the *risk detections* (Identity Protection)
**Measured finding**: `m365_type=risk = 0`, and **100% of sign-ins report `risk_level=hidden /
risk_state=none`**. The Azure risk engine computes nothing → the `m365_risque` detection stays silent.
Cause = **no Entra ID P2 license**. To do on the tenant side:

1. **License** — enable **Entra ID P2** (or EMS E5 / M365 E5) on the accounts to monitor.
   *Without P2, `identityProtection/riskDetections` returns 0 — it is not the fetcher.*
2. **Graph permission** — on the fetcher's app registration, add the **Application**
   (app-only) permission **`IdentityRiskEvent.Read.All`** (+ optionally `IdentityRiskyUser.Read.All`). Keep
   `AuditLog.Read.All` + `Directory.Read.All` already in place.
3. **Admin consent** — a Global Admin clicks **"Grant admin consent"**
   on these permissions (otherwise app-only token without scope → Graph 403 → risk stays 0).

**Check**: after these 3 steps, `m365_type=risk` should go > 0 and new sign-ins report
`risk_level` ∈ {low, medium, high}. `m365_risque` will then start detecting.

## ⚠️ Action 2 — block *legacy auth* (MFA bypass)
**Measured finding**: **1461 "Authenticated SMTP" authentications** (+ 41 "Other clients") over the
window. Legacy protocols (basic SMTP/IMAP/POP/ActiveSync) **do not support MFA** → an
attacker uses them to bypass MFA in a password-spray. To do:
- **Conditional Access**: "Block legacy authentication" policy (or Security Defaults).
- Check which accounts/services still use authenticated SMTP (sending apps, MFP scan-to-mail) and
  migrate them (OAuth / SMTP via a dedicated connector) before blocking.

> Once legacy auth is blocked, `m365_brute_externe` remains the spray detection on modern sign-ins.
