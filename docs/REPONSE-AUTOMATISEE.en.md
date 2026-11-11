# Advanced detection & automated response — AD Canary + SOAR

*Version 1.0 — 12/06/2026 — Classification: internal — ISO ref A.8.16, A.5.26.*

This document describes the two "active" SIEM mechanisms: the **canary
account** (very low-noise intrusion detection) and the **SOAR-light**
(automatic response by IP blocking).

---

## 1. AD canary account (internal intrusion detection)

### Principle
A **decoy** Active Directory account, credible and attractive (it looks like a
privileged SQL service account), but **with no real privilege** and that is
**never used legitimately**. Any authentication, attempt or Kerberos
request concerning it can only be the act of an attacker who is
enumerating the directory, brute-forcing, Kerberoasting or moving
laterally. **Near-zero false positive rate by construction.**

### Implementation
| Element | Detail |
|---|---|
| AD account | `windows/New-OmniCanary.ps1` — random password never communicated, `PasswordNeverExpires`, **MSSQLSvc SPN** (Kerberoasting trap → generates a 4769), zero `logonHours`, no privileged membership |
| SIEM detection | `omni-canary` lookup (CSV `lookups/canary-accounts.csv`) + pipeline rule `omni-winsec-10-canary` (matches user / TargetUserName / SubjectUserName / ServiceName) |
| Alert | **"OMNI - CANARY ACCOUNT touched"** — P3, email + Teams, immediate |
| Provisioning | `35-canary.sh` (lookup + alert), then replay `12-graylog-pipelines.sh` |

### Operation
- **Add a canary**: edit `canary-accounts.csv` + rerun `35-canary.sh`.
- **Trigger = incident**: any canary alert is handled as a priority
  (cf. playbook P-4, PRO §6). Identify the source host/IP immediately.
- Recommended: one canary per sensitive zone (a different, credible name).

---

## 2. SOAR-light (automatic blocking of attacking IPs)

### Principle
When a network attack is detected (brute force / VPN spraying), the SIEM
publishes the source IP in a **blocklist** that the FortiGate reads as an
*External Threat Feed* and blocks. **Decoupled** architecture: the SIEM has
**no credentials** on the firewall (security), and the block **expires on its own**.

### Full chain
```
Graylog alert (VPN brute force / Password spraying)
   │  HTTP notification
   ▼
omni-soar (service, 127.0.0.1:8088)
   │  safeguards: never RFC1918, never SOAR_WHITELIST,
   │  threshold SOAR_MIN_HITS, cap SOAR_MAX, TTL SOAR_TTL_HOURS
   ▼
/var/www/siem-kit/soar/blocklist.txt   (served over HTTPS)
   │  poll every 2 min
   ▼
FortiGate External Connector "OMNI_SOAR_Blocklist"
   │
   ├─ local-in-policy  → blocks the SSLVPN portal (traffic to the appliance)
   └─ firewall policy  → blocks the published services (traversing traffic)
   ▼
Block — automatic expiration after TTL (default 24 h)
```

### Components
| Element | Role |
|---|---|
| `/usr/local/sbin/omni-soar` | webhook service → decision → feed (traceability GELF) |
| `/usr/local/sbin/omni-soar-expire` (+ hourly timer) | removes expired IPs |
| `36-soar.sh` | creates the HTTP notification, attaches it to the VPN/spraying alerts, creates the traceability alert |
| `fortigate/06-soar-threatfeed.conf` | FortiGate connector + policies |
| Alert **"OMNI - SOAR: IP blocked automatically"** | email on each block |

### Safeguards (`00-vars.env` parameters)
| Parameter | Default | Role |
|---|---|---|
| `SOAR_WHITELIST` | (empty) | **Public IPs to NEVER block**: OMNITECH sites, IPsec peers, admins. To be filled in. |
| `SOAR_MIN_HITS` | 5 | minimum occurrences of the IP in the backlog to block |
| `SOAR_MAX` | 500 | cap on IPs blocked simultaneously |
| `SOAR_TTL_HOURS` | 24 | block duration before auto expiration |

Structural safeguards: **no private IP** (RFC1918) is ever blocked;
each block is **traced** (email + GELF); a false positive **unblocks
itself** after the TTL.

### Operation
- **View blocked IPs**: SIEM console (Backups page / search
  `event_action:ip_bloquee`) or FortiGate GUI (*External Connectors → View
  Entries*). The `diagnose` CLI commands are not supported on all
  FortiOS versions.
- **Unblock manually**: remove the IP from `/var/lib/omni-soar/blocklist.json`
  then `python3 /usr/local/sbin/omni-soar-expire`.
- **Complete the whitelist**: essential before real operation —
  add the fixed public IPs of the sites and of the admins.
- **End-to-end test**: inject a test IP into the feed and check
  that it is read on the FortiGate side (poll ≤ 2 min, visible in the nginx logs).

> ⚠️ The SOAR acts **automatically** on the firewall. Keeping the whitelist
> up to date is an operational responsibility (monthly review, PRO §2).

## Evolution — advanced SOAR (scoping)

The IP blocking above is **PB-01** (in production). The following playbooks
are **designed**, pending the **NinjaOne API** (cf. **`SOAR-PLAYBOOKS.md`**):
- **PB-02 Isolate a compromised host** (ransomware / LSASS / confirmed lateral).
- **PB-03 Disable an account** (relies on the `identity` field) — canary /
  impossible travel / DCSync.
- **PB-04 Open a pre-filled incident ticket**; **PB-05 Enrich IOC**.

Reinforced safeguards (same principles as PB-01): **never** a domain
controller / the SIEM / the hypervisor / a break-glass account; **dry-run** first;
reversible and traced actions. As long as NinjaOne is not connected, isolation
and disabling remain **manual** (cf. PROCEDURE-INCIDENT §5).
