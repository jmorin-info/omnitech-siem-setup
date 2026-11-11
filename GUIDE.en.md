# OMNITECH SIEM Guide — understand the system in 15 minutes

> This document explains, **in plain language**, what this SIEM is for, what it
> monitors, and how to read its screens. It is meant for **everyone**:
> management, auditors, newcomers, technicians. No cybersecurity prerequisite —
> technical terms are defined in the **glossary** at the end of
> the document.

---

## 1. What is a SIEM? (in one sentence)

A **SIEM** (Security Information and Event Management) is the company's security
**black box**: it continuously **collects** the logs of all the
equipment (servers, workstations, firewalls, Microsoft 365 cloud, etc.), **analyzes** them
to spot what is abnormal or malicious, and **alerts** the team when
something is wrong. It is the tool that makes it possible to **detect an attack** and to
**run the investigation** afterwards.

Ours is built on **Graylog** (the collection/search engine) + **OpenSearch**
(the database that stores the logs) + an **in-house analysis layer** that goes
beyond what Graylog can do (behavioral detection, attack
correlation, threat map, etc.).

---

## 2. The journey of a log (overview)

```
   Windows Workstations / Servers ─┐
   FortiGate Firewall ─────────────┤
   Microsoft 365 / Entra ──────────┼─►  COLLECTION  ─►  NORMALIZATION  ─►  DETECTION  ─►  ENRICHMENT  ─►  STORAGE
   vSphere / ESXi ─────────────────┤     (Graylog)      (unified fields)    (rules)       (MITRE, score)   (OpenSearch)
   Veeam Backups ──────────────────┘                                                                             │
                                                                                                                ▼
   IN-HOUSE ANALYSIS (every X minutes)  ◄───────────────────────────────────────────────  DASHBOARDS + ALERTS
   • risk score per entity (UEBA)                                                           (SOC screens + email/Teams)
   • impossible travel, C2 beacon, DNS tunnel, volume anomaly
   • incident correlation (kill-chain)
```

**In plain terms:** every event is received, filed into a common format, compared to
detection rules, tagged (e.g. "LSASS memory access = credential
theft"), associated with a known attack technique (**MITRE ATT&CK**) and
with a **risk score**, then stored. In parallel, analysis programs
run in a loop to spot suspicious behaviors and to **group the
alerts into incidents**.

---

## 3. The dashboards — which page answers which question?

Everything is in the **"OMNI - SOC"** dashboard (*Dashboards* menu). The pages are
organized by theme.

| Page | Which question it answers |
|------|-------------------------------|
| **Management** | "Overall, is everything OK?" Posture in 10 seconds: volume, detections, **critical incidents**, **at-risk entities**, trends vs the previous day. *Page for management.* |
| **Alerts** | "What went off?" The queue of all detections, to be triaged. |
| **Incidents** | "Is there an attack in progress?" The detections of a single host/account **grouped into an ordered attack narrative** (the *kill-chain*). |
| **ATT&CK** | "Which attack techniques are we seeing?" Read via the global MITRE ATT&CK framework. |
| **UEBA / NDR** | "Who is most at risk, and is there abnormal behavior?" Score per entity + impossible travel, C2 beacon, DNS tunnel, volume anomaly. |
| **Collection health** | "Are my sources reporting properly?" Coverage, silent hosts (*go-dark*). |
| **AD Identity** | "Who is connecting, who is failing?" Active Directory authentications. |
| **Privileged accounts** | "What are the admin accounts doing?" Enhanced monitoring of sensitive accounts. |
| **Accounts & compliance** | "Account lifecycle, PKI, compliance." |
| **M365 / M365 Activity** | "What is happening in the Microsoft cloud?" Sign-ins, shares, mail. |
| **Endpoint / Hunting** | "What are the workstations doing?" Processes, and **hunting** for advanced techniques. |
| **Network / VPN & Exposure / Mapping** | "What traffic, from where, to where?" Firewall, VPN, geography. |
| **vSphere / Backups / Certificates** | "Is my infrastructure (virt, backup, PKI) healthy?" |
| **Vulnerabilities** | "Which hosts are exposed to an exploited flaw?" (Wazuh-style, via CISA KEV). |
| **Investigation** | "I want to investigate X." Free page: type `host:BX-SRV01` or `user:adm-jmorin` in the search bar, everything filters. |

**Reading tip:** each widget has an **ⓘ** icon (on hover) that explains
what it shows and what a spike means. Cells **color** themselves orange
(to watch) or red (critical) automatically.

---

## 4. The "beyond Graylog" analysis layer (explained simply)

These analyses compute things that a classic search engine cannot
do. They run automatically and feed their results back into the
screens.

- **Entity risk score (UEBA)** — gives each host and each account a
  **score out of 100**, by merging all its alerts, its vulnerabilities, its
  connection failures, etc. Lets you say "start by handling that one."

- **Impossible travel** — if a single account connects from France then,
  20 minutes later, from another continent, that is **physically
  impossible**: the account is probably compromised. We compute the distance and the
  speed required between two connections.

- **C2 beacon (beaconing)** — an infected workstation "calls home" at a
  **very regular** interval (every 60 s for example). We measure this regularity
  to spot a hidden command channel.

- **DNS tunnel** — a technique to **quietly exfiltrate data** by
  encoding it in DNS queries. We detect domain names with "random"
  content (high entropy) that are very long.

- **Volume anomaly** — if a source suddenly starts emitting 10× more (or
  stops dead), that is suspect. We compare against its usual behavior **at the same
  hour** on previous days.

- **Incident correlation** — instead of drowning the analyst under 50 alerts, we
  **group** those of a single host into **one story**: *"Execution →
  defense evasion → credential theft → ransomware attempt."*

---

## 5. The automatic programs (what runs, when)

These are scheduled "robots" (systemd timers). There is **nothing to launch
by hand**.

| Program | Frequency | Role |
|-----------|-----------|------|
| `omni-collect-health` | 1 h | Collection coverage + detection of silent (go-dark) hosts |
| `omni-vuln-scan` | 1 d | Cross-references the software inventory with actively exploited flaws (CISA KEV) |
| `omni-ueba-score` | 30 min | Recomputes the risk score of each entity |
| `omni-ueba-geo` | 30 min | Impossible travel |
| `omni-ndr-beacon` | 6 h | C2 beacons |
| `omni-ndr-dns` | 1 h | DNS tunnels |
| `omni-ueba-volume` | 1 h | Volume anomalies |
| `omni-incident-correlate` | 15 min | Groups detections into incidents |
| `omni-geo-flux` | 30 s | Feeds the real-time cyber map |
| `omni-monthly-report` | 1st of the month | Generates + sends the executive PDF report |
| `omni-weekly-report` | weekly | Weekly email report |

---

## 6. The alerts — how it is prioritized

When a rule fires, a **notification** goes out (email + Teams). Three
levels:

- **P3 (critical)** — immediate action (log tampering, DCSync, ransomware,
  critical correlated incident, etc.).
- **P2 (important)** — to be handled quickly (C2 beacon, DNS tunnel, go-dark host, UEBA
  entity ≥ 80, impossible travel, etc.).
- Anti-spam: the same alert that persists is **not resent in a loop**
  (6 h delay for conditions that last).

---

## 7. The real-time cyber map

Address: **`https://<siem>/kit/carte-cyber.html`**. It shows, as
**animated arcs on a world map**, the attacks targeting the company
(blocked connections, malicious IPs, VPN attacks, etc.), with their **country
of origin**. Updated every 30 seconds. *Ideal for a SOC wall screen.*

---

## 8. Log retention & compliance (ISO 27001)

- **Security folder retained 12 months** (Windows, Sysmon, M365, vSphere, etc.);
  **firewall traffic 90 days** (high volume, shorter forensic value).
- Low-value noise is filtered to fit within disk space.
- Detailed policy: `docs/POLITIQUE-RETENTION.md` (audit evidence, mapped to
  ISO 27001 controls A.8.15 / A.8.16 / A.8.17).

---

## 9. Where to start when you arrive in the morning (routine)

1. **Management** — a quick glance: any critical incidents? any at-risk entities?
2. **Incidents** — read the day's attack narratives, handle the *critical* ones.
3. **UEBA / NDR** — check the top at-risk entities, the behavioral
   detections.
4. **Collection health** — make sure all sources are reporting (coverage
   ~100%, no go-dark host).
5. Mailbox / Teams — handle the alerts received.

---

## 10. Glossary (for non-specialists)

| Term | Simple explanation |
|-------|--------------------|
| **Log / journal** | Written trace of an event (connection, file opened, network packet, etc.). |
| **Detection / alert** | An event that matches a "suspicious" rule. |
| **MITRE ATT&CK** | Global catalog of the techniques used by attackers (each technique has a Txxxx code). |
| **Kill-chain** | The successive stages of an attack, in order. |
| **Incident** | Several related detections, grouped into a single case to handle. |
| **UEBA** | Analysis of user/machine behavior to detect the abnormal. |
| **NDR** | Detection on network traffic (beacons, tunnels, etc.). |
| **LSASS** | Windows process that holds passwords in memory — the #1 target of credential thieves. |
| **DCSync** | Technique to steal all the passwords of an Active Directory domain. |
| **Beaconing / C2** | Hidden communication channel between an infected workstation and the attacker. |
| **DNS tunnel** | Exfiltrating data discreetly via the DNS service. |
| **go-dark** | A host that suddenly stops emitting logs (failure... or an attacker cutting off monitoring). |
| **KEV** | Official list (CISA) of flaws **actively exploited** by attackers. |
| **Entropy** | A measure of the "disorder" of a text; a very random (hence encoded) text has high entropy. |
| **Firewall / deny** | Equipment that filters the network; "deny" = blocked connection. |

---

*Reference document — SIEM OMNITECH Security. For the technical implementation
detail, see `CONTEXT.md`. For the retention policy,
`docs/POLITIQUE-RETENTION.md`.*
