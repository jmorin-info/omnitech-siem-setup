# Co-managed MDR — pricing & decision (night/weekend coverage + threat-intel)

**OMNITECH SECURITY — 2026-06-18 — intended for: Julien Morin (CISO/dev)**
**Upstream decision:** adopt a **co-managed MDR** to close the 3 *irreducible* gaps of the internal build
(24/7 human SOC, threat-intel/dark-web, cyber warranty). See `docs/REVUE-CRITIQUE-PLATEFORME-IA-2026-06-18.md`.
**Scope of this doc:** frame the perimeter, the model, benchmark the 2026 market, price it, and list the
switch criteria + RFP questions.

> **Reliability of the figures.** MDR prices are almost all **quote-based**; the ranges below
> come from public 2026 benchmarks (sources at the end of the doc) and from **estimates explicitly flagged
> `[EST]`**. None is an OMNITECH quote. Rate used: 1 USD ≈ €0.93.

---

## TL;DR

- **The rational perimeter is NOT a full-stack MDR** (which would duplicate your already mature SIEM/EDR) but a
  **co-managed SOC augmentation**: **night + weekend + public holiday** coverage, with the internal team keeping
  the lead during business hours and **remaining owner of the detection policy**, + a
  **CTI/dark-web** component.
- **Choose a *technology-agnostic* provider (BYO-SIEM/EDR)** that consumes your Graylog alerts and your ESET
  telemetry **via API**, definitely not a "platform-native" MDR that imposes its agent. **Counter-intuitive
  consequence: Bitdefender MDR — the reference you wanted to reproduce — is eliminated** (GravityZone
  agent mandatory, no third-party EDR, non-EU SOC).
- **Favor a sovereign FR/EU player** (Orange Cyberdefense SecNumCloud, Advens, Intrinsec, Sekoia) —
  consistent with your "local-first" choice for the LLM and with ISO subcontracting (A.5.19–A.5.23).
- **Planning pricing**: targeted co-managed night/WE option ≈ **€35,000 – €80,000/yr** `[EST]`;
  + CTI/dark-web ≈ **€10,000 – €40,000/yr** `[EST]`. To be compared with a **full 24/7** MDR ≈ **€60,000 – €140,000/yr**
  `[EST]` and with a **real in-house 24/7** (~5-6 FTE) ≈ **€400,000 – €550,000/yr** `[EST]`.
- **Verdict: co-managed night/WE is economically rational** (an order of magnitude below in-house 24/7,
  more sustainable than a home-grown on-call rotation). **But don't expect a proportional discount**
  "because we only take nights": the provider's SOC runs 24/7 anyway, onboarding and telemetry are
  complete — negotiate an explicit *co-managed/augmentation tier*.

---

## 1. Retained perimeter

**What we buy:**
- **Time coverage**: nights (≈ 7pm–8am), weekends, public holidays — i.e. the ~128 h/week when the internal
  team is not operational (out of 168 h). Monitoring, triage, and **first-level response** (per
  mandate) on critical alerts.
- **Threat-intel / dark-web monitoring**: watch for OMNITECH credential leaks, domain/brand exposure,
  mentions on forums/markets, contextualized IOCs re-injectable into Graylog/SOAR.
- **Escalation on-call**: a contact reachable < 30 min on a critical nighttime incident (home-grown
  equivalent of Bitdefender's "Pre-Approved Actions" + SAM).

**What we do NOT buy** (already covered by the internal build, cf. review):
- The detection engine (Graylog pipelines, 74 MITRE rules, UEBA/NDR, incident correlation).
- The FortiGate blocking SOAR (`omni-soar`), reporting, SOC dashboards.
- The EDR (ESET) — kept as a telemetry source; we do not replace the agent.

**Guiding principle (co-managed, not outsourced):** OMNITECH **remains owner** of the detection policy and
of the action decision; the provider **operates the off-hours** and **enriches** (CTI), without imposing its
stack or taking over governance. "Your internal security team remains the primary owner of your policy
configuration" model (standard market co-managed wording).

---

## 2. Co-managed model: RACI, technical articulation, reversibility

**Synthetic RACI:**

| Activity | Internal (business hours) | Provider (night/WE) |
|---|---|---|
| Detection policy & rules | **R/A** (owner) | C (proposes improvements) |
| Tuning, exceptions, allowlists | **R/A** | C |
| Alert triage (business hours) | **R/A** | I |
| Triage + investigation (night/WE) | I | **R** (A stays internal) |
| Reversible response (isolation/blocking) | **R/A** | **R** on pre-approved actions, else escalation |
| Threat-intel / dark-web | C | **R/A** |
| Destructive action decision | **A** (internal human-in-the-loop) | mandatory escalation |
| ISO compliance / evidence | **R/A** | C (provides intervention logs) |

**Articulation with the existing SIEM/EDR — the #1 technical criterion:**
- **Desired model (BYO)**: the provider **consumes** your feeds — Graylog alerts/events (REST API,
  webhook, or Syslog/CEF export) + ESET telemetry — and works **within** your console or its overlay
  (ReliaQuest GreyMatter / Binary Defense type), **without forced re-ingestion** into its own SIEM.
- **Model to avoid**: the platform-native MDR that requires **its** agent (Bitdefender = GravityZone
  mandatory, no third-party EDR) → fleet re-deployment, dual agent, loss of the build's value, lock-in.
- **Hidden cost point**: if the provider **re-ingests** your logs into its SIEM, **volume-based** billing
  applies (≈ $0.50–2.00/GB above a baseline). Now you produce **~25 GB/day (~750 GB/month)** → to be
  scoped imperatively (filter what leaves, or stay in the "the provider reads Graylog" model).

**Reversibility (contractual requirement):** data and rules stay with you (Graylog is the source of
truth); exit clause with return/destruction of data, no dependency on a proprietary agent, reasonable
notice. This is precisely the advantage of BYO co-managed over platform MDR.

---

## 3. Market options (2026)

| Provider | Pricing (indicative) | Real co-managed / BYO-SIEM-EDR | Third-party stack integration (Graylog/ESET) | Data location |
|---|---|---|---|---|
| **Bitdefender MDR / MDR PLUS** | Quote-based; 2 tiers. MTTD 24 min (MITRE 2024), notif SLA ≤30 min. Warranty up to **$1M but ≥1000 endpoints** (→ **OMNITECH not eligible**) | "Co-Managed" marketing but **GravityZone agent mandatory, no third-party EDR** | Weak (imposes its agent) | SOC San Antonio / Bucharest / Singapore — **no EU residency guarantee** |
| **Arctic Wolf MDR** | $8–25/endpoint/month (base); effective SMB $25–40/user/month; entry ~$44k/yr (≤100 users), median deal ~$96k/yr | Concierge Security Team, "your tools + our SOC" model | Broad SIEM/EDR connectors | US-centric (EU option to verify) |
| **Sophos MDR** | $7–17/endpoint/month (base); effective $15–25/user/month with servers + Intercept X + packs | Supports third-party telemetry ("MDR Complete") but pushes its EDR | Integrates third-party EDR/SIEM via packs | EU region available (to confirm) |
| **Orange Cyberdefense** (FR) | Quote-based | SOC managed / MDR / XDR, co-managed model | Agnostic, strong in integration | **SecNumCloud** (Cloud Avenue SecNum ANSSI-qualified, Jul. 2025) |
| **Advens / ITrust** (FR) | Quote-based | Players claiming full **strategic autonomy** | Agnostic | FR sovereign |
| **Intrinsec** (FR) | Quote-based | **Outsourced 24/7 SOC**, ANSSI-certified experts, SIEM/SOAR | Agnostic (reputed CTI) | FR |
| **Sekoia.io** (FR/EU) | Quote-based (platform + partner MDR) | Open SOC/XDR platform, 900+ rules, 24/7 | **Designed to ingest third-party sources** | EU |
| **ReliaQuest / Binary Defense / Huntress** (US) | Quote-based | Explicit **BYO-SIEM/EDR** (overlay above the existing) | API-first, data portability | US (except EU option) |

**Reading:** for OMNITECH (sovereignty + keeping Graylog/ESET), the **winning quadrant = agnostic FR/EU
players** (Orange Cyberdefense, Advens, Intrinsec, Sekoia). The US BYO players (ReliaQuest/Binary Defense)
are technically excellent but lose on sovereignty. Bitdefender is **disqualified** by agent lock-in and
location — assumed paradox: we reproduce its *tech* in-house, we don't take its *service*.

---

## 4. Pricing

**OMNITECH sizing base:** ~**150 workstations** + ~**90 VMs/servers** + 3 sites. Common server
multiplier **1.5–2.5×** the workstation price (servers run 24/7, generate more telemetry). "Endpoint-
equivalents" ≈ 150 + (90 × ~2) ≈ **~330**.

| Scenario | Assumptions | Annual cost `[EST]` |
|---|---|---|
| **A. Full 24/7 MDR** (high reference) | 150 workstations @ $10–25/month + 90 servers @ $50–100/month | **~€60,000 – €140,000/yr** |
| **B. Targeted co-managed night/WE + escalation** (retained option) | ~40–70% of a full (the SOC runs 24/7, complete onboarding; no proportional discount) | **~€35,000 – €80,000/yr** |
| **C. CTI / dark-web** (standalone or bundle) | brand/credential/domain monitoring → full CTI | **~€10,000 – €40,000/yr** |
| **B + C combined** (OMNITECH target) | often a partial bundle at the FR players | **~€45,000 – €100,000/yr** |
| **D. Real in-house 24/7** (anti-model) | 5–6 SOC analyst FTE, loaded cost ~€80–110k/FTE | **~€400,000 – €550,000/yr** |
| **E. Light in-house on-call** (shaky compromise) | 3–4 people in rotation + on-call premiums | **~€60,000 – €120,000/yr** but degraded response + burnout/key-person risk |

**Billing traps to neutralize in the RFP:**
1. **Log volume**: ~750 GB/month — require a "reading from Graylog" model or a generous included GB baseline,
   otherwise 0.50–2.00 $/GB overbilling.
2. **Servers**: 90 VMs at a 2–2.5× multiplier can **double** the bill vs a "per workstation" count.
3. **Add-ons**: retention >90 d, awareness, IR retainer, onboarding → check what is included.
4. **Commitment**: 1-year vs 3-year discounts (mind reversibility if lock-in).

---

## 5. Build-only vs co-managed: what co-managed *actually* adds

The internal build already covers **75–85% of the MXDR tech** (cf. review). Co-managed adds no tech —
it adds **3 things not reproducible in-house at reasonable cost**:

1. **Human eyes at night/WE.** The alternative (scenario D) costs **5–10×** more for a real staffed
   24/7; the light on-call (E) is cheaper but **degraded** (latency, fatigue, and above all
   **worsens the key-person risk** — the opposite of what we just fixed with the git P0).
2. **Threat-intel/dark-web** that you cannot produce alone (no Bitdefender Labs / no CTI team).
3. **A risk transfer** (and, at some providers, a cyber warranty — but reserved for large fleets;
   OMNITECH at 150 workstations does not reach the thresholds of $1M warranties).

**Opportunity cost:** every euro put into a *full-stack* MDR that duplicates Graylog/ESET is wasted.
The spend is justified **only** on the delta (night/WE + CTI). Hence the §1 perimeter.

---

## 6. Compliance & sovereignty

- **GDPR / location**: logs contain personal data (logins, IPs, M365 UPNs). Require **processing and
  storage in the EU**, signed DPA, list of further subprocessors, no transfer outside the EU without
  guarantees. → clearly favors **FR/EU** players; **disqualifies** a US/non-EU SOC without a residency
  option (Bitdefender as-is).
- **SecNumCloud / ANSSI**: if the risk analysis requires it (or a client/insurance requirement), aim for
  **SecNumCloud** hosting (Orange Cloud Avenue SecNum qualified Jul. 2025) — "imperviousness to extra-EU laws."
- **ISO 27001:2022 — subcontracting**: the mission falls under **A.5.19–A.5.23** (supplier relationships,
  security in agreements, supply-chain management, monitoring of supplier services, cloud security).
  For the **Stage 2 audit (Nov. 2026)**: contract + DPA + SLA + reversibility clauses + **periodic
  review of the provider** (expected evidence). A well-tracked co-managed setup becomes **evidence** of
  A.5.7 (threat-intel) and A.8.16 (24/7 monitoring), not a gap.
- **Key contractual clauses**: notification SLA (< 30 min critical), exact scope of authorized nighttime
  actions (reversible only, escalation for the destructive — aligned with ANSSI R9), ownership and
  **reversibility of data/rules**, right to audit, location, subprocessors, exit plan.

---

## 7. Recommendation, switch criteria, RFP questions

**Recommendation:**
1. Launch a **restricted RFP** to **3–4 agnostic FR/EU players**: **Orange Cyberdefense, Advens,
   Intrinsec, Sekoia** (+ possibly a US BYO as a price benchmark: ReliaQuest/Binary Defense).
2. RFP perimeter = **co-managed night/WE + CTI/dark-web** (scenario B+C), **BYO-SIEM/EDR** (reading from
   Graylog + ESET, no forced re-ingestion), strong reversibility.
3. Framing budget: **~€45,000 – €100,000/yr** `[EST]`, to be confirmed by quote. Rule out from the start
   the full-stack MDR and any provider requiring its agent.

**Trigger criteria (when to sign):**
- Nighttime/weekend incident(s) **detected too late** in real operations (measure of after-hours MTTD);
  **or**
- **Client/insurance/audit** requirement for a 24/7 SOC; **or**
- HR inability to sustain an in-house on-call rotation (scenario E confirmed untenable).
*Failing that, stay in build-only + alerting (the improved notifications already reduce the risk of
missing a signal) and reassess after 6 months of operation.*

**Open questions for the RFP:**
- Do you consume **our** Graylog alerts / our ESET EDR **via API**, or do you impose your stack/agent?
- **Exact** pricing: per workstation, per server (multiplier?), by log volume (included GB baseline?)?
- **Night/WE** model: dedicated tier, or the price of a full 24/7? Real discount for partial coverage?
- **Location** of the data and the analysts? SecNumCloud available?
- Scope of **autonomous actions** at night? Escalation process < 30 min?
- **CTI/dark-web**: included or option? Which sources, what reporting re-injectable into Graylog/SOAR?
- **Reversibility**: return/destruction of data, notice, exit plan?

---

## Caveats

- **No price here is an OMNITECH quote.** The `[EST]` are planning ranges derived from public 2026
  benchmarks and sizing assumptions (server multiplier, log volume); the real gap can be wide. **Get 2–3
  quotes before any committed budget.**
- **FR/EU prices are opaque** (quote only): the sovereign comparison is done on model and compliance,
  not (yet) on the displayed price.
- The **cyber warranty** ($1M Bitdefender) only applies to large fleets (≥1000 endpoints) — **not
  relevant** for OMNITECH; the risk transfer rather goes through a classic **cyber insurance**.
- The MDR market moves fast (consolidation, BYO on the rise): re-verify offers/residency at the time of
  the RFP.

## Sources
- [MDR Cost 2026 (mdrcost.com)](https://mdrcost.com/) · [MDR Providers — pricing](https://mdrproviders.io/pricing) · [MDR pricing 2026 (learn)](https://mdrproviders.io/learn/mdr-pricing)
- [Bitdefender MDR review 2026 (mdrproviders.io)](https://mdrproviders.io/providers/bitdefender-mdr) · [Bitdefender Managed Services](https://www.bitdefender.com/en-us/business/services/managed-services)
- [Arctic Wolf MDR](https://arcticwolf.com/solutions/managed-detection-and-response/) · [Sophos MDR review 2026 (zerometric)](https://zerometric.net/review/sophos-mdr/) · [UnderDefense — MDR pricing](https://underdefense.com/mdr-pricing/)
- [Co-managed security services (SonicWall)](https://www.sonicwall.com/glossary/comanaged-security-services) · [Huntress — MDR/EDR vendors 2026](https://www.huntress.com/cybersecurity-insights/managed-detection-response-vendors)
- [Sovereign MSSP (Journal du Net)](https://www.journaldunet.com/cybersecurite/1541445-mssp-souverains-qui-sont-ils/) · [Managed SOCs France 2026 (SOC Monitor)](https://soc-monitor.com/acteurs/soc-manages-france/) · [Intrinsec — SOC 24/7](https://www.intrinsec.com/en/soc-securite-operationnelle/) · [Sekoia.io](https://www.sekoia.io/en/homepage/) · [Orange — sovereignty/SecNumCloud](https://www.orange.com/en/whats-up/european-digital-sovereignty-orange-steps-face-growing-threats)

---
*Pricing/decision document — to be filed in the dossier (REG_016) and linked to the supplier register /
risk analysis for the ISO 27001 Stage 2 audit (Nov. 2026).*
