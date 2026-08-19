# Critical review & synthesis — AI detection/response platform on a Graylog foundation

**OMNITECH SECURITY — 2026-06-18 — intended for: Julien Morin (CISO/dev)**
**Subject:** reconcile the 3 research dossiers (`/tmp/prompt/compass_*.md`) with the real state of
`omnitech-siem-setup`, challenge their assumptions, and settle an executable sequence.
**Sources:** the 3 artifacts; `CONTEXT.md` (1007 l.), `README.md`, `docs/`, script-by-script inventory
(59 scripts / 10,238 lines of bash + 26 Python microservices `/usr/local/sbin/omni-*`).

---

## 0. Verdict in five decisions

1. **The 3 docs reason in greenfield; your system is in production and mature.** The "recommended
   starting point" of Doc 3 (Kerberoasting PoC → read-only multi-case MVP, i.e. its Lots 1-2, ~6 months) is
   **already delivered and surpassed**. Following the roadmap to the letter = rebuilding what is running.
2. **The real new scope reduces to 4 building blocks**: (a) LLM triage layer, (b) response actuators
   beyond IP blocking (ESET isolation, AD disabling), (c) cloud LLM chain (anonymization + ZDR) —
   **conditional**, (d) **active** surface scan — **to be deprioritized**. Everything else exists.
3. **Risk #1 is not the AI, it is the total absence of version control.** 10k lines of production
   security, zero git, zero test, zero CI, a single maintainer. **This is the absolute priority, before any
   line of AI**, and it is also direct evidence for the ISO audit (change management, clause 10).
4. **Start with the *local* LLM (Mistral/Ollama), not with cloud LLM.** It validates the value of triage without
   contractual dependency (ZDR), without anonymization risk, without exfiltration surface. Cloud LLM is only
   justified **after** proof of local value **and** of a case that Mistral 7B fails to handle.
5. **Cloud LLM provides NO evidence required for the Nov. 2026 audit.** The audit is served by the existing
   SIEM + the ISO dossier already drafted. The AI platform is a *plus*, off the audit's critical path,
   and must not jeopardize it (this is in fact what Doc 3 says — but the AI enthusiasm drowns it out).

---

## 1. The central mismatch: "to be built" vs "already in prod"

The three dossiers describe a BUILD as if the detection/correlation/response layer did not exist.
Quantified reconciliation (the "already done" % is the inventory's self-assessment, corroborated by `CONTEXT.md`):

| What the docs propose to "build" | Reality in `omnitech-siem-setup` | Already done |
|---|---|---|
| **Kerberoasting PoC** (Doc 3, Lot 1, starting point) | 4769 RC4 0x17 detection + non-machine SPN in prod, mapped to T1558.003, **+ canary account** with an `MSSQLSvc` SPN deliberately set as bait (`35-canary.sh`) | **100%** |
| Multi-source **correlation** microservice (Doc 1, Obj 1) | `omni-incident-correlate`: aggregates by entity, reconstructs the kill-chain (canonical order), scores 0-100 by saturation, 24h window, ≥2 tactics | **~70%** |
| **Sigma / MITRE detections** (Doc 1 & 3) | 74 pipeline rules, ~54 techniques / 14 tactics, Navigator export (`37`/`57`), MITRE enrichment on every event | **~85%** |
| **NDR / network monitoring** (Doc 1, Obj 2) | 4 services: C2 beaconing (coefficient of variation), DNS tunneling (entropy), network scan (T1046), impossible-travel (Haversine) | **~85%** |
| **SOAR / semi-autonomous response** (Doc 1 & 2) | `omni-soar`: webhook → feed → FortiGate deny, **no creds on the FW**, TTL 24h, whitelist, threshold, cap/kill-switch, GELF audit | **~60%** |
| **Unified "single pane of glass" console** (Doc 2 & 3) | SOC dashboard 19-21 pages (50 widgets), real-time cyber map, native Graylog drill-down | **~80%** |
| **Threat intel** (Doc 1) | Tor exit + Spamhaus DROP wired in, alert on public IP hit | partial (OSS) |
| **ISO retention / integrity** (cross-cutting) | Tiered retention, HMAC-SHA256 anti-tampering integrity chain (`omni-integrity`), DRP/PRO/POL drafted | **~90%** |
| **Reporting** (Doc 2, KPI) | Weekly HTML report + monthly PDF (weasyprint) + MTTD/posture KPIs | **~85%** |
| **LLM layer (Mistral/Ollama)** | — | **0%** |
| **Cloud LLM layer + Presidio anonymization + ZDR** | — | **0%** |
| **Response actuators** (ESET isolate, AD disable) | ESET ingested as a *log source* (syslog 1515), **no** response API | **0%** |
| **ACTIVE surface scan** (nmap/OpenVAS) | *Passive* mapping (FortiGate, `49-expo-port-class`) + KEV/patch detection (`38`); no active scanner | **0% (active) / ~70% (passive)** |

**Reading:** Doc 3's roadmap (Lots 1→8) starts by rebuilding what is, by its own
metric, 60-90% delivered. The project's center of gravity must shift from "building detection" to
"grafting a thin LLM layer + 2 actuators onto a foundation that already works".

---

## 2. The real new scope (the honest work list)

1. **LLM triage service** — 27th `omni-*` microservice, same pattern as the other 26 (consumes OpenSearch,
   emits GELF). Net-new, but small. **Value: incident narrative for the CISO + triage of the new/ambiguous
   patterns not covered by the rules + draft response plan.** It is a *copilot*, not
   an engine.
2. **Response actuators** — ESET PROTECT API (isolation/scan/kill) and AD disabling. Net-new on the
   integration side, **but the safety state machine already exists** in `omni-soar` (cf. §4-H).
3. **Cloud LLM chain** *(conditional)* — deterministic tokenization + Presidio as a net + contractual ZDR.
   To be undertaken only after §0-4.
4. **ACTIVE surface** *(to be deprioritized)* — nmap/OpenVAS. Lower added value (passive + KEV exist),
   higher operational risk (fragile prod + 14 partner tunnels).
5. **Human approval surface** — only useful once (2) is in place; small console extension.

Everything else in the 3 docs is either already done, or a *nice-to-have* (Grafana, CMDB, topology graph, iOS).

---

## 3. Detailed reconciliation by objective

### Doc 1 — Architecture (correlation+LLM / surface / MXDR)

| Objective | Doc's position | Gap with reality | Verdict |
|---|---|---|---|
| **Obj 1** Correlation + LLM microservice | Build a FastAPI that polls `/events/search`, re-correlates by key/window, maps MITRE, then LLM | Correlation + MITRE **already done** (pipelines + `omni-incident-correlate`). The doc risks **duplicating the engine** (2nd source of truth = divergence) | Do **not** rebuild the correlation. Add **a single stage**: LLM downstream of `event_source=incident`. Keep the stdlib/timer idiom, **not FastAPI** (cf. §4-C) |
| **Obj 2** Exposure surface | FortiGate passive + prudent nmap/OpenVAS active | Passive **already done**; scan detection **already done**; **active = the only real novelty** | Keep the passive. Active = **last priority**, authenticated OpenVAS only if A.8.8 requires it beyond the KEV |
| **Obj 3** Reproduce ~70% of Bitdefender MXDR | ~70% reproducible, hard gaps = 24/7 human + dark-web + guarantee | On the *technical* axis, you are rather at **75-85%** already (strong SIEM, NDR-logs+beaconing, SOAR-block, scoring, threat-intel). The hard gaps are accurate | Reframe: you have **already built the essentials of the MXDR *technology***. The irreducible part = the *staffed service* + the *insurance*, not the technology |

### Doc 2 — Cloud LLM integration (hybrid / Presidio / console / continual improvement)

| Aspect | Doc's position | Gap / critique | Verdict |
|---|---|---|---|
| **A** Hybrid Mistral/cloud-LLM router + tool gateway | Routing score, approval state machine, anti-injection | Excellent in principle. **The state machine exists in v1 in `omni-soar`** (validate→policy→TTL/cap→execute→audit) | **Generalize `omni-soar`**, do not redesign from scratch |
| **B** Reversible Presidio anonymization | Presidio = backbone, modest FR recall | **Inversion needed**: your data is mostly *structured* (known field schema). Deterministic tokenization **= backbone** (100% recall on the known fields), Presidio = *net* on free text (cmdline/message). Cf. §4-D | Adopt Presidio **as a backstop**, not as the spine |
| **C** Console (Grafana + NestJS) | Assemble everything | The "single pane of glass" **already exists** (SOC dashboard + map). Grafana only adds infra metrics (Centreon/Prometheus) | Console = **small extension** (approval + nominative auth), not a project |
| **D** Continual improvement + n8n/Ansible orchestration | Closed loop, nightly Batch API | Doc 3 itself documents the **n8n trap** (abandoned as soon as conditionals/state appear). Keep the complex part in controlled code | n8n for the simple linear only; Ansible for idempotent config |

### Doc 3 — Roadmap (Lots 0-8)

| Lot | Doc's position | Reality | Verdict |
|---|---|---|---|
| **0** Foundation / anti-key-person (IaC, git, doc) | "cross-cutting, immediate start" | **Under-weighted.** It is in fact **THE #1 priority and it is urgent**: no git, no test (cf. §6) | **Raise to absolute P0** |
| **1** Kerberoasting PoC | starting point | **Already in prod** | Skip (but propagate the RC4 2026 calendar note, cf. §5) |
| **2** Read-only multi-case MVP | 10-15 Sigma rules | **74 rules already in prod** | Largely surpassed |
| **3** Cloud LLM layer + Presidio | advisory mode | Net-new, but **start local** (cf. §0-4) | Re-sequence: local Mistral **before** cloud LLM |
| **4** Tool gateway for reversible actions | the "recommended reinforcement" lot | Safety pattern **already proven** (`omni-soar`) | Generalize, not rebuild |
| **5** Unified console | Grafana + NestJS | **~80% already there** | Targeted extension |
| **6** Attack surface | passive + active | Passive done; active = to be deprioritized | Push back |
| **7** Continual improvement | posture reviews, clause 10 register | Reports + KPIs already there; the **formal register** is missing | Real value = formalize the register |
| **8** iOS app | outsource/defer | Depends on a nonexistent approval workflow; the least likely competency | **Out of scope until stabilization** |

---

## 4. Critique of the assumptions (the substance)

**A. The greenfield fallacy (master critique).** Already treated in §1. Practical consequence: any estimate
in person-days from Doc 3 for Lots 1-2 is moot; those lots are the past.

**B. The correlation microservice is a partial reinvention.** `omni-incident-correlate` *is* the
engine that Doc 1 wants to build. The only legitimate evolution is **latency**: the correlator is a
15-min timer; the docs suggest a webhook flow. But that is "add a webhook trigger + an LLM stage to the
existing correlator", **not** "build a new correlation microservice". Two engines = two
truths = drift.

**C. FastAPI is oversized for the current form.** Your 26 services are in **Python stdlib**
(HTTPServer, timers) — a deliberate choice, minimal dependencies, idempotent. The docs impose by default
FastAPI + httpx + APScheduler + pySigma + psycopg/pgvector. For a **solo** maintainer with the key-person
being risk #1, stacking an async framework + an ORM + a vector database **contradicts** the philosophy that
makes this system maintainable. Keep the stdlib/systemd for the LLM service; only introduce pgvector
if the RAG is *validated* as necessary. **Do not import a framework to host an endpoint.**

**D. Presidio: the right risk, but the wrong architecture.** Doc 3 is right to hammer on the modest FR recall
(~0.74, FR phone numbers at 0%). But it misses a decisive subtlety: **your data is largely
structured** — Graylog gives you `user`, `host`, `src_ip`, `dest_ip`, `process_name`… (known schema,
listed in `CONTEXT.md`). We **do not need** probabilistic NER to anonymize a known field: we
**tokenize it deterministically** (100% recall on those fields). Presidio only serves for the **residual
free text** (command lines, message bodies). Correct architecture:
*deterministic per-field tokenization (spine) → Presidio/regex on the free text (backstop) → fail-closed.*
This **de-risks the entire cloud LLM path** and reduces Presidio from a point of failure to a net.

**E. The question the 3 docs dare not ask: "do we need cloud LLM?"** They assume cloud LLM
desirable and debate the *how*. A senior look poses the *if*. The system already does detection + scoring
0-100 + kill-chain. The *marginal* value of an LLM = (1) narratives for the CISO, (2) triage of new
patterns, (3) draft response plan, (4) posture reviews. Real, but it is a **copilot**. Against it:
ZDR dependency, residual Presidio leakage, injection surface (the logs are *attacker-controlled* —
the docs are right to insist), cost (+35% of tokens with the new tokenizer, Doc 2 note), maintenance. **So:
prove the value *locally* first. If Mistral 7B suffices for triage, the cloud LLM/ZDR/Presidio saga is
perhaps unnecessary.** The docs sequence Mistral→cloud LLM but never make this tipping point explicit.

**F. The "~70% MXDR" is now measurable — and higher than 70% on the tech axis.** Given the inventory,
the *technical* reproduction is rather at 75-85%. The honest formulation: **you have already built the
essentials of the MXDR *technology*; what you cannot build is the *24/7 human service*, the *deep
threat-intel/dark-web*, and the *cyber guarantee* (an insurance product, not a technology).** The
resulting build-vs-buy: do not buy an MXDR for the technology; consider a **co-managed MDR only**
for the night/weekend coverage + threat-intel, **if** a risk analysis justifies it.

**G. The key-person is indeed risk #1 — and the evidence is damning.** Cf. §6: no git, no test.

**H. Technical credibility detail (the docs "smell" of the outside).** Cf. Appendix. In short: Doc 1's curl
example hits `:443` whereas the API is `:9000` behind nginx, end-to-end TLS, `--cacert`,
`X-Requested-By`, and above all **the `lib-graylog.sh` helpers (wrap_entity/post_entity) exist**; the GELF
reinjection bus `:12201` / `event_source=siem_*` **exists** (M365, SOAR, backup, integrity already use it);
and the tool gateway's state machine **exists in v1** in `omni-soar`.

**I. Active scan: the caution is right, but the priority is misplaced.** The whole spiel "never the partner
tunnels, masscan banned, nmap -T2/-T3, systemd timers" is correct. But the passive + scan detection + KEV
already exist. The active scan is **the riskiest and least differentiating brick** — to be pushed back, and
only in authenticated *minimally invasive* OpenVAS if the A.8.8 auditor asks for more.

**J. Console: the docs over-build.** SOC dashboard 19-21 pages + real-time map = the "single pane"
is there. The real gaps are narrow: the **approval** surface (useful only with the actuators (2))
and **nominative auth** (LDAPS exists, but a shared `admin` account is still used). iOS = defer/outsource.

---

## 5. What the docs got right (to keep as-is)

- **Prompt injection = risk #1, *architectural* defense not *model* defense**: authorization policy
  never delegated to the LLM, deterministic execution on the orchestrator side, human-in-the-loop for the non-reversible.
  Aligned with ANSSI R9/R25/R27. **Keep in full.**
- **Presidio recall to be measured on a real corpus** (I only invert spine/backstop, I do not cancel the guard).
- **ZDR is not self-service** (Sales/Enterprise agreement, Mythos/Fable model exclusions, retained safety
  classifiers) — a correct caveat if the cloud LLM path is undertaken.
- **"Read-only / advisory first, then actions"** — correct and consistent with your existing prudent culture.
- **ISO mapping** (A.8.11 masking, A.5.34 PII, clause 10) — correct.
- **Build-vs-buy per component**: build the differentiating core, adopt the OSS (SigmaHQ, Presidio).
- **RC4/Kerberos 2026 calendar note** (CVE-2026-20833, enforcement April 2026, end of rollback July):
  **useful and actionable now** — your Kerberoasting detection will see its RC4 false-positive base melt away;
  add monitoring of the **abnormal AES (0x12)** and of the **4769 spikes per account (3-sigma rule)**. To be carried
  into `12-graylog-pipelines.sh` / `omni-ueba-*` independently of everything else.

---

## 6. Risks, reordered (verified on the real system)

1. **🔴 Key-person / absence of version control — CRITICAL, IMMEDIATE.**
   `git` is **not installed**; **no repository** under `/root`. **10,238 lines** of production bash (59 scripts)
   + **26 Python microservices** are **under no versioning**. No test, no CI, no shellcheck.
   The only net: the daily AES-256 tar to SMB. The operational knowledge lives in `CONTEXT.md` (a
   changelog) **and in your head**. If you leave tomorrow, it is a black box. *ISO note: it is also a hole
   in change management (A.8.32) and in clause 10.* **→ P0 action, before any AI (cf. §7).**
2. **🟠 Indirect prompt injection** (as soon as an LLM reads logs). Handled by the architecture (deterministic
   policy + human-in-loop). **Never** give the LLM a destructive action in auto mode.
3. **🟠 Cleartext secrets.** The service secrets live in `00-vars.env` (chmod 600, **plaintext**).
   Vaultwarden is today an *audited log source*, **not** a secret-retrieval backend.
   Yet the response service will hold the most powerful creds (ESET isolate, AD disable): **those above all**
   must not end up in clear in `00-vars.env`. *The docs' "secret retrieval via Vaultwarden"
   is therefore both net-new AND a real hardening to do.*
4. **🟠 Active scan on prod + partner tunnels** — a real risk but **avoidable by pushing the brick back**.
5. **🟡 Alert / approval fatigue** — already encountered (the "Brute force" storm of 12/06). The LLM can
   *help* (group, narrate) or *worsen* (one more approval). To watch.
6. **🟡 Engine divergence** if a 2nd correlation is built alongside `omni-incident-correlate`.

---

## 7. Decision: revised sequence + build-vs-buy

**Guiding principle:** graft a thin AI layer onto a foundation that works, starting by de-risking
the organizational and the local before the external and the contractual.

**P0 — Put the existing under git + a test net (3-5 d). NON-NEGOTIABLE, BEFORE ANYTHING.**
Install git, initialize the repository (monorepo: scripts + `windows/` + `fortigate/` + `lookups/` + `docs/` +
**versioned copy of the `/usr/local/sbin/omni-*`**), push to the internal GIT server already backed up.
Add: `shellcheck` on the `.sh`, a syntax smoke-test (`bash -n`) + an idempotent migration test,
externalize the runbook out of your head. *Directly serves A.8.32 / clause 10 for the audit.* **No line
of AI before this point.**

**P1 — *Local* LLM triage in advisory mode (≈8-12 d).**
27th `omni-llm-triage` microservice (stdlib, timer or webhook): consumes `event_source=incident` (score ≥ threshold)
→ local Mistral/Ollama prompt → emits `event_source=llm_triage` as GELF (narrative + technique + proposed plan)
→ dashboard page + email. **Zero cloud LLM, zero Presidio, zero ZDR.** *Tests the central hypothesis*: does the LLM
add value on top of the 0-100 score? If not, you have saved the whole cloud LLM program.

**P2 — Generalize `omni-soar` into a tool-gateway (≈10-15 d), reversible actions only.**
Extend the existing state machine (validate→policy→TTL→execute→audit) to: **ESET isolation** (ESET
PROTECT API — net-new), **AD disabling** (dedicated least-privilege account). Reversible + rollback + dry-run by
default + strict exclusion of the 14 partner tunnels. The approval surface = the only real console extension.
Response secrets → harden (cf. §6-3).

**P3 *(conditional)* — Cloud LLM chain (≈15-25 d), if and only if P1 proves the value AND a real case escapes
Mistral 7B.** **Deterministic** tokenization on the known schema (spine) + Presidio backstop on free text +
fail-closed + ZDR agreement + DPA. Mistral/cloud-LLM router by score. **Fail-safe: if anonymization is doubtful or
ZDR not confirmed → stays local.**

**P4 *(optional / pushed back)* — Active surface (authenticated OpenVAS if A.8.8 requires it), Grafana infra, formalized
clause 10 register. iOS: out of scope until full stabilization.**

**Build-vs-buy:**
- **Build**: the LLM service, the tool-gateway extension, the approval surface (differentiating core).
- **Adopt (OSS)**: SigmaHQ rules, Presidio (backstop only), OpenVAS (if A.8.8 need).
- **Buy / consider**: co-managed MDR **only** for the 24/7 human + threat-intel/dark-web (the *irreducible*
  gaps), not for the technology. **Outsource**: iOS, UI polish.
- **Do not build**: 2nd correlation engine, FastAPI for one endpoint, heavy n8n orchestration.

---

## 8. Open decisions (to be settled by Julien)

1. **Cloud LLM scope:** do you accept the principle "local first, cloud LLM only if proven necessary",
   or is there an imperative (client, management) to integrate cloud LLM from the outset?
2. **ZDR / sovereignty:** are you ready to commit to a ZDR + DPA agreement with an LLM vendor (Sales negotiation), or does the
   GDPR/sovereignty constraint impose staying 100% local for the alert data?
3. **Response actuators:** how far in auto? (proposal: ESET isolation + AD disabling in
   *reversible auto* with rollback; everything else in human-in-the-loop — like `omni-soar` today).
4. **Active scan:** is the A.8.8 auditor satisfied with KEV/patch-age + passive (then we push back the active),
   or does it require an active vulnerability scan (then authenticated OpenVAS, strict OMNITECH scope)?
5. **Co-managed MDR:** do you want me to cost the "outsourced night/weekend + threat-intel" option as a
   complement, or does the 24/7 human stay out of budget (and therefore an owned gap)?
6. **Immediate priority:** do you confirm P0 (git/tests) before any AI? This is my strong recommendation.

---

## Appendix — Technical credibility corrections (for any future AI code)

- **Graylog API:** not `:443` but **`https://${SIEM_FQDN}:9000/api`**, end-to-end TLS, `--cacert
  /etc/graylog/certs/omnitech-rootca.crt`, `X-Requested-By` header on any non-GET. **Reuse
  `lib-graylog.sh`** (`api_get`/`api_put`/`wrap_entity`/`post_entity`) — the `CreateEntityRequest` envelope
  (`{"entity":…, "share_request":…}`) is already handled, and `api_put` can return exit 0 on failure → **always
  check `.id`** (trap documented in CONTEXT §7octies).
- **Reinjection bus:** GELF `:12201`, `event_source=siem_*` / `*_score` / `incident` / `llm_triage`,
  routed to the **"OMNI - Interne SIEM"** stream. The LLM verdicts must run on **this** existing bus,
  not a new one. (GELF reminders: JSON 1 line, custom fields prefixed with `_`, IP in `ip` format without `:port` —
  `clean_ip()` already exists; booleans ignored at ingestion.)
- **State machine:** `omni-soar` already implements validate→policy(non-RFC1918/whitelist/threshold)→cap/TTL→
  execute→GELF audit. The tool-gateway generalization starts from **there**.
- **Secrets:** today `00-vars.env` (plaintext, 600). Vaultwarden = log source, **not** a secret
  backend. The docs' "retrieval via Vaultwarden API" = net-new + hardening (a priority for the
  response creds).
- **Idiom:** services in **Python stdlib + systemd timers**, **idempotent** scripts. Any new AI service
  must follow this mold (testable, without a heavy framework, key-person-friendly).

---
*Review document — to be filed in the decision dossier (REG_016) and linked to the continual improvement register
(clause 10) once the §8 decisions are settled.*
