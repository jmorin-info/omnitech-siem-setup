# OMS-XDR — Correlation/response XDR layer on top of Graylog

An overlay that turns OMNITECH's Graylog (10.33.220.10) into a platform for
**correlated detection + guided remediation + response**, on the functional
model of a market MXDR, with no dependency on an external SOC.

> ⚠️ **Integrated state (18/06/2026) — see [`docs/INTEGRATION-OMNITECH.md`](docs/INTEGRATION-OMNITECH.md).**
> The actual deployment on the SIEM VM differs from the original design described below:
> **read via local OpenSearch** (not the REST API), **GELF HTTP reinjection on 12201**
> (existing input, not a dedicated 12222), **local `qwen2.5:3b` LLM**, **FortiGate blocking
> delegated to the `omni-soar` feed** (no direct FortiOS API). Graylog token not required.

---

## 1. What Bitdefender MXDR does — and how we reproduce it

Bitdefender MXDR = the **GravityZone Defense XDR** bundle (endpoint /
identity / network / productivity sensors) + the **MDR** service (24/7 SOC, *Pre-approved
Actions*). The correlation and reinjection engine actually relies on
**Streams & Pipelines** — Graylog terminology: reproducing these functions
on your SIEM is therefore perfectly aligned.

| MXDR capability | OMS-XDR equivalent (self-hosted) | Status |
|---|---|---|
| Multi-domain sensors (endpoint, network, identity, productivity) | FortiAnalyzer→Graylog (network/FW), Winlogbeat (Windows/identity), Sysmon (planned), ESET EDR, FortiClient, + **netscan** (network discovery) | Existing + netscan added |
| Cross-domain correlation → incidents | `correlation.py` + `rules.yaml` (atomic signals → attack chains per entity) | **Delivered** |
| MITRE ATT&CK mapping | techniques/tactics carried by each rule | **Delivered** |
| Network Attack Defense (scan, brute force, lateral) | FortiGate IPS signals + `netscan` (port delta) | **Delivered** |
| Threat intel / enrichment | Graylog lookup tables (abuse.ch/OTX/MISP) to be wired in | To be wired |
| Behavioral detection / anomalies | per-entity thresholds today; statistical anomalies to be added | Partial |
| Analyst triage / readability (AI summary) | `enrich.py` via **Ollama/Mistral 7B** (FR narration) | **Delivered** |
| Guided remediation | `remediation.py` (per-technique playbooks, OMNITECH-specific) | **Delivered** |
| Pre-approved Actions (isolate host, neutralize account) | `responder.py` (FortiGate / AD / NinjaOne) — **dry-run by default** | **Delivered** |
| Human 24/7 SOC | not reproducible in-house — compensated by Teams notification + timers | N/A |
| Reporting | Graylog dashboards on the "OMS-XDR Incidents" stream | To be built |

Accepted difference: no human analysts 24/7. The reproducible value is
**correlation + enrichment + tooled remediation**, under CISO control.

---

## 2. Architecture

```
 Sources                Graylog (SIEM)            OMS-XDR (this layer)
 ───────                ──────────────            ──────────────────────
 FortiAnalyzer ─CEF1514─┐
 Winlogbeat   ─────────►│  streams + pipelines ──► correlation.py (signals→rules)
 Sysmon/NinjaOne ──────►│                              │
 oms-netscan ──GELF────►│                              ├─► enrich.py (Ollama)
                        │                              ├─► remediation.py (playbooks)
                        │◄──── GELF 12222 ─────────────┤   responder.py (FGT/AD/Ninja)
                        │   stream "OMS-XDR Incidents"  └─► Teams (Power Automate)
```

Architecture choice: **no Graylog Java plugin**. The 6.x plugin API is
unstable between versions and allows neither response orchestration nor
LLM calls. A decoupled external layer (REST query + GELF
reinjection) is more robust, versionable and testable — and survives Graylog
version upgrades.

---

## 3. Installation (Debian 13)

```bash
sudo useradd -r -s /usr/sbin/nologin oms-xdr
sudo mkdir -p /opt/oms-xdr /etc/oms-xdr /var/lib/oms-xdr
sudo cp -r oms_xdr /opt/oms-xdr/
sudo cp config.yaml /etc/oms-xdr/
sudo cp deploy/oms-xdr.env.example /etc/oms-xdr/oms-xdr.env
sudo chmod 600 /etc/oms-xdr/oms-xdr.env
sudo chown -R oms-xdr:oms-xdr /opt/oms-xdr /var/lib/oms-xdr

python3 -m venv /opt/oms-xdr/.venv
/opt/oms-xdr/.venv/bin/pip install -r requirements.txt
sudo apt install -y nmap jq        # netscan + setup
```

Fill in `/etc/oms-xdr/oms-xdr.env` (ideally injected from Vaultwarden).
The Graylog token is used in Basic `token:token`.

```bash
# Provision the GELF input + the incidents stream
export OMS_GRAYLOG_TOKEN=********
bash deploy/setup_graylog.sh        # copy the stream IDs into config.yaml
```

Enable the timers:

```bash
sudo cp deploy/*.service deploy/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now oms-xdr.timer oms-netscan-quick.timer oms-netscan-full.timer
```

Manual test:

```bash
sudo -u oms-xdr OMS_GRAYLOG_TOKEN=$OMS_GRAYLOG_TOKEN \
  /opt/oms-xdr/.venv/bin/python -m oms_xdr.engine --once --config /etc/oms-xdr/config.yaml
```

---

## 4. Automatic response safety

`response.dry_run: true` by default: **no** action on the infra. Actions
are only logged as recommendations and written into the incident.
To enable real containment, flip `dry_run: false` **and** the targeted
`auto_*` flag. Recommendation: start in dry-run for 2–3 weeks, validate the
false-positive rate on the incidents stream, then selectively enable
`auto_block_fortigate` before the AD/endpoint actions.

---

## 5. Scan scope — legal/ISO framing

`netscan` only sweeps the **internal OMNITECH** networks declared in
`netscan.targets`. To be aligned with the real addressing plan (Oméga/Ivry/Lançon)
and traced in the ISMS (REG_016) as an asset-discovery activity
(mappable to A.5.9 inventory, A.8.8 vulnerability management).

---

## 6. Roadmap

1. **Threat intel**: Graylog lookup tables (abuse.ch, OTX) → `S_C2_IOC` signal.
2. **Sysmon**: NinjaOne deployment → fine-grained process/network signals (T1055, T1003).
3. **Anomalies**: per-entity EWMA baseline (4625 volumes/flows) instead of fixed thresholds.
4. **Vuln correlation**: cross netscan ↔ POL_018 (CVSS matrix) to prioritize.
5. **Dashboard** "OMS-XDR Incidents" + scheduled weekly report.
6. **Signed AD runbooks** (WinRM/NinjaOne) for `disable_ad_account`/`force_pwd_reset`.
