<div align="center">

# OMNITECH SIEM — Detection & Response Platform

**Self‑hosted, production‑grade SIEM and detection‑&‑response stack built on Graylog**
*Plateforme SIEM & détection/réponse auto‑hébergée, de niveau production, bâtie sur Graylog*

![Graylog](https://img.shields.io/badge/Graylog-7.1-1971c2)
![OpenSearch](https://img.shields.io/badge/OpenSearch-2.19-005EB8)
![MongoDB](https://img.shields.io/badge/MongoDB-8.0-13aa52)
![Debian](https://img.shields.io/badge/Debian-13-A81D33)
![Detections](https://img.shields.io/badge/detections-74_rules-d6336c)
![ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-54_techniques-e8590c)
![Status](https://img.shields.io/badge/status-production-2b8a3e)
![ISO 27001](https://img.shields.io/badge/ISO_27001-evidence_ready-364fc7)

**[English](#english) · [Français](#français)**

</div>

> ⚠️ **Internal operational repository.** Real secrets are **never** committed (see [Security & secrets](#security--secrets)). This repo provisions the production SIEM of OMNITECH SECURITY; treat it as sensitive infrastructure‑as‑code.

---

## Aperçu visuel · Visual tour

> 🔒 Captures **anonymisées** — comptes / hôtes / IP / SID pseudonymisés de façon cohérente (mode `MOBILE_REDACT`). *Anonymised screenshots: accounts / hosts / IPs / SIDs are consistently pseudonymised.*

### Console SOC « OMNI SOC » — *web console (VPN‑only)*

<div align="center">

[![Vue d'ensemble](docs/captures/01-vue-ensemble.jpg)](docs/captures/01-vue-ensemble.jpg)

*Vue d'ensemble · niveau de menace, KPI, tactiques ATT&CK, **anomalies ML (oms‑ml)** & risque UEBA, flux temps réel, origines géographiques*

</div>

| | |
|:---:|:---:|
| [![Incidents](docs/captures/02-incidents.jpg)](docs/captures/02-incidents.jpg)<br>**Incidents** · cas corrélés (oms‑xdr), statut/assignation/notes | [![Détections](docs/captures/03-detections.jpg)](docs/captures/03-detections.jpg)<br>**Détections** · liste filtrable 24 h (tactique / source) |
| [![Détections filtrées](docs/captures/11-detections-filtre.jpg)](docs/captures/11-detections-filtre.jpg)<br>**Détections filtrées** · drill par tactique | [![Entité‑360](docs/captures/09-entite-360.jpg)](docs/captures/09-entite-360.jpg)<br>**Entité‑360** · tactiques, techniques, événements récents |
| [![Matrice ATT&CK](docs/captures/04-matrice-attack.jpg)](docs/captures/04-matrice-attack.jpg)<br>**Matrice MITRE ATT&CK** · couverture × activité (7 j) | [![Graphe](docs/captures/05-graphe.jpg)](docs/captures/05-graphe.jpg)<br>**Graphe d'attaque** · entités ↔ techniques |
| [![Fuites](docs/captures/06-fuites.jpg)](docs/captures/06-fuites.jpg)<br>**Fuites & Dark Web** · RansomLook / HIBP / Dehashed / GitHub | [![Santé](docs/captures/07-sante.jpg)](docs/captures/07-sante.jpg)<br>**Santé & collecte** · cluster, fraîcheur par source |
| [![Rapport](docs/captures/08-rapport.jpg)](docs/captures/08-rapport.jpg)<br>**Rapport** · synthèse exécutive imprimable (PDF) | [![Palette](docs/captures/10-palette.jpg)](docs/captures/10-palette.jpg)<br>**Palette de commandes** (⌘K) · navigation |

### Graylog — *moteur SIEM sous‑jacent*

| | |
|:---:|:---:|
| [![Direction](docs/captures/graylog-01-dashboard-direction.jpg)](docs/captures/graylog-01-dashboard-direction.jpg)<br>**Dashboard « OMNI - SOC » · Direction** · KPI exécutifs | [![ATT&CK](docs/captures/graylog-02-attack.jpg)](docs/captures/graylog-02-attack.jpg)<br>**Onglet ATT&CK** · couverture & techniques |
| [![UEBA / NDR](docs/captures/graylog-03-ueba-ndr.jpg)](docs/captures/graylog-03-ueba-ndr.jpg)<br>**Onglet UEBA / NDR** · score comportemental, beaconing | [![OMS‑XDR](docs/captures/graylog-04-oms-xdr.jpg)](docs/captures/graylog-04-oms-xdr.jpg)<br>**Onglet OMS‑XDR** · incidents corrélés |
| [![Identité AD](docs/captures/graylog-05-identite-ad.jpg)](docs/captures/graylog-05-identite-ad.jpg)<br>**Onglet Identité AD** · Kerberos, authentifications | [![Comptes à privilèges](docs/captures/graylog-06-comptes-privileges.jpg)](docs/captures/graylog-06-comptes-privileges.jpg)<br>**Onglet Comptes à privilèges** |
| [![Sources](docs/captures/graylog-07-sources.jpg)](docs/captures/graylog-07-sources.jpg)<br>**Dashboard « Sources »** · télémétrie par source | [![Streams](docs/captures/graylog-08-streams.jpg)](docs/captures/graylog-08-streams.jpg)<br>**Streams** · routage (index sets dédiés) |
| [![Alertes](docs/captures/graylog-09-alertes.jpg)](docs/captures/graylog-09-alertes.jpg)<br>**Alertes & événements** | [![Analytics](docs/captures/graylog-10-analytics.jpg)](docs/captures/graylog-10-analytics.jpg)<br>**Dashboard « OMNI - Analytics »** · ML / UEBA / SLA collecte / santé robots / bruit FP |

### PWA mobile — *application installable (web‑push)*

| | |
|:---:|:---:|
| [![PWA Menace](docs/captures/pwa-01-menace.jpg)](docs/captures/pwa-01-menace.jpg)<br>**Menace** · niveau, KPI, **anomalies ML & risque UEBA** (parité console) | [![PWA Synthèse](docs/captures/pwa-02-synthese.jpg)](docs/captures/pwa-02-synthese.jpg)<br>**Synthèse** · KPI, courbe & tactiques ATT&CK |

---

## English

### Overview

A complete, reproducible SIEM and detection‑&‑response platform deployed on a single hardened Debian VM, plus a Windows/AD enrolment kit. It ingests Windows Security/Sysmon, FortiGate/FortiAnalyzer, Microsoft 365, vSphere, ESET, Vaultwarden and Veeam telemetry; normalises it into a common schema; runs **74 detection rules** mapped to **MITRE ATT&CK**; adds **behavioural analytics (UEBA/NDR)**, **incident kill‑chain correlation**, **light SOAR auto‑response**, and a **19–21 page SOC dashboard** — all provisioned by idempotent scripts and documented for **ISO 27001:2022** evidence.

Everything is code. Every script is **idempotent** (safe to re‑run) and stops on first error with a final check.

### Key capabilities

| Capability | What it does |
|---|---|
| **Detection engineering** | 100+ pipeline rules across 7 streams (AD/Sysmon, FortiGate, FortiManager, M365, vSphere, …) → tagged events (`alert_tag`) + 100+ alert definitions (mail + Teams), tumbling windows |
| **MITRE ATT&CK** | 69 `alert_tag` → 48 techniques / 12 tactics, risk score 0–10, ATT&CK Navigator layer + interactive coverage matrix |
| **XDR correlation & local LLM** | `oms-xdr`: cross‑source kill‑chain correlation, incident scoring, local LLM triage/narration (Ollama, CPU), dry‑run response (double‑lock) |
| **SOC console & mobile app** | “OMNI SOC” web console (VPN‑only): interactive ATT&CK matrix, attack graph, Entity‑360, real‑time SSE feed, command palette (⌘K), case‑management (status/assignee/notes). Installable mobile **PWA** with web‑push |
| **Self‑explaining alerts** | Each detection carries `alert_explain` + `alert_remediation` (“what happened / what to do”), plus decoded failure cause, EventID, ATT&CK and risk in every notification |
| **UEBA / NDR** | Volume Z‑score, impossible‑travel (Haversine), C2 beaconing (interval CV), DNS‑tunnelling (entropy), internal scan, entity risk scoring 0–100 |
| **Threat intel & leaks** | abuse.ch (Feodo C2 / URLhaus domains), CISA KEV + patch‑age; leak & dark‑web monitoring: RansomLook (ransomware extortion sites), HIBP, Dehashed, GitHub |
| **SOAR & response** | Threat‑feed auto‑block of attacker IPs on FortiGate (no creds, TTL, whitelist, audit); AD account disable via LDAPS (dry‑run + denylist + audit + human‑in‑the‑loop) |
| **Compliance & integrity** | Tiered retention, tamper‑evident HMAC chain (`omni-integrity`), continual‑improvement register (clause 10) + dated audit‑evidence generator, full ISO 27001:2022 mapping |

### Architecture

```
 Endpoints / Servers ──Winlogbeat TLS 5044──┐      GPO OMNI-AUDIT-Baseline (DC 10.33.50.250)
 (Sysmon + audit GPO)                        │      + NETLOGON\SIEM distribution (NinjaOne)
                                             ▼
 FortiGate ─► FortiAnalyzer ──syslog/CEF 1514/5555──►  ┌────────────────────────────┐
                10.33.80.253                           │  bx-it-graylog-vm           │
 Microsoft 365 ──Graph API (pull)──────────────────────│  Nginx TLS :443             │
 vSphere ──────syslog 1516─────────────────────────────│   └─ Graylog 7.1 :9000 (TLS)│
 ESET PROTECT ─syslog 1515─────────────────────────────│       ├─ OpenSearch 2.19    │
 Vaultwarden / Veeam ──Filebeat / channel──────────────│       │   (127.0.0.1:9200)  │
 Admins ───────HTTPS 443───────────────────────────────│       └─ MongoDB 8.0 rs0    │
                                                        └────────────────────────────┘
        │                                                          │
        │   26 Python microservices (/usr/local/sbin/omni-*)       │ GELF :12201
        └──  UEBA · NDR · incident correlation · SOAR · reports ───┘ (event_source=siem_*)
```

### Repository layout

| Path | Contents |
|---|---|
| `00–09*.sh` | Base OS, MongoDB, OpenSearch, Graylog, Nginx/TLS, firewall, inputs, backup, SNMP |
| `10–14*.sh` | Data model, enrichment, pipelines (74 rules), 59 alerts, dashboards |
| `15–22*.sh` | Reports, M365, vSphere, alert hygiene & routing |
| `30–62*.sh` | Resilience, retention/ISO, LDAPS, canary, **SOAR**, **MITRE**, **UEBA/NDR**, vuln scan, incident correlation, integrity, new sources |
| `lib-graylog.sh` | Graylog API helpers (TLS, `wrap_entity`, `ensure_rule`/`ensure_pipeline`, `post_entity`) |
| `windows/` · `fortigate/` | AD audit GPO + agent kit · FortiGate UTM/VPN hardening configs |
| `lookups/` | CSV lookup tables (EventID maps, MITRE, alert explanations, …) |
| `docs/` | ISO 27001 policy/standards/procedures, architecture, DRP, and decision records |
| `00-vars.env.example` · `SECRETS.example.md` | Configuration & secret **templates** (real values never committed) |

### Quick start

```bash
cd omnitech-siem-setup && chmod +x *.sh && chmod 600 00-vars.env
cp 00-vars.env.example 00-vars.env && $EDITOR 00-vars.env   # fill the CHANGEME secrets

./00-preflight.sh --gen-vars   # analyse host: AVX, RAM, disks, network, repos, ports
./01-base.sh ./02-mongodb.sh ./03-opensearch.sh ./04-graylog.sh ./05-nginx-tls.sh
./06-firewall.sh ./07-inputs.sh ./10-graylog-model.sh … ./14-graylog-dashboards.sh
./08-backup.sh                 # then the feature scripts (21, 31, 36, 37, 40, 44, 55, …)
```

Console: `https://bx-it-graylog-vm.omnitech.security/`. Windows/AD side: see `windows/README-WINDOWS.md`.

### Data model

Normalised common schema (`event_id`, `event_source`, `user`, `host`, `src_ip`/`dest_ip` typed as `ip`, `alert_tag`, `mitre_*`, `risk_score`, `failure_reason`, …) across index sets `omni-winsec` / `omni-sysmon` / `omni-winother` / `omni-fortigate` / `omni-m365` / `omni-vsphere`, with tiered retention and daily rotation. GeoIP enrichment runs after the pipeline stage.

### Security & secrets

- **No secret is ever committed.** `.gitignore` excludes `00-vars.env`, `SECRETS.md`, all `*.key`/`*.pem`/`*.cred`/certs. Use the provided `*.example` templates.
- Service secrets live in `00-vars.env` (`chmod 600`); TLS keys, the Mongo keyfile and the Graylog `password_secret` live under `/etc` `/root` with strict permissions (see `SECRETS.example.md`).
- Internal services bind to `127.0.0.1` only (OpenSearch, MongoDB, Graylog API); only Nginx (443) and the configured inputs are exposed, behind nftables and FortiGate rules.

### ISO 27001:2022 alignment

Annex A evidence produced by the platform: **A.8.15/8.16** (logging & monitoring), **A.8.8** (vulnerabilities), **A.5.7** (threat intelligence), **A.8.11** (data masking), **A.5.25/5.26** (incident response), **A.8.13** (backup), **A.5.37 / A.8.32** (operating procedures & change management — this repo), and **Clause 10** (continual improvement). Full policy/standard/procedure set in `docs/`.

### Operations

```bash
source 00-vars.env && source lib-graylog.sh
api_get /system | jq .lifecycle                  # API health
api_get /system/inputstates | jq .               # inputs RUNNING?
curl -s 127.0.0.1:9200/_cat/indices/omni-*?v     # index sizes
journalctl -u graylog-server -f                  # live logs
```

### Stack & versions (pinned)

Debian 13 · Graylog 7.1 · OpenSearch 2.19.x (3.x breaks Graylog) · MongoDB 8.0 · Winlogbeat OSS 8.x. Controlled upgrades only: `apt-mark unhold` → check Graylog matrix → upgrade → re‑hold.

### Status & roadmap

**Production.** **Delivered:** XDR correlation + local LLM triage (`oms-xdr` + Ollama), **ML scoring layer (`oms-ml`: unsupervised anomaly + supervised FP‑reduction)**, **premium SOC web console + mobile PWA** (ML/UEBA scores, free‑text search + CSV export, entity search, Entity‑360 scores, filterable attack graph, KPI trends, collection‑SLA/robot health, toasts, help, keyboard a11y, density), perf cache + offline test suite, threat‑intel (abuse.ch IOC) + leak/dark‑web monitoring, ATT&CK coverage matrix, AD account‑disable actuator (dry‑run), ISO clause‑10 register + dated audit‑evidence generator. **Next:** ESET endpoint isolation + arming the AD response (pending API access / AD delegation), optional cloud‑LLM advisory layer with deterministic tokenisation + Presidio backstop. Co‑managed MDR scoping in `docs/MDR-CO-MANAGE-CHIFFRAGE-2026-06-18.md`.

---

## Français

### Vue d'ensemble

Plateforme SIEM et détection/réponse complète et reproductible, déployée sur une VM Debian durcie, avec un kit d'enrôlement Windows/AD. Elle collecte les journaux Windows Security/Sysmon, FortiGate/FortiAnalyzer, Microsoft 365, vSphere, ESET, Vaultwarden et Veeam ; les normalise dans un schéma commun ; exécute **74 règles de détection** mappées **MITRE ATT&CK** ; ajoute de l'**analyse comportementale (UEBA/NDR)**, la **corrélation d'incidents par kill‑chain**, un **SOAR léger de réponse automatique**, et un **tableau de bord SOC de 19 à 21 pages** — le tout provisionné par des scripts idempotents et documenté pour l'**audit ISO 27001:2022**.

Tout est code. Chaque script est **idempotent** (rejouable sans danger) et s'arrête à la première erreur avec un contrôle final.

### Capacités clés

| Capacité | Rôle |
|---|---|
| **Detection engineering** | 100+ règles pipeline sur 7 streams (AD/Sysmon, FortiGate, FortiManager, M365, vSphere, …) → événements tagués (`alert_tag`) + 100+ définitions d'alerte (mail + Teams), fenêtres tumbling |
| **Mapping MITRE ATT&CK** | 69 `alert_tag` → 48 techniques / 12 tactiques, score de risque 0–10, couche ATT&CK Navigator + matrice de couverture interactive |
| **Corrélation XDR & LLM local** | `oms-xdr` : corrélation kill‑chain multi‑sources, scoring d'incident, triage/narration par LLM local (Ollama, CPU), réponse en dry‑run (double verrou) |
| **Console SOC & app mobile** | Console web « OMNI SOC » (VPN‑only) : matrice ATT&CK interactive, graphe d'attaque, Entité‑360, flux temps réel (SSE), command palette (⌘K), case‑management (statut/assignation/notes). **PWA** mobile installable avec web‑push |
| **Alertes auto‑explicatives** | Chaque détection porte `alert_explain` + `alert_remediation` (« ce qui s'est passé / que faire »), plus la cause décodée de l'échec, l'EventID, ATT&CK et le risque dans chaque notification |
| **UEBA / NDR** | Z‑score de volume, voyage impossible (Haversine), beaconing C2 (CV des intervalles), tunnel DNS (entropie), scan interne, score de risque d'entité 0–100 |
| **Threat intel & fuites** | abuse.ch (C2 Feodo / domaines URLhaus), CISA KEV + ancienneté de patch ; surveillance fuites & dark web : RansomLook (sites d'extorsion ransomware), HIBP, Dehashed, GitHub |
| **SOAR & réponse** | Blocage auto des IP attaquantes sur FortiGate via threat‑feed (sans identifiant, TTL, liste blanche, audit) ; désactivation de compte AD via LDAPS (dry‑run + denylist + audit + human‑in‑the‑loop) |
| **Conformité & intégrité** | Rétention par paliers, chaîne d'intégrité HMAC anti‑altération (`omni-integrity`), registre d'amélioration continue (clause 10) + générateur de preuves daté, mapping ISO 27001:2022 complet |

### Architecture

```
 Postes / Serveurs ───Winlogbeat TLS 5044──┐      GPO OMNI-AUDIT-Baseline (DC 10.33.50.250)
 (Sysmon + audit GPO)                       │      + distribution NETLOGON\SIEM (NinjaOne)
                                            ▼
 FortiGate ─► FortiAnalyzer ──syslog/CEF 1514/5555──►  ┌────────────────────────────┐
                10.33.80.253                           │  bx-it-graylog-vm           │
 Microsoft 365 ──Graph API (pull)──────────────────────│  Nginx TLS :443             │
 vSphere ──────syslog 1516─────────────────────────────│   └─ Graylog 7.1 :9000 (TLS)│
 ESET PROTECT ─syslog 1515─────────────────────────────│       ├─ OpenSearch 2.19    │
 Vaultwarden / Veeam ──Filebeat / canal────────────────│       │   (127.0.0.1:9200)  │
 Admins ───────HTTPS 443───────────────────────────────│       └─ MongoDB 8.0 rs0    │
                                                        └────────────────────────────┘
        │                                                          │
        │   26 microservices Python (/usr/local/sbin/omni-*)       │ GELF :12201
        └──  UEBA · NDR · corrélation incidents · SOAR · rapports ─┘ (event_source=siem_*)
```

### Organisation du dépôt

| Chemin | Contenu |
|---|---|
| `00–09*.sh` | OS de base, MongoDB, OpenSearch, Graylog, Nginx/TLS, pare‑feu, inputs, sauvegarde, SNMP |
| `10–14*.sh` | Modèle de données, enrichissement, pipelines (74 règles), 59 alertes, tableaux de bord |
| `15–22*.sh` | Rapports, M365, vSphere, hygiène & routage des alertes |
| `30–62*.sh` | Résilience, rétention/ISO, LDAPS, canari, **SOAR**, **MITRE**, **UEBA/NDR**, scan de vulnérabilités, corrélation d'incidents, intégrité, nouvelles sources |
| `lib-graylog.sh` | Helpers API Graylog (TLS, `wrap_entity`, `ensure_rule`/`ensure_pipeline`, `post_entity`) |
| `windows/` · `fortigate/` | GPO d'audit AD + kit agent · configs de durcissement UTM/VPN FortiGate |
| `lookups/` | Tables de lookup CSV (EventID, MITRE, explications d'alerte, …) |
| `docs/` | Politique/standards/procédures ISO 27001, architecture, PRA, et notes de décision |
| `00-vars.env.example` · `SECRETS.example.md` | **Gabarits** de configuration & de secrets (valeurs réelles jamais versionnées) |

### Démarrage rapide

```bash
cd omnitech-siem-setup && chmod +x *.sh && chmod 600 00-vars.env
cp 00-vars.env.example 00-vars.env && $EDITOR 00-vars.env   # renseigner les secrets CHANGEME

./00-preflight.sh --gen-vars   # analyse l'hôte : AVX, RAM, disques, réseau, dépôts, ports
./01-base.sh ./02-mongodb.sh ./03-opensearch.sh ./04-graylog.sh ./05-nginx-tls.sh
./06-firewall.sh ./07-inputs.sh ./10-graylog-model.sh … ./14-graylog-dashboards.sh
./08-backup.sh                 # puis les scripts fonctionnels (21, 31, 36, 37, 40, 44, 55, …)
```

Console : `https://bx-it-graylog-vm.omnitech.security/`. Volet Windows/AD : voir `windows/README-WINDOWS.md`.

### Modèle de données

Schéma commun normalisé (`event_id`, `event_source`, `user`, `host`, `src_ip`/`dest_ip` typés `ip`, `alert_tag`, `mitre_*`, `risk_score`, `failure_reason`, …) sur les index sets `omni-winsec` / `omni-sysmon` / `omni-winother` / `omni-fortigate` / `omni-m365` / `omni-vsphere`, rétention par paliers et rotation quotidienne. L'enrichissement GeoIP s'exécute après l'étage pipeline.

### Sécurité & secrets

- **Aucun secret n'est versionné.** Le `.gitignore` exclut `00-vars.env`, `SECRETS.md`, tous les `*.key`/`*.pem`/`*.cred`/certificats. Utiliser les gabarits `*.example`.
- Les secrets de service vivent dans `00-vars.env` (`chmod 600`) ; clés TLS, keyfile Mongo et `password_secret` Graylog résident sous `/etc` `/root` avec des permissions strictes (cf. `SECRETS.example.md`).
- Les services internes n'écoutent qu'en `127.0.0.1` (OpenSearch, MongoDB, API Graylog) ; seuls Nginx (443) et les inputs configurés sont exposés, derrière nftables et les règles FortiGate.

### Alignement ISO 27001:2022

Preuves Annexe A produites par la plateforme : **A.8.15/8.16** (journalisation & surveillance), **A.8.8** (vulnérabilités), **A.5.7** (renseignement sur les menaces), **A.8.11** (masquage), **A.5.25/5.26** (réponse à incident), **A.8.13** (sauvegarde), **A.5.37 / A.8.32** (procédures d'exploitation & gestion du changement — ce dépôt), et **Clause 10** (amélioration continue). Dossier politique/standard/procédure complet dans `docs/`.

### Exploitation courante

```bash
source 00-vars.env && source lib-graylog.sh
api_get /system | jq .lifecycle                  # santé API
api_get /system/inputstates | jq .               # inputs RUNNING ?
curl -s 127.0.0.1:9200/_cat/indices/omni-*?v     # taille des index
journalctl -u graylog-server -f                  # logs en direct
```

### Stack & versions (gelées)

Debian 13 · Graylog 7.1 · OpenSearch 2.19.x (la 3.x casse Graylog) · MongoDB 8.0 · Winlogbeat OSS 8.x. Mises à jour contrôlées uniquement : `apt-mark unhold` → vérifier la matrice Graylog → upgrade → re‑hold.

### État & feuille de route

**Production.** **Livré :** corrélation XDR + triage LLM local (`oms-xdr` + Ollama), **couche de scoring ML (`oms-ml` : anomalie non‑supervisée + réduction de FP supervisée)**, **console web SOC premium + PWA mobile** (scores ML/UEBA, recherche libre + export CSV, recherche d'entité, Entité‑360 scorée, graphe d'attaque filtrable, tendances KPI, SLA de collecte/santé des robots, toasts, aide, accessibilité clavier, densité), cache de performance + suite de tests hors‑ligne, threat‑intel (IOC abuse.ch) + surveillance fuites/dark web, matrice de couverture ATT&CK, actionneur de désactivation de compte AD (dry‑run), registre clause 10 + générateur de preuves d'audit daté. **À venir :** isolation d'endpoint ESET + armement de la réponse AD (en attente des accès API / délégation AD), couche LLM cloud optionnelle (conseil) avec tokenisation déterministe + filet Presidio. Chiffrage du MDR co‑managé dans `docs/MDR-CO-MANAGE-CHIFFRAGE-2026-06-18.md`.

---

<div align="center">
<sub>OMNITECH SECURITY — internal SIEM platform. Provisioned by idempotent scripts. Secrets excluded by design.</sub>
</div>
