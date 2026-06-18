# OMS-XDR — Couche XDR de corrélation/réponse au-dessus de Graylog

Surcouche qui transforme le Graylog d'OMNITECH (10.33.220.10) en plateforme
de **détection corrélée + remédiation guidée + réponse**, sur le modèle
fonctionnel d'un MXDR du marché, sans dépendance à un SOC externe.

> ⚠️ **État intégré (18/06/2026) — voir [`docs/INTEGRATION-OMNITECH.md`](docs/INTEGRATION-OMNITECH.md).**
> Le déploiement réel sur la VM SIEM diffère du design d'origine décrit plus bas :
> **lecture via OpenSearch local** (pas l'API REST), **réinjection GELF HTTP 12201**
> (input existant, pas un 12222 dédié), **LLM `qwen2.5:3b` local**, **blocage FortiGate
> délégué au feed `omni-soar`** (pas d'API FortiOS directe). Token Graylog non requis.

---

## 1. Ce que fait Bitdefender MXDR — et comment on le reproduit

Bitdefender MXDR = bundle **GravityZone Defense XDR** (capteurs endpoint /
identité / réseau / productivité) + service **MDR** (SOC 24/7, *Pre-approved
Actions*). Le moteur de corrélation et de réinjection repose d'ailleurs sur
**Streams & Pipelines** — la terminologie Graylog : reproduire ces fonctions
sur ton SIEM est donc parfaitement aligné.

| Capacité MXDR | Équivalent OMS-XDR (auto-hébergé) | État |
|---|---|---|
| Capteurs multi-domaines (endpoint, réseau, identité, productivité) | FortiAnalyzer→Graylog (réseau/FW), Winlogbeat (Windows/identité), Sysmon (planifié), ESET EDR, FortiClient, + **netscan** (découverte réseau) | Existant + ajout netscan |
| Corrélation cross-domaine → incidents | `correlation.py` + `rules.yaml` (signaux atomiques → chaînes d'attaque par entité) | **Livré** |
| Mapping MITRE ATT&CK | techniques/tactiques portées par chaque règle | **Livré** |
| Network Attack Defense (scan, brute force, latéral) | signaux FortiGate IPS + `netscan` (delta de ports) | **Livré** |
| Threat intel / enrichissement | lookup tables Graylog (abuse.ch/OTX/MISP) à brancher | À brancher |
| Détection comportementale / anomalies | seuils par entité aujourd'hui ; anomalies stats à ajouter | Partiel |
| Triage analyste / lisibilité (résumé IA) | `enrich.py` via **Ollama/Mistral 7B** (narration FR) | **Livré** |
| Remédiation guidée | `remediation.py` (playbooks par technique, spécifiques OMNITECH) | **Livré** |
| Pre-approved Actions (isoler hôte, neutraliser compte) | `responder.py` (FortiGate / AD / NinjaOne) — **dry-run par défaut** | **Livré** |
| SOC 24/7 humain | non reproductible en interne — compensé par notification Teams + timers | N/A |
| Reporting | dashboards Graylog sur le stream « OMS-XDR Incidents » | À construire |

Différence assumée : pas d'analystes humains 24/7. La valeur reproductible est
la **corrélation + l'enrichissement + la remédiation outillée**, sous contrôle RSSI.

---

## 2. Architecture

```
 Sources                Graylog (SIEM)            OMS-XDR (cette couche)
 ───────                ──────────────            ──────────────────────
 FortiAnalyzer ─CEF1514─┐
 Winlogbeat   ─────────►│  streams + pipelines ──► correlation.py (signaux→règles)
 Sysmon/NinjaOne ──────►│                              │
 oms-netscan ──GELF────►│                              ├─► enrich.py (Ollama)
                        │                              ├─► remediation.py (playbooks)
                        │◄──── GELF 12222 ─────────────┤   responder.py (FGT/AD/Ninja)
                        │   stream "OMS-XDR Incidents"  └─► Teams (Power Automate)
```

Choix d'architecture : **pas de plugin Java Graylog**. L'API plugin 6.x est
instable entre versions et ne permet ni l'orchestration de réponse ni
l'appel LLM. Une couche externe découplée (interrogation REST + réinjection
GELF) est plus robuste, versionnable et testable — et survit aux montées de
version Graylog.

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

Renseigner `/etc/oms-xdr/oms-xdr.env` (idéalement injection depuis Vaultwarden).
Le token Graylog s'utilise en Basic `token:token`.

```bash
# Provisionner l'input GELF + le stream incidents
export OMS_GRAYLOG_TOKEN=********
bash deploy/setup_graylog.sh        # reporter les stream IDs dans config.yaml
```

Activer les timers :

```bash
sudo cp deploy/*.service deploy/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now oms-xdr.timer oms-netscan-quick.timer oms-netscan-full.timer
```

Test manuel :

```bash
sudo -u oms-xdr OMS_GRAYLOG_TOKEN=$OMS_GRAYLOG_TOKEN \
  /opt/oms-xdr/.venv/bin/python -m oms_xdr.engine --once --config /etc/oms-xdr/config.yaml
```

---

## 4. Sécurité de la réponse automatique

`response.dry_run: true` par défaut : **aucune** action sur l'infra. Les actions
sont seulement journalisées comme recommandations et écrites dans l'incident.
Pour activer le containment réel, basculer `dry_run: false` **et** le flag
`auto_*` ciblé. Recommandation : démarrer en dry-run 2–3 semaines, valider le
taux de faux positifs sur le stream incidents, puis activer sélectivement
`auto_block_fortigate` avant les actions AD/endpoint.

---

## 5. Périmètre de scan — cadrage légal/ISO

`netscan` ne balaie que les réseaux **internes OMNITECH** déclarés dans
`netscan.targets`. À aligner sur le plan d'adressage réel (Oméga/Ivry/Lançon)
et à tracer dans le SMSI (REG_016) comme activité de découverte d'actifs
(rattachable A.5.9 inventaire, A.8.8 gestion des vulnérabilités).

---

## 6. Roadmap

1. **Threat intel** : lookup tables Graylog (abuse.ch, OTX) → signal `S_C2_IOC`.
2. **Sysmon** : déploiement NinjaOne → signaux process/réseau fins (T1055, T1003).
3. **Anomalies** : baseline EWMA par entité (volumes 4625/flux) au lieu de seuils fixes.
4. **Vuln correlation** : croiser netscan ↔ POL_018 (matrice CVSS) pour prioriser.
5. **Dashboard** « OMS-XDR Incidents » + rapport hebdo planifié.
6. **Runbooks AD signés** (WinRM/NinjaOne) pour `disable_ad_account`/`force_pwd_reset`.
```
