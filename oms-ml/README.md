# OMS-ML — the learning layer (ML scoring) of the OMNITECH SIEM

Learns from the data already collected by the SIEM and **reinjects an `ml_score`**
into Graylog. Local-first: `scikit-learn` on CPU, reads from OpenSearch, writes via
the existing GELF input. Complements — without duplicating — the statistical UEBA
(`40-ueba-ndr`) and `oms-xdr` (correlation + LLM).

## Two models

| | Anomaly (unsupervised) | FP reduction (supervised) |
|---|---|---|
| Model | IsolationForest (log1p + StandardScaler) | GradientBoosting |
| Label | **none** — trainable right away | analyst disposition of SOC cases (TP/FP) |
| Entity | host (`source`), account (`TargetUserName`) | individual alert |
| Output | `ml_score` 0-100 + `ml_reason` per entity | "false positive" probability per alert |
| Cadence | hourly (`oms-ml-anomaly.timer`) | daily retraining |

### Features per entity (anomaly)
A single OpenSearch `terms` query + sub-aggregations over the window (7 d):
`ev_total, ev_detections, n_alert_tags, n_techniques, risk_max, risk_sum,
n_src_ip, n_countries, n_event_sources, n_peers`.
`log1p` before scaling: otherwise a large emitter (firewall) overwhelms the population and
always comes out "abnormal". We score the anomaly of **shape**, not mere size.

### Explainability
For each abnormal entity, we surface the 3 features that deviate the most from
the population mean (z-score) → `ml_reason` readable by the analyst. No
black box: essential in the SOC and for the ISO audit.

## Usage
```bash
# Compute + display only (no write to the SIEM)
python -m oms_ml.run anomaly --entity all --window 7d --top 15
# GELF reinjection (event_source=ml_anomaly, additive, non-destructive)
python -m oms_ml.run anomaly --entity all --push
# State of supervised labels / FP (re)training
python -m oms_ml.run status
python -m oms_ml.run fp --train
```

## Deployment
`sudo ./77-ml-scoring.sh`: venv + `/etc/oms-ml/config.yaml` + systemd timers +
routing `ml_anomaly` → stream "OMNI - Interne SIEM" (like the UEBA).

## v2 — segmentation by asset class
To prevent a large emitter (a firewall with 70 M events) from overwhelming the
population and always coming out "abnormal", the anomaly of **hosts** is computed
**per asset class** (dominant `event_source` = firewall / Windows server /
hypervisor / cloud…): one IsolationForest per class, the small classes
grouped as "other". This way we compare a firewall to other firewalls.
Moreover, the score is **dampened by the actual magnitude** of the deviation (z-max) and
not by mere rank — an entity "within the norm" no longer gets 100 by
min-max. Enabled by `segment: true` (see `config.yaml`).

## Acknowledged limitations (senior honesty)
- **Temporal baseline**: v2 segments by class; a later evolution
  would also compare each entity to **its own past** (individual drift).
- **Supervised FP = needs labels**: as long as analysts have not qualified
  enough cases (TP/FP) in the console, the model self-skips and flags it.
  → the TP/FP disposition at case closure is the fuel of the model.
- **Class imbalance**: real attacks are rare; we monitor
  the AUC in cross-validation and do not over-interpret a small sample.
- The `ml_score` is a **prioritization aid**, not a verdict: it adds
  to the UEBA risk and the oms-xdr correlation, it does not replace them.
