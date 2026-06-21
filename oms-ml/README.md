# OMS-ML — couche d'apprentissage (scoring ML) du SIEM OMNITECH

Apprend sur les données déjà collectées par le SIEM et **réinjecte un `ml_score`**
dans Graylog. Local-first : `scikit-learn` CPU, lecture OpenSearch, écriture via
l'input GELF existant. Complète — sans dupliquer — l'UEBA statistique
(`40-ueba-ndr`) et `oms-xdr` (corrélation + LLM).

## Deux modèles

| | Anomalie (non-supervisé) | Réduction de FP (supervisé) |
|---|---|---|
| Modèle | IsolationForest (log1p + StandardScaler) | GradientBoosting |
| Label | **aucun** — entraînable tout de suite | disposition analyste des cas SOC (VP/FP) |
| Entité | hôte (`source`), compte (`TargetUserName`) | alerte individuelle |
| Sortie | `ml_score` 0-100 + `ml_reason` par entité | probabilité « faux positif » par alerte |
| Cadence | horaire (`oms-ml-anomaly.timer`) | ré-entraînement quotidien |

### Features par entité (anomalie)
Une seule requête OpenSearch `terms` + sous-agrégations sur la fenêtre (7 j) :
`ev_total, ev_detections, n_alert_tags, n_techniques, risk_max, risk_sum,
n_src_ip, n_countries, n_event_sources, n_peers`.
`log1p` avant scaling : sinon un gros émetteur (pare-feu) écrase la population et
sort toujours « anormal ». On score l'anomalie de **forme**, pas la simple taille.

### Explicabilité
Pour chaque entité anormale, on remonte les 3 features qui s'écartent le plus de
la moyenne de population (z-score) → `ml_reason` lisible par l'analyste. Pas de
boîte noire : indispensable en SOC et pour l'audit ISO.

## Usage
```bash
# Calcul + affichage seul (aucune écriture dans le SIEM)
python -m oms_ml.run anomaly --entity all --window 7d --top 15
# Réinjection GELF (event_source=ml_anomaly, additif, non destructif)
python -m oms_ml.run anomaly --entity all --push
# État des labels supervisés / (ré)entraînement FP
python -m oms_ml.run status
python -m oms_ml.run fp --train
```

## Déploiement
`sudo ./77-ml-scoring.sh` : venv + `/etc/oms-ml/config.yaml` + timers systemd +
routage `ml_anomaly` → stream « OMNI - Interne SIEM » (comme l'UEBA).

## v2 — segmentation par classe d'actif
Pour éviter qu'un gros émetteur (un pare-feu à 70 M d'événements) écrase la
population et sorte toujours « anormal », l'anomalie des **hôtes** est calculée
**par classe d'actif** (`event_source` dominant = pare-feu / serveur Windows /
hyperviseur / cloud…) : un IsolationForest par classe, les petites classes
regroupées en « autres ». On compare ainsi un pare-feu à d'autres pare-feux.
De plus, le score est **amorti par l'ampleur réelle** de la déviation (z-max) et
non par le simple rang — une entité « dans la norme » n'obtient plus 100 par
min-max. Activé par `segment: true` (cf. `config.yaml`).

## Limites assumées (honnêteté senior)
- **Baseline temporelle** : la v2 segmente par classe ; une évolution ultérieure
  comparerait aussi chaque entité à **son propre passé** (dérive individuelle).
- **FP supervisé = besoin de labels** : tant que les analystes n'ont pas qualifié
  assez de cas (VP/FP) dans la console, le modèle s'auto-saute et le signale.
  → la disposition VP/FP à la clôture des cas est le carburant du modèle.
- **Déséquilibre de classes** : les vraies attaques sont rares ; on surveille
  l'AUC en validation croisée et on ne sur-interprète pas un petit échantillon.
- Le `ml_score` est une **aide à la priorisation**, pas un verdict : il s'ajoute
  au risque UEBA et à la corrélation oms-xdr, il ne les remplace pas.
