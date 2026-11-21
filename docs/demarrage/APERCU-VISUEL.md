# Aperçu visuel

Captures de la console SOC, de la PWA et des tableaux de bord Graylog de
l'installation de référence. La vue d'ensemble et les incidents utilisent des
**données synthétiques** ; les autres captures présentent l'installation
historique, avec comptes, hôtes, adresses IP et SID **pseudonymisés**
(mode `MOBILE_REDACT`). Certaines captures montrent une interface antérieure
à la version actuelle de la console.

Retour à [l'index de la documentation](../README.md).

## Console SOC « OMNI SOC »

<div align="center">

| | |
|:---:|:---:|
| [![Recherche d'entités](../captures/02-entites.png)](../captures/02-entites.png)<br>**Entités** — classées par risque fusionné + watchlist | [![Dossier 360](../captures/10-dossier360.png)](../captures/10-dossier360.png)<br>**Dossier 360** — jauge de risque fusionné, identité unifiée, provenance |
| [![Chronologie unifiée](../captures/10b-timeline.png)](../captures/10b-timeline.png)<br>**Chronologie unifiée** — détections + authentifications, par date | [![Détections](../captures/04-detections.png)](../captures/04-detections.png)<br>**Détections** — liste 24 h + guide d'action intégré |
| [![Playbooks](../captures/05-playbooks.png)](../captures/05-playbooks.png)<br>**Playbooks** — ce que c'est / vérifier / remédier / corriger | [![Matrice ATT&CK](../captures/06-attack.png)](../captures/06-attack.png)<br>**Matrice MITRE ATT&CK** — couverture et activité |
| [![Graphe d'attaque](../captures/07-graphe.png)](../captures/07-graphe.png)<br>**Graphe d'attaque** — entités et techniques | [![Incidents](../captures/03-incidents.png)](../captures/03-incidents.png)<br>**Incidents** — cas corrélés (oms-xdr) |
| [![Santé et collecte](../captures/08-sante.png)](../captures/08-sante.png)<br>**Santé et collecte** — cluster, SLA, santé des robots | [![Fuites et Dark Web](../captures/09-fuites.png)](../captures/09-fuites.png)<br>**Fuites et Dark Web** — RansomLook / HIBP / Dehashed / GitHub |

[![Interface bilingue](../captures/11-overview-en.png)](../captures/11-overview-en.png)

**Interface bilingue FR/EN** — bascule instantanée et persistée.

</div>

## PWA mobile — application installable, notifications web-push

<div align="center">

| | |
|:---:|:---:|
| [![PWA Menace](../captures/12-pwa-mobile.png)](../captures/12-pwa-mobile.png)<br>**Menace** — parité console (ML / UEBA) | [![PWA Guides](../captures/13-pwa-guides.png)](../captures/13-pwa-guides.png)<br>**Guides** — playbooks par tactique |

</div>

## Tableaux de bord Graylog

<div align="center"><img src="../captures/graylog/graylog-01-soc.png" alt="Graylog : tableau de bord OMNI - SOC" width="90%"></div>

*`OMNI - SOC` : vue d'ensemble de la sécurité.*

<div align="center"><img src="../captures/graylog/graylog-02-analytics.png" alt="Graylog : tableau de bord OMNI - Analytics" width="90%"></div>

*`OMNI - Analytics` : couverture de collecte, télémétrie des robots, anomalies ML et UEBA, voyages impossibles.*

| | |
|---|---|
| ![Triage et multi-site](../captures/graylog/graylog-03-triage-multisite.png) | ![Sources](../captures/graylog/graylog-04-sources.png) |
| `OMNI - Triage & Multi-site` : courriels envoyés ou écartés, FortiGate par site | `Sources` : volume ingéré par source |
| ![SEAL SOC](../captures/graylog/graylog-05-seal-soc.png) | ![SEAL multi-site](../captures/graylog/graylog-06-seal-multisite.png) |
| `SEAL - SOC opérationnel` : accès physiques en temps réel | `SEAL - Vue multi-site` : accès par site |
| ![Inputs](../captures/graylog/graylog-07-inputs.png) | ![Pipelines](../captures/graylog/graylog-08-pipelines.png) |
| Inputs de collecte (Beats, Syslog, GELF) | Pipelines de traitement |
