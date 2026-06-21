# Console SOC « OMNI SOC » — Guide

Console web + PWA mobile pour le pilotage du SIEM/XDR OMNITECH. **VPN-only**,
authentification AD (déléguée à Graylog/LDAPS). Construite sur le backend
`omni-mobile-api` (lecture OpenSearch, stdlib + pywebpush) servi par nginx.
Interface premium (glassmorphism, glow, micro-interactions), accessible au clavier.

## Accès
- **Console desktop** : `https://bx-it-graylog-vm.omnitech.security/soc/`
- **App mobile (PWA)** : `https://bx-it-graylog-vm.omnitech.security/m/` → *Partager → Sur l'écran d'accueil* (installable, web-push).
- Connexion : **compte AD** (les mêmes identifiants que la console Graylog).
- Raccourcis : **Ctrl/Cmd + K** = palette (navigation + **recherche d'entité**) ; **?** = aide & raccourcis ; **Échap** = fermer ; **Entrée/Espace** = activer l'élément ciblé.

## Pages (desktop)
| Page | Contenu |
|---|---|
| **Vue d'ensemble** | KPI **avec tendance** (▲/▼ % vs période précédente), courbe détections 24 h, donut tactiques ATT&CK, top détections/sources, **Anomalies ML** + **Risque UEBA** (vrais scores), flux temps réel (SSE), origines géographiques |
| **Incidents** | File de **cas** (oms-xdr) : statut, assignation, notes ; **disposition Vrai/Faux positif** → alimente le modèle ML de réduction de FP |
| **Détections** | Liste **filtrable** (tactique/source) + **recherche libre** + **export CSV** ; sévérité réelle (`risk_severity`) + score de risque ; clic → Entité-360 |
| **Matrice ATT&CK** | Heatmap tactiques × techniques, colorée par activité réelle (7 j), cellules cliquables (drill) |
| **Graphe d'attaque** | Graphe entités ↔ techniques **filtrable** (tactique, seuil de volume, centrage d'entité) |
| **Fuites & Dark Web** | Synthèse par catégorie (extorsion/identifiants/GitHub), RansomLook/HIBP/Dehashed, état « aucune fuite » rassurant |
| **Santé & Collecte** | État cluster, **robots d'auto-supervision** (X/Y), **couverture de collecte (SLA)** + **hôtes go-dark**, fraîcheur par source |
| **Rapport** | Synthèse exécutive imprimable (PDF) : KPI, couverture, **posture opérationnelle (robots/SLA)**, **entités à risque ML & UEBA**, incidents, sources |
| **Entité-360** (volet) | Fiche d'une entité : **score ML + score UEBA**, tactiques, techniques ATT&CK, événements récents (pagination « charger plus ») |

## Couche ML (oms-ml)
La console surface les scores du paquet **`oms-ml`** (sklearn local, cf. `oms-ml/README.md`) :
- **Anomalie non-supervisée** (IsolationForest) par entité → `ml_score` réinjecté en GELF (`event_source=ml_anomaly`), visible sur la Vue d'ensemble et l'Entité-360.
- **Réduction de faux positifs supervisée** : entraînée à partir de la **disposition VP/FP** posée par les analystes à la clôture des cas (boucle fermée).
- Les événements internes (`ueba_score`, `collecte_sla`, `siem_health`, `xdr_incident`, `ml_anomaly`) sont écrits dans l'index set **`omni-interne`** (cf. `79-interne-indexset.sh`) — sans quoi la console (qui lit `omni-*`) ne les verrait pas.

## Ergonomie & UX
- **Toasts** : retour non bloquant sur les actions (cas qualifié, export, session expirée, erreur réseau).
- **Aide (?)** : raccourcis clavier, rôle de chaque page, glossaire des signaux (ML, UEBA, sévérité, go-dark, KEV).
- **Densité** : bascule confortable/compact (persistée).
- **Chargement** : squelettes au premier affichage, pastille « Mis à jour il y a Xs », **cadence de rafraîchissement** réglable (30 s / 60 s / pause).
- **Accessibilité** : navigation et modales opérables au clavier (focus visible, focus-trap, ARIA).

## PWA mobile
Onglets **Synthèse** (KPI, courbe, tactiques), **Alertes**, **Incidents**, et **Menace** —
parité console : niveau de menace + KPI, **anomalies ML & risque UEBA** (jauges), détections à sévérité colorée. Installable, web-push.

## Architecture
```
Navigateur (VPN) → nginx 443 → /soc/ (statique) + /m/ (PWA) + /m/api/* (proxy → omni-mobile-api 127.0.0.1:8090)
omni-mobile-api : auth Graylog (LDAPS) → cookie HMAC ; lecture OpenSearch ; SSE ; web-push VAPID
```
- **Endpoints** `/m/api/` : login, me, kpis, **kpi-trend**, timeseries, by-tactic, top-detections, top-sources,
  alerts, cases (+POST case avec `disposition`), detections, **entity-search**, entity (size/from + scores), attack-matrix,
  graph, **leaks2**, health, report, geo, risk, stream (SSE), vapid/subscribe (push).
- **Performance** : micro-cache mémoire à TTL (30 s, `MOBILE_CACHE_TTL`) sur les agrégations lourdes
  (attack-matrix, report, kpis, health, geo, terms) — matrice ATT&CK ~783→7 ms, rapport ~811→3 ms.
- **Sécurité** : VPN-only, cookie HttpOnly+Secure+SameSite=Strict, rate-limit login (5/15 min),
  en-têtes CSP/HSTS/X-Frame-Options (`75-console-hardening.sh`).
- **Mode rédaction** (`MOBILE_REDACT=1`) : pseudonymise comptes/hôtes/IP/SID de façon cohérente
  (carte réversible pour l'Entité-360) — sert à produire des captures anonymisées. **Désactivé en exploitation.**

## Exploitation
- Backend : `systemctl status omni-mobile-api` ; conf `/etc/default/omni-mobile`.
- Déploiement / mise à jour : `65-mobile-pwa.sh` (PWA + backend), `71-soc-console.sh` (console).
- Bibliothèques front vendorées localement (`chart.min.js`, `cytoscape.min.js`) — aucun CDN au runtime.
- **Tests** (hors-ligne, sans OpenSearch) : `./run-tests.sh` — rédaction (`_rd`/`_scrub`) + oms-ml (anomalie, gating FP) ; 23 tests.
