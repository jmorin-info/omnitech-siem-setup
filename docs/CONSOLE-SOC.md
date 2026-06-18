# Console SOC « OMNI SOC » — Guide

Console web + PWA mobile pour le pilotage du SIEM/XDR OMNITECH. **VPN-only**,
authentification AD (déléguée à Graylog/LDAPS). Construite sur le backend
`omni-mobile-api` (lecture OpenSearch, stdlib + pywebpush) servi par nginx.

## Accès
- **Console desktop** : `https://bx-it-graylog-vm.omnitech.security/soc/`
- **App mobile (PWA)** : `https://bx-it-graylog-vm.omnitech.security/m/` → *Partager → Sur l'écran d'accueil* (installable, web-push).
- Connexion : **compte AD** (les mêmes identifiants que la console Graylog).
- Raccourci : **Ctrl/Cmd + K** = palette de commandes (navigation).

## Pages
| Page | Contenu |
|---|---|
| **Vue d'ensemble** | KPI (incidents critiques, hôtes à risque, détections, KEV), courbe détections 24 h, donut tactiques ATT&CK, top détections, sources, **flux temps réel (SSE)** |
| **Incidents** | File de **cas** (oms-xdr) : statut (Nouveau/En cours/Clos), assignation, **notes d'investigation** persistées, analyse LLM + remédiation |
| **Détections** | Liste **filtrable** (tactique / source) des détections 24 h ; clic → fiche Entité-360 |
| **Matrice ATT&CK** | Heatmap tactiques × techniques, colorée par activité réelle (7 j) |
| **Graphe d'attaque** | Graphe entités ↔ techniques (taille = volume, couleur = tactique) ; clic entité → **Entité-360** |
| **Fuites & Dark Web** | RansomLook (extorsion ransomware), HIBP, Dehashed, GitHub |
| **Santé & Collecte** | État cluster, volume 24 h, fraîcheur par source (détecte une source qui décroche) |
| **Rapport** | Synthèse exécutive imprimable (**PDF en un clic**) — KPI, couverture, incidents, sources |

## Architecture
```
Navigateur (VPN) → nginx 443 → /soc/ (statique) + /m/api/* (proxy → omni-mobile-api 127.0.0.1:8090)
omni-mobile-api : auth Graylog (LDAPS) → cookie HMAC ; lecture OpenSearch ; SSE ; web-push VAPID
```
- **Endpoints** : `/m/api/` → login, me, kpis, timeseries, by-tactic, top-detections, top-sources,
  alerts, cases (+POST case), detections, attack-matrix, graph, entity, leaks, health, report, stream (SSE), vapid/subscribe (push).
- **Sécurité** : VPN-only, cookie HttpOnly+Secure+SameSite=Strict, rate-limit login (5/15 min),
  en-têtes CSP/HSTS/X-Frame-Options (`75-console-hardening.sh`).

## Exploitation
- Backend : `systemctl status omni-mobile-api` ; conf `/etc/default/omni-mobile`.
- Déploiement / mise à jour : `65-mobile-pwa.sh` (PWA + backend), `71-soc-console.sh` (console).
- Bibliothèques front vendorées localement (`chart.min.js`, `cytoscape.min.js`) — aucun CDN au runtime.
