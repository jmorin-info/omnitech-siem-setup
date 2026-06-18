# SOAR — Playbooks de réponse automatisée (OMNITECH SIEM)

> Cadrage du chantier « SOAR avancé » · 2026-06-14
> État : PB-01 en production. PB-02→05 **conçus, en attente de l'API NinjaOne**
> (accès à activer côté tenant, compte Owner — l'intégration se fera dès réception).

## Architecture (existant)
Service `omni-soar` (`/usr/local/sbin/omni-soar`) : HTTP local `127.0.0.1:8088`.
Une notification Graylog HTTP POST → action → garde-fous → état → effet.
- État : `/var/lib/omni-soar/blocklist.json`. Effet : `/var/www/siem-kit/soar/blocklist.txt` (threat feed servi par nginx, consommé par le FortiGate).
- **Garde-fous déjà en place (à conserver pour TOUT nouveau playbook) :** jamais d'IP RFC1918 / loopback / link-local / réservée, jamais la **whitelist**, seuil de hits, **cap** (taille max), **TTL** (expiration auto). Toute action est tracée en GELF (`event_source:siem_soar`).

## Catalogue des playbooks

| # | Playbook | Déclencheur (alert_tag) | Action | Dépendance | Statut |
|---|---|---|---|---|---|
| **PB-01** | Bloquer IP attaquante | Force brute VPN, password spraying | Ajout au threat feed FortiGate (TTL) | FortiGate (fait) | ✅ **PROD** |
| **PB-02** | Isoler un hôte compromis | `ransomware_indicator`, `lsass_access`, `lateral_movement` (confirmé) | NinjaOne : isolation réseau du device | **API NinjaOne** | 🟡 conçu |
| **PB-03** | Désactiver un compte | `canary`, `impossible_travel`, `dcsync` (confirmé) | Désactivation compte AD (script NinjaOne sur DC, ou LDAP) | **API NinjaOne** (ou LDAPS) | 🟡 conçu |
| **PB-04** | Ouvrir un ticket | Toute alerte P3 (mail tier) | Création d'un incident avec contexte (identité, hôte, MITRE) | **API ticketing NinjaOne** | 🟡 conçu |
| **PB-05** | Enrichir IOC | `threat_intel`, IP/domaine externes | Enrichissement TI + retro-hunt | MISP/feed (optionnel) | 🟡 conçu |

## Conception détaillée (PB-02 → PB-04)
Chaque playbook = un nouvel endpoint du service `omni-soar` (`/isolate`, `/disable`, `/ticket`), appelé par une notification Graylog dédiée, avec les **mêmes garde-fous renforcés** :

- **PB-02 Isoler hôte** — `POST /isolate {host}`.
  - Garde-fous CRITIQUES : **jamais** un contrôleur de domaine, le SIEM, l'hyperviseur, un serveur d'infra (whitelist de **rôles d'hôte** à définir) ; `risk_score >= 12` requis ; **réversible** (dé-isolation auto après TTL ou manuelle) ; option **confirmation manuelle** (tier « propose, n'exécute pas » pour les actions destructrices).
  - NinjaOne : endpoint *device isolation* (API `https://eu.ninjarmm.com/api/v2/...`, scope *management*).
- **PB-03 Désactiver compte** — `POST /disable {identity}` (s'appuie sur le champ **`identity`** unifié posé par `58`).
  - Garde-fous : **jamais** un compte *break-glass*/service/admin critique (whitelist de comptes) ; réversible (réactivation tracée) ; journalisé.
  - Mécanisme : script NinjaOne `Disable-ADAccount` sur un DC, ou bind LDAPS dédié (compte de service à privilèges minimaux : *Account Operators* restreint).
- **PB-04 Ticket** — `POST /ticket {event}` → ticket pré-rempli (titre = alerte, corps = identité + hôte + technique MITRE + lien Graylog). Sert de file d'incidents (pallie l'absence de case-management en OSS).

## Prérequis côté client (à fournir avant intégration)
1. 🔑 **API NinjaOne** : `client_id` + `client_secret` (OAuth2), scopes *management* (PB-02/03) et *ticketing* (PB-04). Région EU (`eu.ninjarmm.com`). → stocker dans `00-vars.env` (chmod 600) façon `FORTI_DHCP_TOKEN`.
2. **Whitelist de rôles d'hôte** à ne JAMAIS isoler (DC, SIEM, hyperviseurs, NAS, cœur réseau).
3. **Whitelist de comptes** à ne JAMAIS désactiver (break-glass, comptes de service critiques).

## Validation (avant mise en prod de chaque playbook)
Mode **dry-run** d'abord (`SOAR_DRYRUN=1` : le service logge l'action sans l'exécuter), sur un hôte/compte de TEST, puis bascule. Tester explicitement qu'une cible whitelistée / RFC1918 est **refusée**. Tenir un journal des déclenchements (utile ISO A.5.25/5.26).

> Dès que l'API NinjaOne est disponible : implémentation des endpoints `/isolate`, `/disable`, `/ticket` dans `omni-soar` + notifications + garde-fous, en dry-run puis prod.
