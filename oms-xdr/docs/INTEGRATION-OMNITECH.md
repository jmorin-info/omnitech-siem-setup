# Intégration OMS-XDR ↔ SIEM OMNITECH existant

**18/06/2026.** oms-xdr ne tourne **pas** en parallèle du SIEM : il se greffe dessus comme
couche **corrélation + LLM + réponse**, en consommant les détections déjà produites.

## 1. Cartographie module → existant

| Module oms-xdr | Statut intégration | Décision |
|---|---|---|
| `correlation.py` + `rules.yaml` | **Recâblé** sur `alert_tag` + champs normalisés (`event_id`/`src_ip`/`user`/`host`) et vrais stream IDs | Consomme les détections ; chevauche `omni-incident-correlate` → **à arbitrer** (cf. §3) |
| `enrich.py` (Ollama/Mistral) | **Net-new** — c'est le triage LLM local validé (« local d'abord ») | Garder ; Ollama interne 10.33.120.55 |
| `remediation.py` (playbooks) | **Net-new** structuré par scénario ; complète la lookup `alert-explain` (par tag) | Garder les deux (tag-level vs scénario-level) |
| `responder.py` (FGT/AD/Ninja) | **= les actionneurs de réponse** ; dry-run double-verrou | FGT : **déléguer au feed `omni-soar`** (pas d'écriture directe FortiOS) ; AD/Ninja = net-new |
| `netscan.py` (nmap actif) | **Désactivé** (`enabled:false`) | Décision KEV + passif d'abord |
| `graylog_client.send_gelf` | **Recâblé** sur l'input GELF HTTP 12201 existant (plus de 12222) | Réutilise le bus ; incidents tagués `event_source=xdr_incident` |

## 2. Ce qui a été fait (ce commit)

- `rules.yaml` : 11 signaux recâblés sur le schéma réel (alert_tag/normalisé), 6 règles inchangées.
- `config.yaml` : stream IDs réels (FortiGate/Windows/Sysmon/Interne), GELF → 127.0.0.1:12201 (HTTP), `netscan.enabled:false`, réponse en dry-run.
- `graylog_client.py` : envoi GELF **HTTP** (réutilise l'input existant) en plus du TCP.
- `correlation.py` : incidents marqués `_event_source=xdr_incident` (routage/dashboard comme les autres `event_source=siem_*`).

## 3. Reste à intégrer (ordre conseillé)

1. **Valider en dry-run** : `python -m oms_xdr.engine --once` en lecture seule → vérifier les incidents produits et **les noms de champs FortiGate** (`subtype`/`status`) sur données réelles.
2. **Router les incidents** : règle de stream sur `event_source:xdr_incident` → page dashboard « OMS-XDR Incidents » (ou fusion dans « Interne SIEM »).
3. **Responder FortiGate → `omni-soar`** : remplacer l'écriture directe `api/v2/cmdb` par l'ajout au feed `omni-soar` (chemin sûr déjà prouvé : pas de creds sur le FW, TTL, whitelist, kill-switch).
4. **Arbitrer le chevauchement corrélation** : oms-xdr (scénarios nommés, data-driven) vs `omni-incident-correlate` (kill-chain entité 0-100). Recommandation : oms-xdr devient le moteur de corrélation **de référence** ; `omni-incident-correlate` retiré une fois la couverture validée.
5. **Actionneurs AD/NinjaOne** : brancher quand les comptes API ESET/AD seront fournis (runbook LDAP/WinRM), human-in-the-loop d'abord.
6. **Déploiement** : systemd timer (comme les 26 `omni-*`), secrets via `00-vars.env`/Vaultwarden, token Graylog lecture seule dédié.

## 4. Garde-fous conservés

Dry-run par défaut (double verrou `dry_run=false` ET `auto_*`), netscan désactivé, exclusions à reporter
(jamais les plages IPsec partenaires / DC / comptes de service critiques), audit GELF de toute action.

## 5. Validation (18/06/2026) — OK de bout en bout

- `pytest` 10/10 vert, `ruff` clean après recâblage.
- Cycle `--once` réel : lecture **OpenSearch local** OK, **1 incident corrélé** produit
  (`CR_CRED_ABUSE`), responder en **RECOMMANDATION** (dry-run respecté), incident
  **réinjecté dans le SIEM** (GELF 12201, `event_source=xdr_incident`, indexé).
- Lecture recâblée sur OpenSearch (`/api/search/messages` renvoie 400 en 7.1) ; token
  Graylog rendu **optionnel**.
- Tuning : exclusion des comptes machine (`NOT user:*$`) sur les signaux brute force /
  logon ; timeout de connexion Ollama ramené à 5 s (démon non bloquant).

### Suites identifiées
1. **Ollama injoignable** depuis la VM SIEM (10.33.220.10 → 10.33.120.55:11434 timeout) :
   ouvrir le flux pare-feu pour activer la narration LLM (fallback déterministe OK en attendant).
2. **Faux positifs comptes de service** (ex. `ninjaone`) : ajouter une exclusion configurable
   (ou consommer le champ `account_class` de l'enrichissement existant).
3. Router `event_source:xdr_incident` vers une page dashboard dédiée.
4. Responder FortiGate → déléguer au feed `omni-soar` (chemin sûr déjà prouvé).

## 6. Suites RÉALISÉES (18/06/2026)

- **Ollama LOCAL** sur la VM SIEM (127.0.0.1:11434, CPU-only, `qwen2.5:3b`) — narration LLM validée.
- **Faux positifs** : exclusion `account_class:machine/service` + `ninjaone`/`fortinet` classés service (49-enrich).
- **Responder FortiGate → feed `omni-soar`** (aucun credential sur le FW ; public-only/whitelist/TTL/cap).
- **Page dashboard « OMS-XDR »** (route `event_source:xdr_incident` → stream Interne SIEM ; KPI + tables + narration).
- **Déploiement systemd** : `oms-xdr.timer` (cycle 5 min, dry-run, lecture OpenSearch, root, depuis le dépôt).

### Reste (quand dispo)
- API ESET/AD pour rendre `disable_ad_account` / `isolate_ninjaone` exécutables (runbook), human-in-the-loop d'abord.
- Arbitrage final corrélation oms-xdr vs `omni-incident-correlate` (retirer l'ancien une fois la couverture confirmée).
- Ouvrir `auto_block_fortigate` (dry_run=false) après période d'observation sur le stream incidents.
