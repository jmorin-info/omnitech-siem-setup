# BRIEF.md — Brief projet OMS-XDR

Ce fichier est destiné au mainteneur du projet. Lis-le en premier avant toute modification.

> ⚠️ **État intégré au SIEM (18/06/2026) : source de vérité = `docs/INTEGRATION-OMNITECH.md`.**
> Différences vs le brief d'origine ci-dessous : **lecture OpenSearch local** (pas l'API
> `/api/search/messages`, qui renvoie 400 en **Graylog 7.1**) ; **GELF HTTP 12201** (input
> existant) ; **Ollama LOCAL `127.0.0.1:11434` modèle `qwen2.5:3b`** (plus 10.33.120.55) ;
> blocage FortiGate **délégué au feed `omni-soar`** ; **token Graylog non requis** ;
> déployé en `oms-xdr.timer` (5 min). `make run-once` ne nécessite plus de token.

## 1. Objectif

OMS-XDR est une **surcouche XDR** au-dessus du SIEM Graylog d'OMNITECH Security.
Elle reproduit les fonctions clés d'un MXDR (corrélation cross-domaine,
enrichissement, remédiation guidée, réponse semi-autonome) **sans SOC externe**.
Voir `README.md` pour la cartographie MXDR → équivalents.

## 2. Principe de fonctionnement

```
OpenSearch ─(terms agg / messages, omni-*)─►  correlation.py  ──►  Incident
                                                │
              enrich.py (Ollama/Mistral) ◄──────┤
              remediation.py (playbooks) ◄──────┤
              responder.py (FGT/AD/Ninja) ◄─────┤
                                                ▼
Graylog ◄──(GELF HTTP 12201, event_source=xdr_incident)── engine.py + Teams
```

Architecture **découplée volontaire** : pas de plugin Java Graylog. **Intégration
sur la VM SIEM** (18/06/2026) : lecture via **OpenSearch local** (comme les
services `omni-*`), écriture sur le **bus GELF existant** du SIEM (input HTTP
12201). Les signaux consomment les détections existantes (`alert_tag` + schéma
normalisé) — cf. `docs/INTEGRATION-OMNITECH.md`.

## 3. Structure

| Fichier | Rôle |
|---|---|
| `oms_xdr/config.py` | chargement YAML |
| `oms_xdr/graylog_client.py` | recherche (Search Scripting API) + agrégation + envoi GELF |
| `oms_xdr/rules.yaml` | **données** : signaux atomiques + règles de corrélation (MITRE) |
| `oms_xdr/correlation.py` | moteur : signaux → règles → `Incident` |
| `oms_xdr/remediation.py` | playbooks par règle/technique (actions OMNITECH) |
| `oms_xdr/enrich.py` | narration analyste FR via Ollama (fallback déterministe) |
| `oms_xdr/responder.py` | actions de containment (dry-run par défaut) |
| `oms_xdr/engine.py` | orchestrateur + dédup + notification |
| `oms_xdr/netscan.py` | découverte réseau nmap + diff baseline → GELF |
| `deploy/` | units systemd, env, provisionnement Graylog |
| `tests/` | pytest (corrélation, remédiation) |

## 4. Commandes

```bash
make install      # venv + dépendances + paquet en editable
make test         # pytest
make lint         # ruff (si installé)
make run-once     # un cycle de corrélation (nécessite OMS_GRAYLOG_TOKEN)
make scan-quick   # scan réseau top-1000
```

Sans make :
```bash
python -m oms_xdr.engine --once --config /etc/oms-xdr/config.yaml
python -m oms_xdr.netscan --mode quick --config /etc/oms-xdr/config.yaml
pytest -q
```

## 5. Conventions (à respecter dans toute contribution)

- **Sorties utilisateur/logs métier en français**, registre expert RSSI. Identifiants
  de code en anglais. Pas de remplissage, pas de hand-holding.
- Type hints partout, `from __future__ import annotations`, logging par module
  (`logging.getLogger("oms-xdr.<module>")`).
- **Aucun secret en dur.** Tout via variables d'environnement (cf. `oms-xdr.env`).
  Idéalement injection depuis Vaultwarden (`vaultwarden.omnitech-security.fr`).
- La détection est **pilotée par données** : enrichir `rules.yaml` plutôt que le code.
  Un nouveau signal = entrée dans `signals:` ; une nouvelle chaîne = entrée dans `rules:`.
- Robustesse : un signal/cycle en échec ne doit jamais faire tomber le démon.

## 6. CONTRAINTE DE SÉCURITÉ (non négociable)

- `response.dry_run: true` est le défaut. **Ne jamais** câbler une action qui
  s'exécute sans le double verrou `dry_run=false` ET `auto_<action>=true`.
- `netscan` ne balaie QUE les réseaux internes déclarés dans `netscan.targets`.
  Ne pas ajouter de cible hors périmètre OMNITECH.
- Toute action de réponse réelle (blocage FGT, désactivation compte AD,
  isolation endpoint) doit rester traçable (log WARNING + champ `actions` de l'incident).

## 7. Constantes d'infrastructure (contexte, ne pas committer de valeurs sensibles)

- Graylog : `https://10.33.220.10` (Debian 13, Graylog 6.x, OpenSearch 2.x, MongoDB rs0).
- AD : domaine `omnitech.security`, DC `10.33.50.250` (BX-AD-01-IT-VM).
- FortiGate 120G HA (FortiOS 7.4.x), FortiManager + FortiAnalyzer (CEF 1514).
- Ollama interne : `http://10.33.120.55:11434` (Mistral 7B).
- ESET EDR, NinjaOne RMM (~150 endpoints), Centreon 24.10, Veeam 3-2-1-1.

## 8. Tâches prioritaires (cf. `docs/ROADMAP.md` pour le détail)

1. Runbooks AD signés (WinRM/NinjaOne) pour rendre `disable_ad_account` / `force_pwd_reset` exécutables.
2. Threat intel : lookup tables Graylog (abuse.ch, OTX) + signal `S_C2_IOC`.
3. Signaux Sysmon (déploiement NinjaOne) : T1055, T1003, parent/child process.
4. Anomalies EWMA par entité (remplacer les seuils fixes).
5. Corrélation vuln : croiser `netscan` ↔ POL_018 (matrice CVSS).
6. Dashboard Graylog « OMS-XDR Incidents » + rapport hebdomadaire planifié.

## 9. Définition de « terminé » pour une contribution

- `make test` passe (ajouter un test pour tout nouveau signal/règle/action).
- Aucun secret introduit ; `dry_run` reste le défaut.
- README/ROADMAP mis à jour si comportement ou périmètre change.
