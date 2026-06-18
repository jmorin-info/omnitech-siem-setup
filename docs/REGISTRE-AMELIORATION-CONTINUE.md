# Registre d'amélioration continue — SIEM/XDR OMNITECH (ISO/IEC 27001:2022, clause 10)

**Périmètre :** plateforme de supervision & détection/réponse (Graylog + oms-xdr).
**Propriétaire :** RSSI (J. Morin). **Revue :** mensuelle + revue de direction (clause 9.3).
**Dernière mise à jour :** 2026-06-18.

> **Clause 10.1 (amélioration continue)** : la plateforme évolue de façon proactive
> (nouvelles sources, détections, capacités) pour améliorer en continu la pertinence
> et l'efficacité du SMSI. **Clause 10.2 (non-conformité & action corrective)** :
> distinction stricte **correction** (remise en état immédiate) vs **action corrective**
> (traitement de la cause racine) ; une entrée n'est **close qu'après vérification
> d'efficacité**. Toutes les modifications sont tracées en Git (`omnitech-siem-setup`,
> dépôt privé) — preuve de **maîtrise du changement (A.8.32)**.

## 1. Non-conformités & actions correctives (10.2)

| ID | Date | Constat (non-conformité) | Cause racine | Correction immédiate | Action corrective (cause) | Vérification d'efficacité | Annexe A | Statut |
|---|---|---|---|---|---|---|---|---|
| **AC-2026-06-18-01** | 18/06 | Tempête de ~3000 alertes/événements | (1) détection « injection de processus » trop large (taggait `bash.exe`/`node.exe` = outils dev) ; (2) **hopping window** (`search_within` 5 min > `execute_every` 1 min) → chaque message compté ×5, sur 21 définitions | Exclusion des outils dev dans la détection injection ; seuils `count≥10/8` sur injection/PowerShell/UTM | `mk_def` (13) clampe désormais `execute_every ≥ search_within` (**tumbling garanti**) ; 83 définitions repassées en tumbling | Volume d'événements : « injection » sorti du top ; vérifié post-fix (commit `104a08a`) | A.8.16 | **Clos** |
| **AC-2026-06-18-02** | 18/06 | Faux positif `exposition_internet` sur le trafic **IPsec inter-sites** (Bordeaux↔Ivry) | Règle `omni-forti-16-expo-internet` sans garde-fou : taguait tout flux entrant-WAN accepté, trafic tunnelé compris | Ajout garde-fous `subtype != "local"` **et** `NOT has_field("vpntype")` (déployé) | Garde-fous intégrés au script `49-expo-port-class.sh` (persistant) | Règle déployée vérifiée (2 garde-fous présents) ; FP n'apparaît plus sur le trafic tunnelé (commit `8897604`) | A.8.16, A.8.20 | **Clos** |
| **AC-2026-06-18-03** | 18/06 | Abort **silencieux** (exit 5) de `49-expo-port-class.sh` au re-run | Règle morte `omni-forti-15-net-direction` en syntaxe ternaire (`let = if…then…else`) **refusée par Graylog** → `api_post` échouait sous `set -e` | Retrait de la règle morte (net_direction est posé par 4 règles `dir-*`) | Documenté comme piège ; convention « 1 règle par condition, aucun conditionnel dans le `then` » | Script ré-exécuté jusqu'à `EXIT=0` (commit `8897604`) | A.8.32 | **Clos** |

## 2. Améliorations proactives (10.1)

| ID | Date | Amélioration | Bénéfice SMSI | Annexe A | Preuve | Statut |
|---|---|---|---|---|---|---|
| AM-01 | 18/06 | **Mise sous contrôle de version** de tout le provisioning (Git privé GitHub) + gabarits de secrets | Maîtrise du changement, réduction du **risque key-person** (dépôt = source unique versionnée) | A.8.32, A.5.37 | dépôt `omnitech-siem-setup` (commits datés) | Clos |
| AM-02 | 18/06 | **Alertes auto-explicatives** : cause de l'échec, EventID, ATT&CK, score, + « explication / que faire » par détection | Réduction du MTTD/MTTR, triage plus rapide | A.8.16, A.5.25 | gabarits `13` ; lookup `alert-explain.csv` | Clos |
| AM-03 | 18/06 | **Renseignement sur les menaces étendu** : feeds IOC abuse.ch (Feodo C2, URLhaus) + matching auto | Détection des menaces **connues** (C2/domaines malveillants) | A.5.7 | `66-threatintel.sh` ; lookups `ti-*` ; tags `c2_ioc`/`malware_domain` | Clos |
| AM-04 | 18/06 | **Couverture ATT&CK étendue** : web shell (T1505.003), NTDS (T1003.003), reco AD (T1087.002) + carte de couverture | Comblement de trous de détection priorisés ; preuve de couverture | A.8.16, A.5.7 | `67-detection-coverage.sh` ; `docs/mitre-navigator-layer.json` | Clos |
| AM-05 | 18/06 | **Couche XDR (oms-xdr)** : corrélation kill-chain + triage LLM local (Ollama) + réponse dry-run | Qualification/priorisation des incidents, narration analyste | A.5.24, A.5.25 | `oms-xdr/` ; timer `oms-xdr` ; page dashboard « OMS-XDR » | Clos |
| AM-06 | 18/06 | **Nouvelle source FortiManager** (admin/config) + **app mobile PWA** (alertes/incidents + push) | Couverture journalisation FMG ; réponse RSSI en mobilité | A.8.15, A.5.26 | `63-fortimanager.sh` ; `65-mobile-pwa.sh` | En cours (forwarding FMG / egress push côté infra) |
| AM-07 | 18/06 | **Actionneur de réponse AD** : désactivation de compte compromis via LDAPS (dry-run + denylist + audit + human-in-the-loop) | Neutralisation rapide d'un compte compromis | A.5.26, A.8.16 | `69-ad-response.sh` ; `/usr/local/sbin/omni-ad-disable` | Dry-run (à armer après délégation AD) |

> **Risque accepté (décision RSSI, 18/06) — AC-RA-01 :** réutilisation du compte
> d'authentification LDAPS `svc_siem` comme acteur de désactivation AD, plutôt qu'un
> compte de réponse dédié. **Écart signalé** au moindre privilège (A.5.18) et à la
> séparation des tâches : un secret d'authentification très exposé acquiert une
> capacité d'écriture sur AD. **Mesures compensatoires en place :** denylist stricte
> des comptes protégés (admin/service/secours/`krbtgt`/`adm-`/`svc_`) ; exécution
> **dry-run par défaut** (double verrou `OMNI_AD_DISABLE_ARM`) ; **journalisation GELF**
> de chaque tentative (`event_source=ad_response`) ; invocation **human-in-the-loop**
> uniquement (jamais en réponse automatique) ; secret LDAPS **non dupliqué** (lu depuis
> `00-vars.env`). **À réévaluer en revue de direction** (bascule vers un compte dédié recommandée).

## 3. Méthode (attendue par l'auditeur Stage 2, nov. 2026)
- Chaque entrée porte **date, propriétaire, cause racine, action, et preuve de vérification** ; la preuve est le commit Git + l'état vérifié en production (« evidence is evidence »).
- Les entrées ci-dessus alimentent la **revue de direction** (clause 9.3) et le **registre des risques**.
- Indicateur de vitalité du SMSI : ce registre montre des entrées **datées et vérifiées** (≠ scores figés d'une année sur l'autre = drapeau rouge auditeur).
