# OMNI Sentinel — Défense proactive (architecture & gouvernance)

> **Statut** : 3 piliers déployés (23/06/2026). Document de référence pour l'exploitation,
> l'onboarding et l'audit ISO 27001 (Stage 2). Local-first, lecture passive, human-gated.

## 1. Pourquoi
Un SIEM classique est **réactif** : il détecte ce qui a déjà tiré une signature. OMNI Sentinel
ajoute une couche **proactive** : modéliser l'environnement, **prendre l'attaquant de vitesse**
en pré-positionnant des pièges sur ses chemins probables, et le contenir **avant l'impact** —
le tout sous contrôle strict (dry-run par défaut, périmètre borné, audit).

## 2. Architecture (les 3 piliers en boucle)

```
   Télémétrie passive (logons 4624/4672, Sysmon, M365, FortiGate)
        │
        ▼
  ┌─────────────────────┐      désigne OÙ poser les leurres
  │ PILIER 2 — Jumeau   │ ───────────────────────────────────┐
  │ d'attaque (oms-graph)│                                     │
  │ chemins → joyaux,    │ ◀── contexte (rayon de souffle,     │
  │ chokepoints, blast   │     distance aux joyaux)            │
  └─────────────────────┘                                     ▼
        │ exposition                              ┌─────────────────────┐
        │ (console + GELF attack_path)            │ PILIER 1 — Déception │
        │                                         │ (88, lookup          │
        ▼                                         │  omni-deception)     │
  ┌─────────────────────┐   un leurre tire        │ comptes/SPN/canaris  │
  │ PILIER 3 — Réponse  │ ◀──────────────────────│ 0-FP, fidélité ~100% │
  │ graduée (respond)    │                         └─────────────────────┘
  │ grade + plan +       │
  │ exécution armée      │ ──▶ NinjaOne (isolation) · FortiGate (blocage via omni-soar)
  │ (infra OMNITECH)     │ ──▶ AD : recommandation seulement (jamais armé)
  └─────────────────────┘ ──▶ audit GELF sentinel_response
```

**La boucle** : le Jumeau (P2) dit *où* l'attaquant ira → on y sème des leurres (P1) → un
leurre touché déclenche une réponse *graduée par le contexte du Jumeau* (P3). **Détecter →
contextualiser → répondre**, du même geste.

## 3. Pilier 1 — Déception (`88-deception-honeytokens.sh`)
Des **leurres sans aucun usage légitime** : tout contact = attaquant.
- **Mécanique** : lookup Graylog `omni-deception` (CSV `lookups/deception-decoys.csv`,
  `key,type`, case-insensitive, relu toutes les 60 s). **Ajouter un leurre = 1 ligne**, couvert
  sans toucher au code.
- **5 règles** (stage 13) : `decoy_identity` (T1078, auth Windows 4624/4625/4768 sur compte/
  machine leurre), `decoy_kerberoast` (T1558.003, TGS 4769 sur SPN leurre — *zero-FP vérifié*),
  `decoy_identity` M365, `canary_token` (T1005, requête DNS Sysmon/FortiGate vers un FQDN canari).
- **Garantie 0-FP** : collision mesurée = 0 sur 30 j pour les 15 comptes + 5 FQDN.
- **Appât** (planter les comptes/fichiers) : action RSSI en dry-run sur l'AD OMNITECH —
  voir `DECEPTION-PLAN.md`. **Jamais** sur le tenant co-managé invissys.

## 4. Pilier 2 — Jumeau d'attaque (`oms-graph`)
Reconstruit **passivement** (sans sonde AD) un graphe d'exposition.
- **Arêtes** : *HasSession* (4624 LogonType 2/10/11 → identifiants exposés sur l'hôte) +
  *AdminTo* (4672 → admin de l'hôte). Propagation de **contrôle** : contrôler un hôte =
  moissonner ses comptes ; contrôler un compte = ses hôtes admin.
- **Calculs** : exposition des joyaux (DC/SIEM/Veeam/PKI/fichiers/vSphere), **chokepoints**
  (où durcir/leurrer), **rayon de souffle**, **points uniques** (RMM admin partout),
  **recommandations de placement de leurres**.
- **Anti-bruit (mesuré)** : comptes machine/système/virtuels exclus ; comptes de gestion
  ubiquitaires sortis des chemins latéraux (sinon ils relient tout à tout).
- **Décision d'ingénierie** : l'arête Kerberos (4769) est **volontairement écartée** —
  sémantiquement c'est de la *joignabilité*, pas du *contrôle* ; l'inclure surévaluerait
  les chemins de pivot.
- **Sorties** : artefact `/var/lib/omni-mobile/attack-graph.json` (console, onglet *Jumeau* /
  PWA *Exposition*) + GELF `event_source=attack_path` (informationnel, sans alert_tag).

## 5. Pilier 3 — Réponse graduée (`oms-graph respond`)
Compose un déclencheur (leurre/détection) + le contexte du Jumeau → un **plan gradé**
(critique/élevé/modéré). Démontrable en tabletop (`respond --simulate <hôte|compte>`), visible
dans la console (clic sur une entité du Jumeau → modal de réponse).

### Modèle de sécurité (quadruple verrou)
Une action ne s'exécute réellement **que si les quatre** sont réunis :

| Verrou | Mécanisme |
|---|---|
| 1 | `response.dry_run = false` (config) |
| 2 | `auto_<action> = true` (config, par action) |
| 3 | `OMNI_SENTINEL_ARM=1` (variable d'environnement sur l'hôte) |
| 4 | `--execute` (approbation explicite de l'analyste — jamais automatique) |

**Bornes non contournables (en dur)** :
- **Actions identitaires (AD/reset)** = recommandation **toujours**, jamais armées.
- **Cible co-managée** (marqueur `invissys`) = forcée en dry-run.
- **Armable** uniquement sur l'infra OMNITECH propre : isolation NinjaOne, blocage FortiGate
  (délégué au feed `omni-soar`, aucun credential pare-feu).
- Le timer `oms-graph-respond` grade + audite **sans jamais exécuter** (pas de `--execute`).
- Audit GELF `event_source=sentinel_response` de chaque plan.

## 6. Mapping ISO 27001
| Contrôle | Couverture Sentinel |
|---|---|
| A.8.7 (protection contre maliciel) | Déception + détection proactive |
| A.8.16 (surveillance) | Jumeau d'exposition + leurres + audit |
| A.5.7 (renseignement sur les menaces) | Chemins d'attaque, chokepoints, blast radius |
| A.5.26 (réponse aux incidents) | Réponse graduée human-gated |
| A.5.15 / A.8.2 (accès privilégiés) | Points uniques signalés (AC-RA-02) |
| A.8.32 (gestion des changements) | Tout versionné, dry-run, réversible |

## 7. Runbook
- **Déployer** : `./88-deception-honeytokens.sh` (pièges) puis `./89-attack-graph.sh` (jumeau +
  réponse). Relancer `57` (carte ATT&CK) + `14` (dashboards) après 88.
- **Planter les appâts** : suivre `DECEPTION-PLAN.md` (comptes leurres *dormants*, fichiers canari)
  sur l'AD OMNITECH. Ajouter la clé exacte dans `deception-decoys.csv` → couvert en < 60 s.
- **Étendre** : joyaux / footholds / leurres dans `oms-graph/config.yaml` (1 ligne).
- **Tabletop** : `oms-graph respond --simulate <hôte|compte>` ou clic dans la console.
- **Armer P3** (le jour voulu) : `response.dry_run=false` + `auto_isolate_ninjaone=true` (et/ou
  `auto_block_fortigate`) dans `/etc/oms-graph/config.yaml`, exporter `OMNI_SENTINEL_ARM=1`,
  fournir les creds `OMS_NINJA_*`. L'exécution reste sur approbation `--execute`.
- **Cadence** : jumeau quotidien, gradation des leurres toutes les 15 min (audit seul).

## 8. Limites (honnêteté)
- Les pièges (P1) sont **armés mais inertes** tant que les appâts ne sont pas plantés (action RSSI).
- Le jumeau (P2) modélise le **contrôle par identifiants** (HasSession/AdminTo) — pas les
  exploits applicatifs ni la joignabilité réseau pure.
- La réponse réelle (P3) exige les creds NinjaOne + l'armement explicite ; par défaut tout est
  recommandation.
- Périmètre strictement **défensif** et **OMNITECH** ; le tenant co-managé reste hors exécution.
