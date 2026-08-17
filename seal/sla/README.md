# SLA d'acquittement des alarmes SEAL severes

Détecte les **alarmes de sûreté physique sévères qui restent ouvertes sans être
traitées** au-delà d'un délai (SLA), sur les deux sites (QA + OMEGA), et notifie.

## Pourquoi un poller (et pas une simple détection Graylog)

Une event definition Graylog agrège une fenêtre et se déclenche sur un seuil.
Elle **ne sait pas exprimer « une alarme ouverte SANS événement de clôture »**
(anti-jointure / absence). Le poller le fait par **corrélation d'état par groupe
d'alarme** puis émet un marqueur que Graylog, lui, sait alerter.

## Modèle de données (vérifié sur la collecte réelle)

- Chaque alarme = un `EVEN_GROUP_ID`. La vue `ALARMES` ré-émet une ligne à chaque
  transition de cycle de vie → plusieurs événements Graylog par groupe. Le
  **dernier** (timestamp max) porte l'état courant.
- `EVEN_LIFESTATUS` : `END` = clos/résolu · `LIV` = actif/en cours · `INF` = informatif.
  - **Résolu** = dernier statut `END` (ou `ACK_EVEN_ID` présent = acquitté console).
  - **Ouvert** = dernier statut `LIV` → candidat SLA.
  - `INF` (et autres) = informatif → **hors SLA**.
  - `END_EVEN_ID` seul n'est PAS fiable (présent même sur des groupes `LIV`).
- `severity_num` est **inexploitable comme rang** (ce sont des codes, pas un score).
  La sévérité SLA vient donc d'un **set de codes REEV** (cf. `severe-codes.json`).
- La majorité des « alarmes » sont du bruit maintenance (perte de module SEM97,
  DOMBOX) ou des événements ponctuels sans cycle (refus d'accès SEM122… déjà
  couverts par les détections de seuil). Ils sont **exclus** du SLA.

## Politique par défaut

| Code | Classe | SLA | Libellé |
|------|--------|-----|---------|
| SEM218 | critical | 15 min | Intrusion détectée par la vidéo |
| SEM113 | critical | 15 min | Effraction porte |
| SEM805 | critical | 15 min | Déclencheur manuel |
| SEM118 | high | 60 min | Bouton poussoir bloqué |
| SEM73  | high | 60 min | Base de données UTL modifiée |

Ajustable par site (`SEAL_SLA_SITE_MULT`) et par code (`severe-codes.json`).

## Chaîne complète

```
alarmes SEAL (stream Alarmes)
   │
   ▼  seal_sla_poller.py  (timer 1 min)   ── état par groupe, âge > SLA ? ──┐
   │                                                                        │
   ▼  émet un marqueur GELF  alert_tag=seal_sla_breach  (idempotent)        │
   │     _seal_site _sla_class _sla_minutes _age_minutes _REEV_CODE ...     │
   ▼                                                                        │
détections SLA-001 (critique) / SLA-002 (élevée)  ── group_by seal_site ────┤
   │     → notification Teams/mail (sévérité selon la classe)               │
   ▼                                                                        │
widget « Backlog SLA par site »  (dashboard SEAL - Vue multi-site)  ◄───────┘
```

Idempotence : le poller n'émet **qu'un marqueur par brèche** (et un de plus à
chaque palier d'escalade = `facteur × SLA`). Les détections sont en fenêtre
tumbling (une alerte par marqueur). Pas de flood.

## Installation

```bash
sudo seal/sla/install-sla-poller.sh      # déploie tout, timer DÉSACTIVÉ, test à blanc
```

Le script affiche les brèches actuelles (`--once`). **Après revue** :

```bash
sudo systemctl enable --now oms-seal-sla.timer
journalctl -u oms-seal-sla.service -f
```

Le timer est laissé désactivé volontairement (même logique que les dead-man
switches : activation post-recette, une fois la politique validée).

## Utilisation manuelle

```bash
# calcul seul, sans émission ni écriture d'état (revue)
/opt/oms-seal-sla/.venv/bin/python /opt/oms-seal-sla/seal_sla_poller.py --once

# cycle réel (émet + met à jour l'état) — normalement lancé par le timer
/opt/oms-seal-sla/.venv/bin/python /opt/oms-seal-sla/seal_sla_poller.py
```

## Configuration

Tout est dans `/etc/oms-seal-sla/seal-sla.env` (voir `deploy/seal-sla.env.example`).
Aucun secret : lecture OpenSearch locale, émission GELF locale.

Pour un parc différent, **découvrir les codes** puis ajuster `severe-codes.json` :

```
event_domain:alarm            # puis regarder REEV_CODE / event_action / EVEN_LIFESTATUS
```

## Règles d'engagement respectées

- Lecture OpenSearch **locale** uniquement ; aucune écriture côté SEAL.
- Aucun impact sur le tenant co-géré ; aucun secret détenu par le poller.
- Idempotent ; `--once` sûr ; timer désactivé par défaut.
