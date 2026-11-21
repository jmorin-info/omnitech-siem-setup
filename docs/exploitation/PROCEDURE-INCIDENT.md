# Procédure de détection et de réponse aux incidents de sécurité

> Décrit comment un événement de sécurité est détecté, évalué, traité et clos via
> le SIEM OMNITECH. Couvre ISO/IEC 27001:2022 **A.5.24** (préparation),
> **A.5.25** (évaluation/décision), **A.5.26** (réponse), **A.5.27**
> (enseignements), **A.5.28** (preuves).
>
> **Statut :** procédure opérationnelle — à valider/approuver par le RSSI.

## 1. Rôles et responsabilités

| Rôle | Responsabilité |
|------|----------------|
| **Analyste SOC / Administrateur** | Triage quotidien, qualification, traitement de 1er niveau |
| **RSSI** | Décision sur incidents majeurs, communication, enseignements |
| **SIEM (automatisé)** | Détection, corrélation, scoring, notification, réponse réflexe (SOAR) |

## 2. Chaîne de traitement (du log à l'incident clos)

```
Événement ─► Détection (88 règles) ─► Enrichissement (MITRE + score) ─► Corrélation
   (alert_tag)        (alerte P2/P3)         (risk_score, technique)      (kill-chain)
                                                                              │
                          ┌───────────────────────────────────────────────────┘
                          ▼
   Notification (e-mail/Teams) + Incident horodaté (page « Incidents »)
                          │
        ┌─────────────────┼──────────────────┐
        ▼                 ▼                  ▼
   ÉVALUATION (A.5.25)  RÉPONSE (A.5.26)   CLÔTURE + ENSEIGNEMENTS (A.5.27)
```

## 3. Détection (A.5.24)

- **Automatique et continue** : 88 règles de détection (cf.
  `REGISTRE-DETECTIONS.md`) + détection comportementale (UEBA/NDR).
- **Priorisation** : **P3** = critique (sabotage d'audit, DCSync, ransomware,
  incident corrélé critique, canari…) ; **P2** = important (LSASS, beaconing,
  tunnel DNS, go-dark, entité UEBA ≥80…).
- **Notification** : chaque déclenchement envoie un e-mail + un message Teams au
  canal SOC. Anti-tempête : pas de renvoi en boucle (délai par entité).

## 4. Évaluation et décision (A.5.25)

L'analyste qualifie via le SIEM :

1. **Page « Direction »** — y a-t-il des incidents critiques / entités à risque ?
2. **Page « Incidents »** — lire le **récit d'attaque** (kill-chain ordonnée) :
   entité, séquence de tactiques, fenêtre temporelle, score.
3. **Page « UEBA / NDR »** — score de l'entité, facteur dominant.
4. **Page « Investigation »** — taper `host:…` ou `user:…` pour tout corréler
   (message brut conservé pour le forensic).

**Décision** : faux positif (documenter) / incident mineur (traiter) / incident
majeur (escalade RSSI). Critères d'escalade : technique critique (T1003, T1486,
DCSync), compte à privilèges, score ≥80, ou plusieurs tactiques enchaînées.

## 5. Réponse (A.5.26)

- **Réflexe automatique (SOAR)** : une IP attaquante répétée (force brute VPN /
  password spraying) est bloquée automatiquement au pare-feu (TTL configurable),
  **jamais** sur une IP interne ou sur liste blanche. Playbooks **isolation d'hôte /
  désactivation de compte** conçus (attente API NinjaOne) → cf. `SOAR-PLAYBOOKS.md` ;
  d'ici là, ces actions restent **manuelles**.
- **Pivot d'investigation** : utiliser le champ **`identity`** (page « Identité »)
  pour reconstituer l'activité d'une personne sur **toutes** les sources
  (AD + M365 + VPN + endpoint), et `src_hostname` pour résoudre une IP interne.
- **Confinement manuel** : désactiver le compte compromis (AD/M365), isoler
  l'hôte, révoquer les sessions, bloquer l'IP/domaine.
- **Éradication** : retirer la persistance (tâche/service/clé Run), corriger la
  vulnérabilité (page « Vulnérabilités »), forcer le changement de mot de passe.
- **Reprise** : restaurer depuis sauvegarde Veeam si nécessaire (page
  « Sauvegardes »), vérifier le retour à la normale.

## 6. Collecte de preuves (A.5.28)

- Les journaux pertinents sont **conservés et horodatés** (12 mois pour le
  dossier sécurité), en **écriture seule** + **registre d'intégrité signé**
  (tamper-evidence) attestant qu'ils n'ont pas été altérés sur l'intervalle.
- Le **message brut** est conservé (champ `message`) pour l'analyse forensique.
- Export possible : recherche Graylog → export CSV ; **sceller** l'export
  (`sha256sum`) + joindre l'attestation `omni-integrity --verify` → **chaîne de
  possession** (procédure détaillée : `PROCEDURE-INTEGRITE-PREUVE.md`).
- La **chaîne de corrélation** (incident) documente la séquence horodatée.

## 7. Clôture et enseignements (A.5.27)

- Documenter la qualification, les actions, la cause racine.
- Si récurrent : ajuster les seuils, ajouter/affiner une règle de détection,
  étendre une liste blanche (ex. beaconing SaaS légitime).
- Les **rapports hebdomadaire et mensuel** consolident les tendances et le top
  des risques pour la revue de direction.

## 8. Indicateurs (pour la revue de direction)

- Nombre d'incidents critiques / élevés (mois).
- Couverture de collecte (%) et hôtes go-dark.
- Top entités à risque (UEBA), top techniques ATT&CK observées.
- Vulnérabilités KEV exposées.

Source : rapport mensuel (`omni-monthly-report`, archivé `/kit/rapports/`).

---
*Voir `ISO27001-MAPPING.md` (correspondance contrôles), `REGISTRE-DETECTIONS.md`
(règles), `PROCEDURE-EXPLOITATION-SIEM.md` (exploitation courante).*
