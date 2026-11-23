# Zones physiques SEAL — résolution topologique

Objectif : rattacher chaque événement (accès, alarme, audit) à la **zone physique**
de l'objet concerné (porte, caméra) pour permettre la répartition et l'alerting
**par zone** — au-delà du seul site.

## État des lieux (vérifié sur la collecte réelle)

| Domaine | `target_object_id` (OBFI_ID) présent | Remarque |
|---------|--------------------------------------|----------|
| access  | **99,4 %** (976 k / 982 k) | la porte = OBFI_ID → fort potentiel |
| alarm   | 0,65 % (4,6 k / 713 k) | seules les alarmes *localisées* (intrusion, porte) |
| audit   | 44 events | opérations de config sur objets/zones |

- Le champ `site` des vues est **NULL** : la hiérarchie topologique
  (`ObjectsHierarchicalCatalog`, ~77 nœuds Porte/Capteur/**GroupeZone**) n'est pas
  jointe. La recon a montré que `NodeObjectId ≠ Objet_Fiche.OBJ_ID` (0 match).
- Le domaine **audit** expose déjà des objets de type `GroupeZone` et des libellés
  « Secteur Formation 1 » → la notion de zone **existe** dans SEAL ; il reste à
  relier chaque objet à sa zone via la hiérarchie.
- Le compte de service `svc_graylog_seal` **ne peut pas** lire la table de
  hiérarchie (verrouillée aux vues par `90_provision`) → l'établissement du lien
  est une **étape opérateur** (compte admin).

## Architecture retenue

```
ObjectsHierarchicalCatalog  (hiérarchie SEAL, admin)
        │  07_recon_topology.sql   → confirmer NodeObjectId = OBFI_ID + classe ZONE
        ▼
dbo.vw_SealZone_SIEM   (OBFI_ID → ZONE_LABEL / ZONE_PATH)     [07_, GRANT svc]
        │  regen_zone_lookup.sh    (multi-site, clé seal_site:OBFI_ID)
        ▼
/etc/graylog/lookup/omni-seal-zone.csv   →  lookup Graylog  omni-seal-zone
        │  16-seal-zone.rule       (stage terminal des 3 pipelines)
        ▼
seal_zone  posé sur les événements  →  widgets « par zone » + détection ZON-001
```

**Clé composite `seal_site:OBFI_ID`** : un OBFI_ID peut collisionner entre sites
(QA porte 285 ≠ OMEGA porte 285) ; la règle et le regen préfixent par `seal_site`.

## Ce qui est DÉJÀ en place (SIEM, testé)

- Lookup `omni-seal-zone` (adapter csvfile + cache + table) — provisionné.
- Règle pipeline `16-seal-zone.rule` (stage terminal des 3 pipelines) — compile,
  **enrichissement validé E2E** (injection OBFI_ID 285 → `seal_zone` posé via la
  clé composite ; normalisation du flottant `0.285e3` → `285` par `to_long`).
- Widgets « Accès par zone » et « Refus par zone » (dashboard *Vue multi-site*).
- Détection `ZON-001` (rafale de refus concentrée dans une zone).

Tout cela est **inerte** tant que le CSV est vide : aucun `seal_zone` posé, aucun
faux positif. L'activation ne demande que de peupler le CSV (étapes opérateur).

## Étapes OPÉRATEUR (compte admin SQL)

1. **Recon** : exécuter `seal/sql/07_recon_topology.sql`, relever les 4 points de
   l'étape 6 (schéma/table réels, noms de colonnes, jointure `NodeObjectId = OBFI_ID`,
   valeur de `NodeClass` identifiant une zone).
2. **Vue** : ajuster `seal/sql/07_vw_SealZone_SIEM.sql` avec ces 4 points, puis
   l'exécuter (crée `dbo.vw_SealZone_SIEM` + `GRANT SELECT` au service). À répéter
   sur **chaque** SEAL (QA + OMEGA).
3. **Peupler le lookup** (côté SIEM) :
   ```bash
   set -a; source /root/omnitech-siem-setup/00-vars.env; set +a
   /root/omnitech-siem-setup/seal/graylog/regen_zone_lookup.sh
   ```
   (à mettre en cron nocturne, comme `regen_reev_lookup.sh`.)

Dès le CSV peuplé, `seal_zone` apparaît sur les nouveaux événements (les widgets et
`ZON-001` se remplissent). Pour re-décorer l'historique : non nécessaire au SOC
(l'analyse par zone porte sur le flux courant) ; sinon re-backfill Logstash.

## Gabarit en attendant la vue SQL (22/11/2026)

Constat : la table installée ne contient que son en-tête ; le plan des zones physiques
(rattachement de chaque porte à une zone) n'existe ni dans SEAL accessible au compte de
service ni dans le dépôt. ZON-001 est désactivée en production
(`tools/maj-detections-2026-11.py`) tant que la table est vide.

Pour avancer sans la vue `vw_SealZone_SIEM`, `seal/graylog/gabarit_zone_portes.py` liste en
lecture seule les portes vues dans OpenSearch, avec la même clé que la règle
(`seal_site:OBFI_ID`) :

```bash
python3 seal/graylog/gabarit_zone_portes.py gabarit --sortie /tmp/gabarit.csv \
        --existant seal/graylog/omni-seal-zone.gabarit.csv
# renseigner la colonne ZONE_PATH (ex. « Bâtiment A/Accueil »), puis :
python3 seal/graylog/gabarit_zone_portes.py table --gabarit /tmp/gabarit.csv --sortie /tmp/omni-seal-zone.csv
install -m 644 -o root -g graylog /tmp/omni-seal-zone.csv /etc/graylog/lookup/omni-seal-zone.csv
```

Le mode `table` ne garde que les portes dont la zone est renseignée. Instantané du
22/11/2026 : `seal/graylog/omni-seal-zone.gabarit.csv` (127 portes : 87 sur `bx-seal-omega`,
40 sur `bx-qa-seal-vm` ; libellés de porte vides dans la collecte). Une fois la table remplie,
replanifier ZON-001 dans Graylog (attention : `provision_detections.py --enable-parked`
réactive aussi EVT-002, parquée pour une autre raison).

## Découvrir les zones d'un autre parc

`event_domain:audit AND target_object_type:GroupeZone` (libellés de zones) et
`event_domain:access AND _exists_:target_object_id` (portes à rattacher).
