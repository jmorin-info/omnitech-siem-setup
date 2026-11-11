# SEAL physical zones — topological resolution

Objective: attach each event (access, alarm, audit) to the **physical zone**
of the object concerned (door, camera) to enable distribution and alerting
**per zone** — beyond the site alone.

## Current situation (verified on the real collection)

| Domain | `target_object_id` (OBFI_ID) present | Remark |
|---------|--------------------------------------|----------|
| access  | **99.4%** (976 k / 982 k) | the door = OBFI_ID → strong potential |
| alarm   | 0.65% (4.6 k / 713 k) | only *localized* alarms (intrusion, door) |
| audit   | 44 events | config operations on objects/zones |

- The `site` field of the views is **NULL**: the topological hierarchy
  (`ObjectsHierarchicalCatalog`, ~77 Door/Sensor/**ZoneGroup** nodes) is not
  joined. Recon showed that `NodeObjectId ≠ Objet_Fiche.OBJ_ID` (0 match).
- The **audit** domain already exposes objects of type `GroupeZone` and labels
  such as "Secteur Formation 1" → the notion of zone **exists** in SEAL; it remains to
  link each object to its zone via the hierarchy.
- The `svc_graylog_seal` service account **cannot** read the hierarchy
  table (locked to the views by `90_provision`) → establishing the link
  is an **operator step** (admin account).

## Chosen architecture

```
ObjectsHierarchicalCatalog  (SEAL hierarchy, admin)
        │  07_recon_topology.sql   → confirm NodeObjectId = OBFI_ID + ZONE class
        ▼
dbo.vw_SealZone_SIEM   (OBFI_ID → ZONE_LABEL / ZONE_PATH)     [07_, GRANT svc]
        │  regen_zone_lookup.sh    (multi-site, key seal_site:OBFI_ID)
        ▼
/etc/graylog/lookup/omni-seal-zone.csv   →  Graylog lookup  omni-seal-zone
        │  16-seal-zone.rule       (terminal stage of the 3 pipelines)
        ▼
seal_zone  set on the events  →  "per zone" widgets + detection ZON-001
```

**Composite key `seal_site:OBFI_ID`**: an OBFI_ID can collide between sites
(QA door 285 ≠ OMEGA door 285); the rule and the regen prefix by `seal_site`.

## What is ALREADY in place (SIEM, tested)

- Lookup `omni-seal-zone` (csvfile adapter + cache + table) — provisioned.
- Pipeline rule `16-seal-zone.rule` (terminal stage of the 3 pipelines) — compiles,
  **enrichment validated E2E** (injection of OBFI_ID 285 → `seal_zone` set via the
  composite key; normalization of the float `0.285e3` → `285` by `to_long`).
- Widgets "Access per zone" and "Denials per zone" (*Multi-site view* dashboard).
- Detection `ZON-001` (burst of denials concentrated in a zone).

All of this is **inert** as long as the CSV is empty: no `seal_zone` set, no
false positive. Activation only requires populating the CSV (operator steps).

## OPERATOR steps (admin SQL account)

1. **Recon**: run `seal/sql/07_recon_topology.sql`, note the 4 points of
   step 6 (real schema/table, column names, join `NodeObjectId = OBFI_ID`,
   value of `NodeClass` identifying a zone).
2. **View**: adjust `seal/sql/07_vw_SealZone_SIEM.sql` with these 4 points, then
   run it (creates `dbo.vw_SealZone_SIEM` + `GRANT SELECT` to the service). To be repeated
   on **each** SEAL (QA + OMEGA).
3. **Populate the lookup** (SIEM side):
   ```bash
   set -a; source /root/omnitech-siem-setup/00-vars.env; set +a
   /root/omnitech-siem-setup/seal/graylog/regen_zone_lookup.sh
   ```
   (to be put in a nightly cron, like `regen_reev_lookup.sh`.)

As soon as the CSV is populated, `seal_zone` appears on the new events (the widgets and
`ZON-001` fill up). To re-decorate history: not necessary for the SOC
(zone analysis concerns the current flow); otherwise re-backfill with Logstash.

## Discovering the zones of another site

`event_domain:audit AND target_object_type:GroupeZone` (zone labels) and
`event_domain:access AND _exists_:target_object_id` (doors to attach).
