# Alerting/correlation audit of 2026-07-17 — remaining to be handled

This document lists what was NOT applied automatically, with, for each item, the
reason, the ready patch, and who must decide. The fixes already applied (in the repo, not
deployed) are in the session summary. Rollback snapshot:
`/root/siem-snapshot-2026-07-17-avant-correctifs`.

## Decision rule followed
- Applied outright: display/product tweaks to triage (same file already pending
  deployment, zero risk), emoji removal, dead patterns, score capping, correlation
  fields, parking of an inert detection.
- NOT applied: anything that (a) revives a detection (rules.yaml: same caution as
  F.1/F.2 — a signal that comes back to life can feed a correlation that escalates),
  (b) requires an action via the Graylog API (forbidden in autonomy: GET only),
  (c) requires data/a decision from Julien.

---

## A. Dead XDR signals — PATCH READY, DO NOT ship alone (rules.yaml)

These three signals reference an entity field that does not exist -> 0 entity produced ->
never triggered. Fixing them makes them live again. **Before shipping, verify what each
signal feeds as a correlation rule** (same lesson as F.1/F.2: do not arm a
detection without measuring the blast radius).

| Finding | File | Patch | Measurement |
|---|---|---|---|
| xdr-bruteforce-vpn-src-ip-vs-remip | oms-xdr/oms_xdr/rules.yaml:56-61 | `entity_field: src_ip` -> `remip` | 0 entity out of 58 docs |
| xdr-lateral-entity-user-vs-entity-user | rules.yaml:193-198 | `entity_field: user` -> `entity_user` | 0 entity out of 4 docs |
| xdr-portscan-fw-mauvais-stream | rules.yaml:31-36 | `stream: windows` -> `stream: ""` (internal) | 0 doc via its stream |

Same for F.1 (S_PSSCRIPTBLOCK) + F.2 (CR_EXECUTION_C2) already documented in the plan: to be
shipped together, under CISO decision.

## B. Actions requiring the Graylog API (operator/console)

- **regle-morte-incident**: remove the rule `event_source==incident` from the Internal
  stream and the rule `NOT event_source==incident` from the M365 stream (stream dead since
  02/07). The structural fix (Internal catch-all, LOT E) makes them useless.
- **"correlated kill-chain" def (F.3)**: the script is already fixed (commented out), but
  the live instance 6a2d2af7... stays ENABLED as long as the operator does not disable it via
  the API (ensure_event is early-skip). PUT state=DISABLED or delete.
- **m365-groupby-src-ip-jamais-peuple** (def 6a3aa906...): remove `src_ip` from the group_by
  (keep `[user]`); src_ip never populated on M365 -> bucket (Empty Value). Cosmetic.
- **seal-hyp007-actor-usercode-partiel** (def 6a575000...): 35% of docs without
  actor_usercode -> complete the SEAL pipeline mapping or also group on a present key.

## C. LOT E — event_source routing (RC-2), the active root cause

The leak (alert_triage -> omni-m365/365d) is structural: taxonomy as a DOUBLE list
(Internal OR 25 rules / M365 NOT 26 rules), which no mechanism keeps in sync. The fix
is ATOMIC and touches ingestion (risk R2): **it must not be done in autonomy**.

- E.1 Internal as catch-all (`AND input==GELF NOT m365 NOT forti_dhcp NOT seal`) — list of 52
  down to 3.
- E.2 M365 as positive (`AND input==GELF AND event_source==m365`) — measured harmlessness: 0 doc
  M365 without the field (0.000000%).
- E.3 Dashboard `84-dashboards-triage-site.sh:20-22` in the same deployment (otherwise KPIs at 0).
- E.4 Centralize in `lib-graylog.sh` (`ensure_event_source_routing()`) + single canonical
  list — **without E.4, the class will come back** (already fixed on 13/06, came back).

J+1 verification: `graylog_*/_count` ~= 8 (not thousands); omni-interne receives
alert_triage; omni-m365 no longer receives it; the 4 KPIs stay non-zero.
Decision: reindex the 85,458 docs already leaked or document the bound (rec.: document).

## D. CISO decisions (reminder)

Graylog upgrade to 7.1.5 (mongodump beforehand); accept the rise in mail volume (end of
silent suppressions); CR_EXECUTION_C2 (same-host join or removal); notify
xdr_incident critical (prerequisite: FP LSASS BX-WDSMDT-IT); enable ANTHROPIC_API_KEY
(governance, after redaction lock); full removal of
TRIAGE_FP_ENTITIES=src_ip=10.94.30.13.

## E. Lookups / doc / SEAL — to complete with data from Julien

- **net-segment-octet-10-absent-lookup**: add the VLAN 10 line to
  `lookups/net-segments.csv` — Julien must first qualify what VLAN 10 carries
  (27 docs/30d fall into an unlabeled segment).
- **seal ACC-004 / ALM-004 group_by**: group on a populated field (`seal_Number` for
  ACC-004, `REEV_CODE+seal_site` for ALM-004) — to be validated against both sites' data.
- **doc-acc007 / FAUX-POSITIFS.md**: re-measure and date the ACC-007 line (today's values:
  39 alerts / 26 badges over 7d).
- **guidance: missing entries** (volume_drop, ...) and **orphan** (kerberos_spray):
  lookup maintenance, non-blocking.
- **triage-gray-default-mort**: `OMNI_TRIAGE_GRAY_DEFAULT` is documented (38-alert-triage.sh)
  but not implemented. Decide: implement the variable, or remove the doc.

## F. Already handled this round (for the record)
Emoji guidance (siem_maintenance) and mail templates (13-graylog-alerts.sh); dead pattern 7045;
_msg_excerpt cap; score capped at 100; text/HTML parity (MITRE, "Received because", links);
_USER_FIELDS/_HOST_FIELDS (+entity_user/dark_host/cert_machine); FP button on NOISE escalation;
ZON-001 parked; honest response stubs (oms-xdr + oms-graph); F.3/F.5; version watch;
bare "credential" clause removed; graylog-server on apt-mark hold.
