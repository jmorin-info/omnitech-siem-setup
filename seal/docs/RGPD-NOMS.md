# RGPD-NOMS.md — Named exposure of badge holders (opt-in per site)

Governance note. Technical authority: `CONTRACT.md` (D1 minimization).
Purpose of the present document: to frame the ONLY exception planned for D1, namely
adding the badge holder's surname/first name to the SIEM flow, via the
`dbo.vw_SealIdentity_Nominatif` view (`seal/sql/05b_vw_SealIdentity_Nominatif.sql`).

## 1. Default state: pseudonym, not name

By default, no SEAL view exposes a name. The identity is carried by the
`identity_matricule` (via `vw_SealIdentity_SIEM`), or even by the sole
`badge_number`. This is a MINIMIZATION choice: the SIEM can correlate and
alert without continuously storing who is physically behind each badge.
This mode remains the recommended one and requires no formality.

## 2. The risk to weigh carefully before enabling names

Adding the name to the access and alarm flow turns the SIEM into a NAMED
SURVEILLANCE database of employees' movements and schedules:

- high-risk processing (presence/movement data linked to identified
  persons, over the SEAL retention period: 12 to 24 months depending on
  the stream);
- a security purpose easily diverted into managerial monitoring if access
  is not compartmentalized;
- cumulative effect: correlated with the other SIEM sources, the name becomes
  cross-cutting tracking of the employee's activity.

This is why the named view is DELIVERED BUT DISABLED: its mere
presence in the repository does not activate it; it requires an explicit
deployment act AND an explicit GRANT, per site.

## 3. Proportionate alternative (recommended by default)

In most cases, the name is not needed continuously: it is needed
OCCASIONALLY, during an investigation. The proportionate approach is therefore:

- keep only the pseudonym (matricule / badge) in the SIEM;
- resolve `matricule -> name` ON DEMAND at the time of a legitimate
  investigation (targeted query on the directory / HR side or on the SEAL
  database side), by an authorized person and with traceability of the consultation;
- never materialize the name in the SIEM indices.

This path satisfies the investigation need while keeping the data store
minimized. It must be preferred as long as a recurring and documented need does
not justify permanent named storage.

## 4. Activation procedure, PER SITE

The choice is made naturally by SEAL: each server has its own views.
Enabling names on one site commits only that site; the others remain
pseudonymized. For a given site, enable ONLY after checking off the
entirety of the checklist below.

Activation checklist (site: __________, date: __________):

- [ ] DPIA (impact assessment) carried out for this processing and this site.
- [ ] Legal basis identified and documented (security purpose, proportionality,
      dedicated justified retention period).
- [ ] Formal DPO + CISO agreement (written record kept).
- [ ] Prior information of the works council and the employees concerned (posting /
      service memo / update of the register of processing activities).
- [ ] Access to the named dashboard / stream RESTRICTED to authorized persons only
      (dedicated role on the Graylog side, no standard analyst access).
- [ ] Logging of access to the named content enabled and reviewed
      periodically.
- [ ] Dedicated retention decided for the named data (as short as
      possible; do not inherit the flow's 12/24 months by default).
- [ ] Reversibility point planned (how to return to pseudonym mode).

Technical implementation once the checklist is validated:

1. Deploy `05b_vw_SealIdentity_Nominatif.sql` on THIS SEAL (in addition to, or in
   place of, `05_vw_SealIdentity_SIEM.sql`).
2. DELIBERATELY add read permission to the service account, e.g.:
   `GRANT SELECT ON OBJECT::dbo.vw_SealIdentity_Nominatif TO svc_graylog_seal;`
   (not set by `90_provision.sql`, which stays at the strict minimum by default).
3. On the SIEM side: map the `identity_name` field to a DEDICATED field, assign it
   to a dashboard/stream with restricted access, and DO NOT broadcast it in
   general triage alerts/emails.

## 5. Consistency with the CONTRACT

- `CONTRACT.md` D1 remains the default rule: the standard SIEM views
  do not expose names. The present document does not modify D1; it describes the
  only governed exception and how to activate it without extending it.
- The field added is named `identity_name`, consistent with the
  `identity_matricule` / `identity_upn` family of D4. Even in named mode, the scope
  remains bounded: only the usual name; all the other PII in
  `milf.BADGES` (PHOTO, BIRTH_*, ADDRESS, etc.) remain EXCLUDED.
- Disabled by default = the reference behavior. Activation is a
  traced governance event, reversible, and local to a site.
