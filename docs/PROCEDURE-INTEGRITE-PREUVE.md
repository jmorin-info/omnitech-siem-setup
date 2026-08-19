# Log integrity & evidentiary value — OMNITECH SIEM

> ISO/IEC 27001: A.8.15 (logging + **log protection**), A.8.2 (privileged access rights), A.5.28 (collection of evidence). · 2026-06-14

## Problem addressed
Graylog OSS has no native archiving (Enterprise) and an administrator can delete/alter indices (demonstrated: purge of 22.9 M docs). Without controls, the logs have no **evidentiary value**. We put in place OSS **tamper-evidence** + **least privilege**.

## Mechanism in place

### 1. Hash-chained + signed integrity ledger (`60-integrity.sh` → `/usr/local/sbin/omni-integrity`)
- **Daily (03:30)**: a *link* captures the state of the corpus (per index: `docs`, `bytes`, `uuid`; totals). Each link includes the **SHA-256 hash of the previous link** (chaining) and is **HMAC-SHA256 signed** with a root-only key (`/etc/graylog/omni-integrity.key`, chmod 600).
- **Off-SIEM**: the ledger `/var/lib/omni-integrity/chain.jsonl` is copied on each run to `//10.33.50.5/Public/SIEM/integrity/` → an insider who **opportunistically** erases/alters is **betrayed** by the divergence with the out-of-band copy. *(See "Limitations" for the case of the determined root who re-signs the chain — the mechanism does not cover this model.)*
- **Attestation**: each run emits an `event_source:siem_integrity` event into the SIEM itself (the SIEM attests to its own state).
- **Verification at any time**: `omni-integrity --verify` → recomputes all hashes, verifies the HMAC signature and the chaining. *Any* alteration (masked deletion, edit) **breaks the chain** (tested: falsifying a value ⇒ "CHAIN COMPROMISED").

**In case of investigation / audit**: run `omni-integrity --verify`, then compare `chain.jsonl` (SIEM) with the out-of-band SMB copy (they must be identical up to the last common link). A divergence or a broken chain = tampering to investigate.

### 2. Least privilege (preventive anti-tampering) — ISO A.8.2
- Graylog role **"OMNI - Analyste (lecture seule)"** created: read streams/searches/dashboards, **no admin or deletion rights**.
- **Policy**: SOC accounts use this role. The **admin** account (the only one able to delete indices/streams) is **break-glass**: exceptional use, traced (SIEM access logged), password in the vault, ideally MFA.

### 3. Encrypted out-of-band configuration backup (`30-backup-config.sh`)
- **AES-256** archive of the config (without the logs) pushed daily to the SMB share, bounded retention. Guarantees reconstruction (see `PRA-RECONSTRUCTION-SIEM.md`).

## Evidence extraction procedure (chain of custody)
To produce logs with evidentiary value (incident, legal request):
1. Delimit the search (Graylog or OpenSearch): period + criteria, **UTC timestamp**.
2. Export the result (CSV/JSON).
3. **Seal**: `sha256sum export.json > export.json.sha256` + note date/time, operator, reason.
4. Attach the integrity ledger extract (`omni-integrity --verify` + the link covering the period) attesting that the corpus was not altered over the interval.
5. Keep the whole set (export + hash + attestation) on controlled media; log the handover (who/when/to whom).

## Limitations & evolution
- **Threat model — assumed limitation (co-located key).** The HMAC key (`/etc/graylog/omni-integrity.key`) is on the **same VM**, readable by `root`. A **determined and malicious** SIEM administrator can therefore alter the indices, **recompute and re-sign** the entire `chain.jsonl` chain (and overwrite the SMB copy if they mount the share with the same account): `--verify` would go back to **green**. The out-of-band copy protects against **opportunistic erasure**, **not** against a root who re-signs. *Not to be oversold to the auditor.* **To cover this model**: externalize the root of trust — daily send of the **last timestamped hash** to a recipient **outside the SIEM root's control** (email/Teams, already available) and/or signature with a key held **out-of-band** (HSM, vault).
- The ledger proves the immutability of the corpus **state** (deletion/alteration **detectable** in the model above), not a bit-level immutability of the **content**. To go further: ship the logs to **WORM / S3 Object Lock** storage (immutable on the storage side) — a separate infra project.
- Entra ID currently **P1**: moving to **P2** enriches cloud detection (risk levels, riskyUsers) — see M365 coverage.

## Periodic controls (to be entered in the operations plan)
- **Weekly**: `omni-integrity --verify` (and comparison with the SMB copy).
- **Monthly**: review of Graylog accounts (who has admin?) + rotation of the HMAC key if compromise is suspected.
