-- audit.sql — flux Audit.* (event_domain=hypervisor_audit)
-- Vue source : dbo.vw_SealAudit_SIEM (UNION ALL des 15 tables Audit.*,
--   watermark = CONVERT(BIGINT, RowVer) AS WatermarkBig — rowversion global à la base,
--   donc monotone et comparable entre tables : 1 seul watermark suffit).
-- Motif watermark SUR (CONTRACT D5) : borne haute = MIN_ACTIVE_ROWVERSION()
-- pour ne jamais lire une transaction encore ouverte (pas de trou, pas de doublon).
SELECT *
FROM dbo.vw_SealAudit_SIEM
WHERE WatermarkBig > :sql_last_value
  AND WatermarkBig < CONVERT(BIGINT, MIN_ACTIVE_ROWVERSION())
ORDER BY WatermarkBig ASC;
