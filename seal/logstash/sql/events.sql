-- events.sql — flux EVENEMENTS (event_domain=access)
-- Vue source : dbo.vw_SealEvents_SIEM (watermark = CONVERT(BIGINT, EVEN_ROWVER) AS WatermarkBig)
-- Motif watermark SUR (CONTRACT D5) : borne haute = MIN_ACTIVE_ROWVERSION()
-- pour ne jamais lire une transaction encore ouverte (pas de trou, pas de doublon).
SELECT *
FROM dbo.vw_SealEvents_SIEM
WHERE WatermarkBig > :sql_last_value
  AND WatermarkBig < CONVERT(BIGINT, MIN_ACTIVE_ROWVERSION())
ORDER BY WatermarkBig ASC;
