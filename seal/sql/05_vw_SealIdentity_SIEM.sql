/* ============================================================================
   05_vw_SealIdentity_SIEM.sql - Phase 1 SEAL : mapping badge -> identite (SIEM)
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG

   OBJET : table de correspondance badge -> matricule/site pour enrichissement
   cote SIEM (lookup Graylog regenere par cron). Pas d'evenement, pas de
   watermark (dimension de reference, D5).

   RGPD (CONTRACT D1) : milf.BADGES contient de la PII lourde. On n'expose ICI
   QUE : PHYSICAL_NUMBER, BADGE_NUMBER, MATRICULE, STATUS, USER_TYPE, COMPANY,
   SITE. JAMAIS : PHOTO, LAST_NAME, FIRST_NAME*, BIRTH_*, ADDRESS, CITY,
   ZIPCODE, NATIONALITY, SEX, MOTHER_*, FATHER_*, MAIDEN_*, PERSONNAL_PHONE,
   QR_CODE*.

   Idempotent : CREATE OR ALTER VIEW.
============================================================================ */
CREATE OR ALTER VIEW dbo.vw_SealIdentity_SIEM
AS
SELECT
    b.PHYSICAL_NUMBER AS badge_physical_number,
    b.BADGE_NUMBER    AS badge_number,
    b.MATRICULE       AS identity_matricule,
    b.STATUS          AS badge_status,
    b.USER_TYPE       AS user_type,
    b.COMPANY         AS company,
    b.SITE            AS site
FROM milf.BADGES b;
GO
