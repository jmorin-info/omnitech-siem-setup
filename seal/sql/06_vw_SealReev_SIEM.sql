/* ============================================================================
   06_vw_SealReev_SIEM.sql - Phase 1 SEAL : vue referentiel REEV (code -> libelle)
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG

   OBJET : exposer le referentiel de decodage des types d'evenement
   (dbo.REF_EVENEMENT) SOUS FORME DE VUE, afin que regen_reev_lookup.sh (qui
   regenere le CSV du lookup Graylog omni-seal-reev) puisse le lire APRES le
   verrouillage 90_provision.sql -- qui revoke l'acces direct aux tables de base.

   Sans cette vue, la chaine serait rompue : 90_provision REVOKE dbo.REF_EVENEMENT,
   mais regen lit cette table -> le decodage event_action tomberait en panne
   silencieuse (les mails/detections afficheraient le code brut SEMxxx).
   Conforme a la regle d'engagement 5 : le compte de service ne lit QUE des vues.

   Colonnes exposees : uniquement REEV_CODE + REEV_LIBELLE (aucune PII, aucun
   pattern de description en clair).

   Idempotent : CREATE OR ALTER VIEW.
============================================================================ */
CREATE OR ALTER VIEW dbo.vw_SealReev_SIEM
AS
SELECT
    CAST(REEV_CODE    AS varchar(32))  AS REEV_CODE,
    CAST(REEV_LIBELLE AS nvarchar(256)) AS REEV_LIBELLE
FROM dbo.REF_EVENEMENT;
GO
