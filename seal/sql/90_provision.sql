/* ============================================================================
   90_provision.sql - Phase 1 SEAL : droits du compte de service (moindre priv.)
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG

   OBJET : retirer la derogation temporaire db_datareader du compte de service
   svc_graylog_seal (accordee pour la recon Phase 0, RECON 9.6) et le restreindre
   au strict necessaire : SELECT sur les 4 vues vw_Seal*_SIEM UNIQUEMENT.
   Defense en profondeur : REVOKE explicite sur les tables de base sensibles.

   REGLES D'ENGAGEMENT :
   - Le LOGIN existe deja (cree hors de ce fichier) : on NE le recree PAS.
   - AUCUN mot de passe, AUCUN secret dans ce fichier.
   - Idempotent : DROP MEMBER garde ; GRANT/REVOKE rejouables sans effet de bord.

   PRE-REQUIS : executer d'abord 01_, 01b_, 02_..05_ (les vues doivent exister).

   NB CHAINE DE PROPRIETE (ownership chaining) : les vues sont en schema dbo et
   lisent milf.BADGES / Hypervision.ObjectsHierarchicalCatalog / Audit.* . Le
   GRANT SELECT sur les vues suffit SANS droit sur les tables de base UNIQUEMENT
   si ces schemas ont le meme proprietaire (dbo). A confirmer cote base ; sinon
   la chaine est rompue et il faudra un GRANT SELECT cible sur les tables lues.
============================================================================ */
SET NOCOUNT ON;

DECLARE @svc sysname = N'svc_graylog_seal';

/* -- 0. Garde-fou : le user de base doit exister (login cree en amont) ------ */
IF DATABASE_PRINCIPAL_ID(@svc) IS NULL
BEGIN
    RAISERROR('Utilisateur de base [%s] absent : creer le login/user avant provision.', 16, 1, @svc);
    RETURN;
END

/* -- 1. Retrait de la derogation large db_datareader (idempotent) ---------- */
IF IS_ROLEMEMBER('db_datareader', @svc) = 1
BEGIN
    PRINT 'DROP MEMBER svc_graylog_seal FROM db_datareader';
    ALTER ROLE db_datareader DROP MEMBER svc_graylog_seal;
END
ELSE
    PRINT 'svc_graylog_seal deja hors db_datareader';
GO

/* -- 2. GRANT SELECT sur les 5 vues SIEM UNIQUEMENT ------------------------- */
GRANT SELECT ON OBJECT::dbo.vw_SealEvents_SIEM   TO svc_graylog_seal;
GRANT SELECT ON OBJECT::dbo.vw_SealAlarms_SIEM   TO svc_graylog_seal;
GRANT SELECT ON OBJECT::dbo.vw_SealAudit_SIEM    TO svc_graylog_seal;
GRANT SELECT ON OBJECT::dbo.vw_SealIdentity_SIEM TO svc_graylog_seal;
GRANT SELECT ON OBJECT::dbo.vw_SealReev_SIEM     TO svc_graylog_seal;  /* decodage REEV (regen lookup, survit au verrouillage) */
GO

/* -- 3. REVOKE explicite sur les tables de base sensibles (defense en prof.) -
   Rejouable : si aucun droit direct n'existe, REVOKE est un no-op. */
REVOKE SELECT ON OBJECT::dbo.EVENEMENTS                    FROM svc_graylog_seal;
REVOKE SELECT ON OBJECT::dbo.ALARMES                       FROM svc_graylog_seal;
REVOKE SELECT ON OBJECT::dbo.Objet_Fiche                   FROM svc_graylog_seal;
REVOKE SELECT ON OBJECT::dbo.REF_EVENEMENT                 FROM svc_graylog_seal;
REVOKE SELECT ON OBJECT::milf.BADGES                       FROM svc_graylog_seal;
REVOKE SELECT ON OBJECT::dbo.UTILISATEUR                   FROM svc_graylog_seal;
REVOKE SELECT ON OBJECT::dbo.UTILISATEUR_PASSWORD_HISTORY  FROM svc_graylog_seal;
REVOKE SELECT ON OBJECT::dbo.DETAIL_FICHE                  FROM svc_graylog_seal;
REVOKE SELECT ON OBJECT::AcApi.TAG                         FROM svc_graylog_seal;
GO
