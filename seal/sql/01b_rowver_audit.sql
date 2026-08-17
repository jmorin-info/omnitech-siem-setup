/* ============================================================================
   01b_rowver_audit.sql - Phase 1 SEAL : watermark natif sur les 15 tables Audit.*
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG

   OBJET : ajouter une colonne rowversion (RowVer) a chacune des 15 tables
   Audit.* pour alimenter vw_SealAudit_SIEM avec un watermark monotone.
   Aucune de ces tables n'a de rowversion natif (cf. RECON 9.4 / CONTRACT D2).
   rowversion est GLOBAL a la base : les valeurs RowVer des 15 tables partagent
   une seule sequence -> le UNION ALL de la vue reste monotone (motif D5).

   Ces tables sont petites -> ADD rowversion = INSTANTANE (pas de fenetre de
   maintenance requise, contrairement a EVENEMENTS cf. 01_).

   Idempotent : chaque ALTER est garde par COL_LENGTH(...) IS NULL.
   Aucun secret. DDL de structure uniquement.
============================================================================ */
SET NOCOUNT ON;

IF COL_LENGTH('Audit.AccessControlPermissionMovements', 'RowVer') IS NULL
    ALTER TABLE Audit.AccessControlPermissionMovements ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.AccountRolesMovements', 'RowVer') IS NULL
    ALTER TABLE Audit.AccountRolesMovements ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.AccountsMovements', 'RowVer') IS NULL
    ALTER TABLE Audit.AccountsMovements ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.CommandObject', 'RowVer') IS NULL
    ALTER TABLE Audit.CommandObject ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.LocalUnitMigrationMovements', 'RowVer') IS NULL
    ALTER TABLE Audit.LocalUnitMigrationMovements ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.LogDownload', 'RowVer') IS NULL
    ALTER TABLE Audit.LogDownload ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.ObjectDeclarationMovements', 'RowVer') IS NULL
    ALTER TABLE Audit.ObjectDeclarationMovements ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.ProfileAllowedSwitch', 'RowVer') IS NULL
    ALTER TABLE Audit.ProfileAllowedSwitch ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.ProfileAuthorizedObjectsMovements', 'RowVer') IS NULL
    ALTER TABLE Audit.ProfileAuthorizedObjectsMovements ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.ProfileRoleMovements', 'RowVer') IS NULL
    ALTER TABLE Audit.ProfileRoleMovements ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.ProfilesMovements', 'RowVer') IS NULL
    ALTER TABLE Audit.ProfilesMovements ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.TagGroupMembersMovements', 'RowVer') IS NULL
    ALTER TABLE Audit.TagGroupMembersMovements ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.TagGroupMovements', 'RowVer') IS NULL
    ALTER TABLE Audit.TagGroupMovements ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.TagMovements', 'RowVer') IS NULL
    ALTER TABLE Audit.TagMovements ADD RowVer rowversion NOT NULL;
GO
IF COL_LENGTH('Audit.UserConnections', 'RowVer') IS NULL
    ALTER TABLE Audit.UserConnections ADD RowVer rowversion NOT NULL;
GO
