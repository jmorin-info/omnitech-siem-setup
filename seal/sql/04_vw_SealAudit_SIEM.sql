/* ============================================================================
   04_vw_SealAudit_SIEM.sql - Phase 1 SEAL : vue d'audit hyperviseur -> SIEM
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG

   OBJET : UNION ALL homogene des 15 tables Audit.* (CONTRACT D2/D4).
   Chaque branche expose le socle commun + le detail heterogene serialise en
   JSON (seal_payload). Graylog extrait ensuite les champs specifiques
   (Login/IpAddress/UserAgent/DoorId/ObjectId/Number...) depuis seal_payload.

   - Heure : OperationDateUtc est DEJA en UTC (D0) -> utilisee telle quelle.
   - Watermark : CONVERT(BIGINT, RowVer) AS WatermarkBig. rowversion est GLOBAL
     a la base -> un seul compteur monotone pour tout le UNION ALL (D5).
   - Usercode : 3 tables nomment la colonne 'UserCode' (CommandObject,
     ProfileAuthorizedObjectsMovements, ProfileRoleMovements) ; SQL Server est
     insensible a la casse sur les identifiants -> a.Usercode fonctionne partout.
   - RGPD : ces tables d'audit ne portent pas de PII/mot de passe ; a.* est donc
     serialise sans exclusion (CONTRACT D1 : rien a retirer ici).
   - Types CAST uniformes pour garantir la compatibilite du UNION ALL.

   Idempotent : CREATE OR ALTER VIEW.
============================================================================ */
CREATE OR ALTER VIEW dbo.vw_SealAudit_SIEM
AS
SELECT
    CAST('seal'             AS varchar(16))  AS event_source,
    CAST('hypervisor_audit' AS varchar(32))  AS event_domain,
    CAST('AccessControlPermissionMovements' AS varchar(64)) AS SourceTable,
    CONVERT(BIGINT, a.RowVer)                AS WatermarkBig,
    CAST(a.Usercode         AS nvarchar(256)) AS Usercode,
    CAST(a.Operation        AS nvarchar(256)) AS Operation,
    CAST(a.OperationChannel AS nvarchar(256)) AS OperationChannel,
    /* hors plage ouvree (heure LOCALE OperationDateLocal ; 07h-19h = ouvre) */
    CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7
              OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true'
              ELSE 'false' END AS varchar(8)) AS off_hours,
    /* alias [timestamp] : OperationDateUtc est deja UTC (D0) ; nom aligne sur
       access/alarm pour le filtre date Logstash. */
    CAST(a.OperationDateUtc AS datetime2(3))  AS [timestamp],
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) AS PayloadJson
FROM Audit.AccessControlPermissionMovements a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('AccountRolesMovements' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.AccountRolesMovements a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('AccountsMovements' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.AccountsMovements a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('CommandObject' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.CommandObject a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('LocalUnitMigrationMovements' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    /* LocalUnitMigrationMovements est la SEULE table Audit.* sans OperationChannel */
    CAST(NULL AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.LocalUnitMigrationMovements a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('LogDownload' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.LogDownload a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('ObjectDeclarationMovements' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.ObjectDeclarationMovements a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('ProfileAllowedSwitch' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.ProfileAllowedSwitch a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('ProfileAuthorizedObjectsMovements' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.ProfileAuthorizedObjectsMovements a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('ProfileRoleMovements' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.ProfileRoleMovements a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('ProfilesMovements' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.ProfilesMovements a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('TagGroupMembersMovements' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.TagGroupMembersMovements a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('TagGroupMovements' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.TagGroupMovements a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('TagMovements' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.TagMovements a
UNION ALL
SELECT CAST('seal' AS varchar(16)), CAST('hypervisor_audit' AS varchar(32)),
    CAST('UserConnections' AS varchar(64)),
    CONVERT(BIGINT, a.RowVer),
    CAST(a.Usercode AS nvarchar(256)), CAST(a.Operation AS nvarchar(256)),
    CAST(a.OperationChannel AS nvarchar(256)), CAST(CASE WHEN DATEPART(HOUR, a.OperationDateLocal) < 7 OR DATEPART(HOUR, a.OperationDateLocal) >= 19 THEN 'true' ELSE 'false' END AS varchar(8)), CAST(a.OperationDateUtc AS datetime2(3)),
    (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM Audit.UserConnections a;
GO
