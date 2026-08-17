/* ==========================================================================
   cleanup.sql — Purge des données synthétiques de recette (marqueur TEST_SIEM)
   OMNITECH SECURITY · MISSION_SEAL_GRAYLOG · base SEAL

   !!! QA UNIQUEMENT — NE JAMAIS EXÉCUTER EN PRODUCTION !!!
   ------------------------------------------------------------------------
   - Supprime UNIQUEMENT les lignes dont Usercode LIKE 'TEST_SIEM%'.
   - USE [SEAL] explicite + garde-fou QA + RETURN (mêmes corrections que inject).
   - N'agit PAS sur Graylog (messages déjà ingérés restent dans les index SEAL).

   Lancement : sqlcmd -S localhost -d SEAL -E -b -i cleanup.sql
   ========================================================================== */
USE [SEAL];
GO

SET NOCOUNT ON;

DECLARE @machine sysname = CAST(SERVERPROPERTY('MachineName') AS sysname);
IF (DB_NAME() <> N'SEAL') OR (@machine NOT LIKE N'BX-QA-SEAL%')
BEGIN
    RAISERROR(N'ABANDON: cible non-QA (machine=%s, db=%s). Script QA UNIQUEMENT.',
              16, 1, @machine, DB_NAME());
    RETURN;
END

PRINT N'== Purge TEST_SIEM — début ==';

DECLARE @t sysname, @sql nvarchar(400), @n int;

/* Toutes les tables Audit.* ayant une colonne Usercode : purge générique. */
DECLARE tbl CURSOR LOCAL FAST_FORWARD FOR
    SELECT N'Audit.' + QUOTENAME(t.name)
    FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id
    WHERE s.name = N'Audit'
      AND EXISTS (SELECT 1 FROM sys.columns c WHERE c.object_id = t.object_id AND c.name = N'Usercode');
OPEN tbl;
FETCH NEXT FROM tbl INTO @t;
WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        SET @sql = N'DELETE FROM ' + @t + N' WHERE Usercode LIKE N''TEST_SIEM%'';';
        EXEC sp_executesql @sql;
        SET @n = @@ROWCOUNT;
        IF @n > 0 PRINT N'[OK] ' + @t + N' : ' + CAST(@n AS nvarchar(10)) + N' ligne(s)';
    END TRY BEGIN CATCH PRINT N'[ERREUR] ' + @t + N' : ' + ERROR_MESSAGE(); END CATCH;
    FETCH NEXT FROM tbl INTO @t;
END
CLOSE tbl; DEALLOCATE tbl;

/* Alarme de test éventuelle (marqueur sur usercode/description anonymisée). */
BEGIN TRY
    DELETE FROM dbo.ALARMES
    WHERE PRIORITY_USERCODE LIKE N'TEST_SIEM%' OR AL_USER_DESCRIPTION_ANON LIKE N'TEST_SIEM%';
    IF @@ROWCOUNT > 0 PRINT N'[OK] dbo.ALARMES : marqueurs TEST_SIEM supprimés';
END TRY BEGIN CATCH PRINT N'[ERREUR] dbo.ALARMES : ' + ERROR_MESSAGE(); END CATCH;

PRINT N'== Purge TEST_SIEM — fin ==';
GO
