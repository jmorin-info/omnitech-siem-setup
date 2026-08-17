/* ==========================================================================
   inject_synthetic.sql — Injection de données SYNTHÉTIQUES de recette SIEM
   OMNITECH SECURITY · MISSION_SEAL_GRAYLOG · base SEAL

   !!! AVERTISSEMENT — QA UNIQUEMENT — NE JAMAIS EXÉCUTER EN PRODUCTION !!!
   ------------------------------------------------------------------------
   - Écrit dans les tables Audit.* de SEAL (marqueur TEST_SIEM, nettoyable).
   - Réservé à la VM QA `BX-QA-SEAL-VM`. Garde-fou en tête (abandon hors QA).
   - Idempotent : purge des marqueurs TEST_SIEM avant réinsertion.
   - Chaque scénario est isolé (TRY/CATCH) : si une table a une colonne
     NOT NULL non prévue ici, ce scénario échoue proprement sans bloquer les
     autres — le message d'erreur est imprimé.

   CORRECTIONS (15/07) :
   - `USE [SEAL]` explicite : garantit le bon contexte de base (sinon
     "Nom d'objet 'Audit.UserConnections' non valide" = erreur de COMPILATION
     si exécuté hors de la base SEAL, non rattrapable par TRY/CATCH).
   - Garde-fou et inserts dans UN SEUL batch (pas de GO au milieu) + RETURN :
     évite l'erreur "@machine doit être déclarée" (le GO coupait la portée)
     et la fragilité de SET NOEXEC.
   - TagMovements : colonne `StatusOld` (et non `OldStatus`).

   Lancement recommandé (sqlcmd, sur/vers la QA) :
     sqlcmd -S localhost -d SEAL -E -b -i inject_synthetic.sql
   ========================================================================== */
USE [SEAL];
GO

SET NOCOUNT ON;

/* -- Garde-fou + tous les scénarios dans un SEUL batch (variables en portée) -- */
DECLARE @machine sysname = CAST(SERVERPROPERTY('MachineName') AS sysname);
IF (DB_NAME() <> N'SEAL') OR (@machine NOT LIKE N'BX-QA-SEAL%')
BEGIN
    RAISERROR(N'ABANDON: cible non-QA (machine=%s, db=%s). Script QA UNIQUEMENT.',
              16, 1, @machine, DB_NAME());
    RETURN;   -- sort du batch : aucun INSERT ci-dessous n'est exécuté
END

PRINT N'== Injection TEST_SIEM sur QA — début ==';

DECLARE @nowUtc   datetime2(3) = SYSUTCDATETIME();
DECLARE @nowLocal datetime2(3) = SYSDATETIME();

/* -- Purge préalable (idempotence) : uniquement les marqueurs TEST_SIEM -- */
BEGIN TRY DELETE FROM Audit.UserConnections   WHERE Usercode LIKE N'TEST_SIEM%'; END TRY BEGIN CATCH PRINT N'[purge] UserConnections: '   + ERROR_MESSAGE(); END CATCH;
BEGIN TRY DELETE FROM Audit.AccountsMovements WHERE Usercode LIKE N'TEST_SIEM%'; END TRY BEGIN CATCH PRINT N'[purge] AccountsMovements: ' + ERROR_MESSAGE(); END CATCH;
BEGIN TRY DELETE FROM Audit.TagMovements      WHERE Usercode LIKE N'TEST_SIEM%'; END TRY BEGIN CATCH PRINT N'[purge] TagMovements: '      + ERROR_MESSAGE(); END CATCH;
BEGIN TRY DELETE FROM Audit.CommandObject     WHERE UserCode LIKE N'TEST_SIEM%'; END TRY BEGIN CATCH PRINT N'[purge] CommandObject: '     + ERROR_MESSAGE(); END CATCH;
BEGIN TRY DELETE FROM Audit.LogDownload       WHERE Usercode LIKE N'TEST_SIEM%'; END TRY BEGIN CATCH PRINT N'[purge] LogDownload: '       + ERROR_MESSAGE(); END CATCH;

/* -- SCÉNARIO 1 — HYP-001/002 : 5 ConnectionFailure puis 1 Connection -- */
BEGIN TRY
    DECLARE @i int = 1;
    WHILE @i <= 5
    BEGIN
        INSERT INTO Audit.UserConnections
            (Usercode, Operation, OperationChannel, OperationDateLocal, OperationDateUtc, Login, IpAddress, UserAgent)
        VALUES (N'TEST_SIEM_HYP001', N'ConnectionFailure', N'SealAdmin',
                DATEADD(SECOND, @i, @nowLocal), DATEADD(SECOND, @i, @nowUtc),
                N'test.siem', N'10.33.199.199', N'TEST_SIEM-agent');
        SET @i += 1;
    END
    INSERT INTO Audit.UserConnections
        (Usercode, Operation, OperationChannel, OperationDateLocal, OperationDateUtc, Login, IpAddress, UserAgent)
    VALUES (N'TEST_SIEM_HYP001', N'Connection', N'SealAdmin',
            DATEADD(SECOND, 6, @nowLocal), DATEADD(SECOND, 6, @nowUtc),
            N'test.siem', N'10.33.199.199', N'TEST_SIEM-agent');
    PRINT N'[OK] Scénario 1 UserConnections (5 échecs + 1 succès)';
END TRY BEGIN CATCH PRINT N'[ERREUR] Scénario 1 UserConnections: ' + ERROR_MESSAGE(); END CATCH;

/* -- SCÉNARIO 2 — Octroi de privilège admin (OldIsAdmin 0 -> 1) -- */
BEGIN TRY
    INSERT INTO Audit.AccountsMovements
        (Usercode, Operation, OperationChannel, OperationDateLocal, OperationDateUtc, Login, OldIsAdmin, NewIsAdmin)
    VALUES (N'TEST_SIEM_ADMIN', N'Update', N'SealAdmin',
            @nowLocal, @nowUtc, N'test.siem.operator', 0, 1);
    PRINT N'[OK] Scénario 2 AccountsMovements (OldIsAdmin 0->1)';
END TRY BEGIN CATCH PRINT N'[ERREUR] Scénario 2 AccountsMovements: ' + ERROR_MESSAGE(); END CATCH;

/* -- SCÉNARIO 3 — Réactivation de badge (StatusOld ANN -> Status VAL) ACC-004 -- */
BEGIN TRY
    INSERT INTO Audit.TagMovements
        (Usercode, Operation, OperationChannel, OperationDateLocal, OperationDateUtc, Number, Status, StatusOld)
    VALUES (N'TEST_SIEM_ACC004', N'Update', N'SealMillefeuille',
            @nowLocal, @nowUtc, N'TESTBADGE01', N'VAL', N'ANN');
    PRINT N'[OK] Scénario 3 TagMovements (ANN->VAL)';
END TRY BEGIN CATCH PRINT N'[ERREUR] Scénario 3 TagMovements: ' + ERROR_MESSAGE(); END CATCH;

/* -- SCÉNARIO 4 — Commande manuelle sur une porte de test (CommandObject) -- */
BEGIN TRY
    INSERT INTO Audit.CommandObject
        (UserCode, Operation, OperationChannel, OperationDateLocal, OperationDateUtc, ObjectId, ObjectLabel, ObjectType)
    VALUES (N'TEST_SIEM_CMD', N'ManualCommand', N'SEAL Exploitation',
            @nowLocal, @nowUtc, N'TEST_DOOR_01', N'PORTE-TEST-SIEM', N'Door');
    PRINT N'[OK] Scénario 4 CommandObject (porte)';
END TRY BEGIN CATCH PRINT N'[ERREUR] Scénario 4 CommandObject: ' + ERROR_MESSAGE(); END CATCH;

/* -- SCÉNARIO 5 — Export de journal (LogDownload) -- */
BEGIN TRY
    INSERT INTO Audit.LogDownload
        (Usercode, Operation, OperationChannel, OperationDateLocal, OperationDateUtc)
    VALUES (N'TEST_SIEM_LOGDL', N'Download', N'SealAdmin', @nowLocal, @nowUtc);
    PRINT N'[OK] Scénario 5 LogDownload';
END TRY BEGIN CATCH PRINT N'[ERREUR] Scénario 5 LogDownload: ' + ERROR_MESSAGE(); END CATCH;

PRINT N'== Injection TEST_SIEM sur QA — fin ==';
PRINT N'Vérifier dans Graylog : event_source:seal AND actor_usercode:TEST_SIEM*';
GO
