/* ============================================================================
   01_rowver_evenements.sql - Phase 1 SEAL : watermark natif sur EVENEMENTS
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG

   OBJET : ajouter une colonne rowversion a dbo.EVENEMENTS pour disposer d'un
   watermark monotone (motif Logstash D5). EVENEMENTS n'a PAS de rowversion
   natif (cf. RECON 9.4 / CONTRACT D2).

   !!! ATTENTION PROD !!!
   ADD <rowversion> materialise une valeur sur CHAQUE ligne : SQL Server
   REECRIT integralement la table (~961 k lignes). En PROD cela impose une
   FENETRE DE MAINTENANCE (verrou Sch-M + journalisation). En QA (~10^5-10^6
   lignes peu actives) l'operation est quasi instantanee.

   Idempotent : garde sur l'existence de la colonne (COL_LENGTH IS NULL).
   Aucun secret. Aucune donnee RGPD touchee (DDL de structure uniquement).
============================================================================ */
SET NOCOUNT ON;

IF COL_LENGTH('dbo.EVENEMENTS', 'EVEN_ROWVER') IS NULL
BEGIN
    PRINT 'ADD dbo.EVENEMENTS.EVEN_ROWVER (rowversion) - reecriture de table, ~961k lignes';
    ALTER TABLE dbo.EVENEMENTS ADD EVEN_ROWVER rowversion NOT NULL;
END
ELSE
    PRINT 'dbo.EVENEMENTS.EVEN_ROWVER deja present - rien a faire';
GO
