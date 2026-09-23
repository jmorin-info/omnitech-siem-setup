/* ============================================================================
   00_recon_queries.sql - Phase 0 SEAL : reconnaissance LECTURE SEULE
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG (Phase 0)

   USAGE : a executer sur la base SEAL (VM QA bx-qa-seal-vm) avec un compte
   disposant d'un SELECT de decouverte (admin temporaire OU futur compte de
   service une fois cree). AUCUNE ecriture, AUCUN DDL. Pas de SELECT * massif :
   uniquement DISTINCT/COUNT/TOP echantillonnes.

   Objectif : decoder la semantique des codes (REEV_CODE, LIFESTAGE, Status...),
   etablir la chaine identite badge -> matricule -> UPN, mesurer la volumetrie.
   Les resultats alimentent seal/docs/RECON.md (a faire VALIDER par l'operateur
   avant d'ecrire la moindre regle de detection).
============================================================================ */
SET NOCOUNT ON;
SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;   /* ne pose aucun verrou */

/* -- 0.1  Edition / version / horloge serveur ------------------------------ */
SELECT SERVERPROPERTY('ProductVersion') AS version,
       SERVERPROPERTY('Edition')        AS edition,
       SYSUTCDATETIME()                 AS utc_now,
       SYSDATETIME()                    AS local_now;

/* -- 0.2  Referentiel des types d'evenement/alarme (code -> libelle ?) ----- */
SELECT s.name AS schema_name, t.name AS table_name
FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id
WHERE t.name LIKE '%REEV%' OR t.name LIKE '%EVENEMENT%'
   OR t.name LIKE '%TYPE%' OR t.name LIKE '%REFER%'
ORDER BY 1, 2;

/* -- 0.3  Semantique des codes (DISTINCT + COUNT, jamais de dump complet) --- */
SELECT EVEN_LIFESTAGE,      COUNT(*) AS n FROM dbo.EVENEMENTS GROUP BY EVEN_LIFESTAGE ORDER BY n DESC;
SELECT REACHED_LIFESTATUS,  COUNT(*) AS n FROM dbo.EVENEMENTS GROUP BY REACHED_LIFESTATUS ORDER BY n DESC;
SELECT EVEN_LIFESTATUS,     COUNT(*) AS n FROM dbo.ALARMES    GROUP BY EVEN_LIFESTATUS ORDER BY n DESC;
SELECT EVEN_DECLENCHEUR,    COUNT(*) AS n FROM dbo.ALARMES    GROUP BY EVEN_DECLENCHEUR ORDER BY n DESC;
SELECT TOP 100 REEV_CODE,   COUNT(*) AS n FROM dbo.ALARMES    GROUP BY REEV_CODE ORDER BY n DESC;
SELECT EVEN_SEVERITE,       COUNT(*) AS n FROM dbo.ALARMES    GROUP BY EVEN_SEVERITE ORDER BY n DESC;

/* -- 0.4  Correlation code -> sens : echantillon de descriptions par code --- */
;WITH codes AS (
  SELECT TOP 30 REEV_CODE, COUNT(*) n FROM dbo.ALARMES GROUP BY REEV_CODE ORDER BY n DESC
)
SELECT c.REEV_CODE, c.n,
       (SELECT TOP 5 e.EVEN_DESCRIPTION + ' | '
        FROM dbo.EVENEMENTS e JOIN dbo.ALARMES a ON a.EVEN_GROUP_ID = e.EVEN_GROUP_ID
        WHERE a.REEV_CODE = c.REEV_CODE
        FOR XML PATH('')) AS exemples_description
FROM codes c ORDER BY c.n DESC;

/* -- 0.5  Audit hyperviseur : Operation / Channel / Status de badge --------- */
SELECT Operation,        COUNT(*) n FROM Audit.UserConnections GROUP BY Operation        ORDER BY n DESC;
SELECT OperationChannel, COUNT(*) n FROM Audit.UserConnections GROUP BY OperationChannel ORDER BY n DESC;
SELECT [Status], StatusOld, COUNT(*) n FROM Audit.TagMovements GROUP BY [Status], StatusOld ORDER BY n DESC;

/* -- 0.6  Fuseau horaire : comparer heure evenement / stockage / serveur ---- */
SELECT TOP 20 EVEN_ID, EVEN_DATEHEURE, EVEN_STORAGE_TIMESTAMP,
       DATEDIFF(MINUTE, EVEN_DATEHEURE, EVEN_STORAGE_TIMESTAMP) AS delta_min
FROM dbo.EVENEMENTS
WHERE EVEN_DATEHEURE IS NOT NULL
ORDER BY EVEN_STORAGE_TIMESTAMP DESC;

/* -- 0.7  Chaine identite : catalogue des champs de fiche ------------------- */
SELECT s.name AS schema_name, t.name AS table_name
FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id
WHERE t.name LIKE '%CHAMP%' OR t.name LIKE '%CFIC%' OR t.name LIKE '%FICHE%'
   OR t.name LIKE '%TAG%'   OR t.name LIKE '%BADGE%'
ORDER BY 1, 2;
SELECT DISTINCT ATTRIBUT FROM dbo.SYNCHRO_LDAP_HISTORY ORDER BY ATTRIBUT;

/* -- 0.8  Chaine identite : resolution sur 20 badges reels (a adapter au ----
      catalogue de champs decouvert en 0.7 : jointure DETAIL_FICHE/CFIC) ----- */
/*  Gabarit a completer une fois le catalogue de champs localise :
    SELECT TOP 20 e.EVEN_PHYSICAL_NUMBER, u.UTI_CODE, df_matricule.valeur, df_upn.valeur
    FROM dbo.EVENEMENTS e
    JOIN <table_badge> b ON b.NUMBER = e.EVEN_PHYSICAL_NUMBER
    JOIN dbo.UTILISATEUR u ON u.FICH_ID = b.FICH_ID
    ...                                                                        */

/* -- 0.9  Volumetrie (calibrage schedule + seuils de detection) ------------- */
SELECT 'EVENEMENTS_24h' AS flux, COUNT(*) AS n
FROM dbo.EVENEMENTS WHERE EVEN_STORAGE_TIMESTAMP >= DATEADD(DAY,-1,SYSDATETIME())
UNION ALL
SELECT 'ALARMES_24h', COUNT(*)
FROM dbo.ALARMES WHERE ACK_EVEN_ID IS NOT NULL OR END_EVEN_ID IS NOT NULL;   /* proxy activite */

/* -- 0.10  Watermark natif : rowversion presence -------------------------- */
SELECT MIN_ACTIVE_ROWVERSION() AS min_active_rowversion;
SELECT t.name AS table_name, c.name AS col
FROM sys.columns c JOIN sys.tables t ON t.object_id = c.object_id
WHERE c.system_type_id = TYPE_ID('timestamp')     /* = rowversion */
ORDER BY 1;
/* ==========================================================================*/
