/* ============================================================================
   02_recon_topology.sql - RECON topologie SEAL : etablir OBFI_ID -> ZONE physique
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG
   >>> A LANCER SUR LES DEUX SEAL : QA (bx-qa-seal-vm) ET OMEGA (bx-seal-omega)

   OBJECTIF : trouver comment relier un objet physique (porte/camera, identifie
   par OBFI_ID dans les evenements) a sa ZONE, afin de peupler `seal_zone` dans
   le SIEM (les alertes d'acces designent aujourd'hui les portes par un numero).

   LECTURE SEULE : aucun DDL, aucun DML, aucune donnee modifiee.
   A executer par un compte ADMIN (le compte de service svc_graylog_seal n'a pas
   acces a la table de hierarchie).

   AUTO-DETECTION (v2, 16/07/2026) : ce script ne suppose plus AUCUN nom de
   schema, de table ni de colonne -- la v1 codait en dur
   Hypervision.ObjectsHierarchicalCatalog et echouait (severite 16) sur un SEAL
   dont la structure differe, alors que decouvrir cette structure est precisement
   son role. Chaque bloc est protege : une etape qui echoue affiche la raison et
   laisse les suivantes se derouler. Le script va TOUJOURS au bout.
   ============================================================================ */
USE [SEAL];
GO
SET NOCOUNT ON;

PRINT '';
PRINT '############################################################';
PRINT '#  RECON TOPOLOGIE SEAL                                    #';
PRINT '############################################################';

/* -- 0. Contexte : sur quel serveur / quelle base / quel compte -------------- */
PRINT '';
PRINT '=== 0. Contexte ===';
SELECT @@SERVERNAME AS serveur, DB_NAME() AS base_de_donnees,
       SUSER_SNAME() AS compte_connecte, CONVERT(varchar(19), GETDATE(), 120) AS date_recon;

/* -- 1. Tables candidates : par le NOM ---------------------------------------
      On ratisse large : selon les versions SEAL, la hierarchie peut s'appeler
      autrement que ObjectsHierarchicalCatalog. */
PRINT '';
PRINT '=== 1a. Tables candidates (par le nom) ===';
SELECT s.name AS schema_name, t.name AS table_name, SUM(p.rows) AS nb_lignes
FROM sys.tables t
JOIN sys.schemas s    ON s.schema_id = t.schema_id
JOIN sys.partitions p ON p.object_id = t.object_id AND p.index_id IN (0, 1)
WHERE t.name LIKE '%Hierarch%' OR t.name LIKE '%Catalog%' OR t.name LIKE '%Node%'
   OR t.name LIKE '%Zone%'     OR t.name LIKE '%Topolog%' OR t.name LIKE '%Tree%'
   OR t.name LIKE '%Arbre%'    OR t.name LIKE '%Groupe%'  OR t.name LIKE '%Secteur%'
   OR t.name LIKE '%Site%'
GROUP BY s.name, t.name
ORDER BY s.name, t.name;

/* -- 1b. Tables candidates : par la STRUCTURE (colonne de type parent) -------
      Une hierarchie se reconnait a sa colonne d'auto-reference. Plus fiable que
      le nom : c'est ce qui permettra de la trouver meme si elle s'appelle
      autrement que prevu. */
PRINT '';
PRINT '=== 1b. Tables ayant une colonne "parent" (signature d''une hierarchie) ===';
SELECT s.name AS schema_name, t.name AS table_name, c.name AS colonne_parent,
       SUM(p.rows) AS nb_lignes
FROM sys.columns c
JOIN sys.tables t     ON t.object_id = c.object_id
JOIN sys.schemas s    ON s.schema_id = t.schema_id
JOIN sys.partitions p ON p.object_id = t.object_id AND p.index_id IN (0, 1)
WHERE c.name LIKE '%Parent%'
GROUP BY s.name, t.name, c.name
ORDER BY s.name, t.name;

/* -- 1c. Ou vit OBFI_ID ? ---------------------------------------------------
      Toute table portant OBFI_ID est un pont potentiel objet <-> topologie. */
PRINT '';
PRINT '=== 1c. Tables portant une colonne OBFI_ID / OBJ_ID ===';
SELECT s.name AS schema_name, t.name AS table_name, c.name AS colonne,
       SUM(p.rows) AS nb_lignes
FROM sys.columns c
JOIN sys.tables t     ON t.object_id = c.object_id
JOIN sys.schemas s    ON s.schema_id = t.schema_id
JOIN sys.partitions p ON p.object_id = t.object_id AND p.index_id IN (0, 1)
WHERE c.name IN ('OBFI_ID', 'OBJ_ID')
GROUP BY s.name, t.name, c.name
ORDER BY s.name, t.name, c.name;

/* ===========================================================================
   RESOLUTION AUTOMATIQUE DE LA TABLE DE HIERARCHIE
   Priorite : le nom attendu ; a defaut, la 1re table auto-referencante trouvee.
   =========================================================================== */
DECLARE @sch sysname = NULL, @tbl sysname = NULL, @full nvarchar(300) = NULL;

SELECT TOP 1 @sch = s.name, @tbl = t.name
FROM sys.tables t JOIN sys.schemas s ON s.schema_id = t.schema_id
WHERE t.name = 'ObjectsHierarchicalCatalog';

IF @tbl IS NULL
    SELECT TOP 1 @sch = s.name, @tbl = t.name
    FROM sys.tables t
    JOIN sys.schemas s  ON s.schema_id = t.schema_id
    JOIN sys.columns c  ON c.object_id = t.object_id
    WHERE c.name LIKE '%Parent%'
      AND (t.name LIKE '%Hierarch%' OR t.name LIKE '%Catalog%' OR t.name LIKE '%Node%')
    ORDER BY t.name;

PRINT '';
PRINT '=== 2. Table de hierarchie retenue ===';
IF @tbl IS NULL
BEGIN
    PRINT '  AUCUNE table de hierarchie identifiee automatiquement sur ce SEAL.';
    PRINT '  -> Renvoyer les resultats des etapes 1a/1b/1c : la table sera';
    PRINT '     identifiee manuellement a partir de ces listes.';
END
ELSE
BEGIN
    SET @full = QUOTENAME(@sch) + N'.' + QUOTENAME(@tbl);
    PRINT '  Table retenue : ' + @full;

    /* -- 2b. Colonnes de la table retenue --------------------------------- */
    PRINT '';
    PRINT '=== 2b. Colonnes de la table de hierarchie ===';
    BEGIN TRY
        DECLARE @q1 nvarchar(max) = N'
            SELECT c.name AS colonne, ty.name AS type_sql, c.max_length, c.is_nullable
            FROM sys.columns c
            JOIN sys.types ty ON ty.user_type_id = c.user_type_id
            WHERE c.object_id = OBJECT_ID(@f)
            ORDER BY c.column_id;';
        EXEC sp_executesql @q1, N'@f nvarchar(300)', @f = @full;
    END TRY
    BEGIN CATCH
        PRINT '  [echec etape 2b] ' + ERROR_MESSAGE();
    END CATCH

    /* -- 3. Echantillon de noeuds ----------------------------------------- */
    PRINT '';
    PRINT '=== 3. Echantillon de noeuds (20 lignes) ===';
    BEGIN TRY
        EXEC(N'SELECT TOP (20) * FROM ' + @full + N';');
    END TRY
    BEGIN CATCH
        PRINT '  [echec etape 3] ' + ERROR_MESSAGE();
    END CATCH

    /* -- 4. Jointure candidate : la colonne "objet" vs OBFI_ID / OBJ_ID ----
          On detecte la colonne d'objet plutot que de supposer NodeObjectId. */
    DECLARE @colObj sysname = NULL;
    SELECT TOP 1 @colObj = c.name
    FROM sys.columns c
    WHERE c.object_id = OBJECT_ID(@full)
      AND (c.name LIKE '%ObjectId%' OR c.name LIKE '%Obfi%' OR c.name LIKE '%ObjId%')
    ORDER BY CASE WHEN c.name LIKE '%ObjectId%' THEN 0 ELSE 1 END, c.column_id;

    PRINT '';
    PRINT '=== 4. Correspondance de cle (quelle colonne relie la topologie aux objets ?) ===';
    IF @colObj IS NULL
        PRINT '  Aucune colonne d''objet evidente. Voir l''echantillon (etape 3).';
    ELSE
    BEGIN
        PRINT '  Colonne d''objet detectee : ' + @colObj;
        BEGIN TRY
            DECLARE @q2 nvarchar(max) = N'
                SELECT
                  (SELECT COUNT(*) FROM ' + @full + N' h
                     JOIN dbo.Objet_Fiche o ON o.OBFI_ID = h.' + QUOTENAME(@colObj) + N') AS match_vs_OBFI_ID,
                  (SELECT COUNT(*) FROM ' + @full + N' h
                     JOIN dbo.Objet_Fiche o ON o.OBJ_ID  = h.' + QUOTENAME(@colObj) + N') AS match_vs_OBJ_ID;';
            EXEC sp_executesql @q2;
            PRINT '  ATTENDU : la colonne gagnante est celle qui rapproche le PLUS d''objets.';
            PRINT '  Si les DEUX valent 0, la topologie ne se raccroche pas a Objet_Fiche';
            PRINT '  par cette colonne -> examiner l''echantillon de l''etape 3.';
        END TRY
        BEGIN CATCH
            PRINT '  [echec etape 4] ' + ERROR_MESSAGE();
        END CATCH
    END

    /* -- 5. Remontee hierarchique d'une porte reelle ------------------------
          Ne s'execute que si les colonnes necessaires existent vraiment. */
    DECLARE @colId sysname = NULL, @colParent sysname = NULL;
    SELECT TOP 1 @colId = c.name FROM sys.columns c
     WHERE c.object_id = OBJECT_ID(@full) AND c.name LIKE '%NodeId%' AND c.name NOT LIKE '%Parent%'
     ORDER BY c.column_id;
    IF @colId IS NULL
        SELECT TOP 1 @colId = c.name FROM sys.columns c
         WHERE c.object_id = OBJECT_ID(@full) AND c.name LIKE '%Id' AND c.name NOT LIKE '%Parent%'
         ORDER BY c.column_id;
    SELECT TOP 1 @colParent = c.name FROM sys.columns c
     WHERE c.object_id = OBJECT_ID(@full) AND c.name LIKE '%Parent%'
     ORDER BY c.column_id;

    PRINT '';
    PRINT '=== 5. Chaine ascendante d''un objet reel (recursif) ===';
    IF @colId IS NULL OR @colParent IS NULL OR @colObj IS NULL
        PRINT '  Colonnes cle/parent/objet non toutes identifiees -> etape ignoree (voir etape 3).';
    ELSE
    BEGIN
        PRINT '  Cle=' + @colId + '  Parent=' + @colParent + '  Objet=' + @colObj;
        BEGIN TRY
            /* OBFI_ID reellement present dans les evenements de CE site : on le
               prend dans la donnee plutot que de coder 285 en dur (qui n'existe
               pas forcement sur les deux SEAL). */
            DECLARE @obfi BIGINT = NULL;
            DECLARE @q3 nvarchar(max) = N'SELECT TOP 1 @o = h.' + QUOTENAME(@colObj) +
                N' FROM ' + @full + N' h JOIN dbo.Objet_Fiche o ON o.OBFI_ID = h.' +
                QUOTENAME(@colObj) + N' WHERE h.' + QUOTENAME(@colObj) + N' IS NOT NULL;';
            EXEC sp_executesql @q3, N'@o BIGINT OUTPUT', @o = @obfi OUTPUT;

            IF @obfi IS NULL
                PRINT '  Aucun objet de la topologie ne resout vers Objet_Fiche -> etape ignoree.';
            ELSE
            BEGIN
                PRINT '  Objet teste (OBFI_ID) : ' + CAST(@obfi AS varchar(32));
                DECLARE @q4 nvarchar(max) = N'
                    WITH chaine AS (
                        SELECT h.' + QUOTENAME(@colId)     + N' AS NodeId,
                               h.' + QUOTENAME(@colParent) + N' AS ParentNodeId,
                               h.' + QUOTENAME(@colObj)    + N' AS NodeObjectId, 0 AS niveau
                        FROM ' + @full + N' h
                        WHERE h.' + QUOTENAME(@colObj) + N' = @o
                        UNION ALL
                        SELECT p.' + QUOTENAME(@colId)     + N',
                               p.' + QUOTENAME(@colParent) + N',
                               p.' + QUOTENAME(@colObj)    + N', c.niveau + 1
                        FROM ' + @full + N' p
                        JOIN chaine c ON p.' + QUOTENAME(@colId) + N' = c.ParentNodeId
                    )
                    SELECT * FROM chaine ORDER BY niveau OPTION (MAXRECURSION 50);';
                EXEC sp_executesql @q4, N'@o BIGINT', @o = @obfi;
                PRINT '  ATTENDU : niveau 0 = l''objet ; en remontant, un noeud de type';
                PRINT '  zone/secteur. Croiser avec l''echantillon (etape 3) pour lire les';
                PRINT '  libelles et reperer la valeur de classe qui identifie une ZONE.';
            END
        END TRY
        BEGIN CATCH
            PRINT '  [echec etape 5] ' + ERROR_MESSAGE();
        END CATCH
    END
END

/* -- 6. RESULTAT A REPORTER -------------------------------------------------- */
PRINT '';
PRINT '=== 6. A RENVOYER (fixe la vue 03_vw_SealZone_SIEM.sql) ===';
PRINT '  (a) schema.table reel de la hierarchie                  -> etape 2';
PRINT '  (b) noms des colonnes cle / parent / objet / libelle / classe -> etapes 2b et 3';
PRINT '  (c) valeur de la classe identifiant une ZONE            -> etapes 3 et 5';
PRINT '  (d) quelle colonne relie la topologie aux objets        -> etape 4';
PRINT '';
PRINT '  Renvoyer simplement le fichier de sortie complet : il contient tout.';
PRINT '############################################################';
GO
