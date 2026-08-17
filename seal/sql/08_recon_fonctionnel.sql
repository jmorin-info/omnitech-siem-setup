/* ============================================================================
   05_recon_fonctionnel.sql - RECON du MODELE FONCTIONNEL SEAL (doc ISO 27001)
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG
   >>> A LANCER SUR UN SEUL SEAL (OMEGA de preference : c'est la production)

   OBJET : extraire la STRUCTURE de la base SEAL pour documenter le
   fonctionnement du controle d'acces (ISO 27001 : A.5.15 controle d'acces,
   A.5.16 gestion des identites, A.5.18 droits d'acces, A.7.1-7.4 securite
   physique).

   ---------------------------------------------------------------------------
   CONFIDENTIALITE - CE SCRIPT NE LIT AUCUNE DONNEE PERSONNELLE
   ---------------------------------------------------------------------------
   Il n'extrait que des METADONNEES (noms de tables, de colonnes, relations,
   volumes) et le CONTENU DES SEULES TABLES DE REFERENCE (libelles de codes,
   types, statuts) -- c'est-a-dire du parametrage, jamais des personnes.

   Il ne lit JAMAIS : noms/prenoms de porteurs, numeros de badge, photos,
   mots de passe, historiques d'acces. Les colonnes interdites par le contrat
   d'interface (UTI_PASSW, UTI_SEED, UTI_HASH_PASS, PASSWORD_HISTORY.*,
   DFIC_VAL_PHOTO) ne sont pas lues, et sont au contraire LISTEES a l'etape 7
   pour verifier qu'elles restent hors du perimetre SIEM.

   LECTURE SEULE : aucun DDL, aucun DML. Rejouable sans effet de bord.
   A executer par un compte ADMIN (le compte de service ne voit que 5 vues).

   SORTIE : rediriger vers un fichier et me le renvoyer.
     sqlcmd -S localhost -d SEAL -E -i 05_recon_fonctionnel.sql -o modele_SEAL.txt
   ou via le lanceur :  .\Run-SealFix.ps1 -Site OMEGA -ModeleFonctionnel
   ============================================================================ */
USE [SEAL];
GO
SET NOCOUNT ON;

PRINT '';
PRINT '############################################################';
PRINT '#  MODELE FONCTIONNEL SEAL - extraction pour documentation  #';
PRINT '#  METADONNEES UNIQUEMENT - aucune donnee personnelle       #';
PRINT '############################################################';

/* -- 0. Contexte ------------------------------------------------------------ */
PRINT '';
PRINT '=== 0. Contexte ===';
SELECT @@SERVERNAME AS serveur, DB_NAME() AS base, SUSER_SNAME() AS compte,
       CONVERT(varchar(19), GETDATE(), 120) AS date_extraction,
       (SELECT COUNT(*) FROM sys.tables) AS nb_tables,
       (SELECT COUNT(*) FROM sys.views) AS nb_vues;

/* -- 1. Inventaire des tables et volumes ------------------------------------
      Le volume revele l'usage : une table a 3 lignes est du parametrage, une
      table a 1 million est un journal. */
PRINT '';
PRINT '=== 1. Toutes les tables et leur volume ===';
SELECT s.name AS [schema], t.name AS [table], SUM(p.rows) AS nb_lignes
FROM sys.tables t
JOIN sys.schemas s    ON s.schema_id = t.schema_id
JOIN sys.partitions p ON p.object_id = t.object_id AND p.index_id IN (0, 1)
GROUP BY s.name, t.name
ORDER BY SUM(p.rows) DESC, s.name, t.name;

/* -- 2. Colonnes de toutes les tables ---------------------------------------
      C'est le dictionnaire de donnees : il dit ce que SEAL sait modeliser
      (validite d'un badge, immunite anti-pass-back, mode escorte, semaine
      type...). Noms de colonnes uniquement, aucune valeur. */
PRINT '';
PRINT '=== 2. Dictionnaire des colonnes (metadonnees, aucune valeur) ===';
SELECT s.name AS [schema], t.name AS [table], c.column_id AS ordre,
       c.name AS colonne, ty.name AS type_sql, c.max_length, c.is_nullable
FROM sys.columns c
JOIN sys.tables t  ON t.object_id = c.object_id
JOIN sys.schemas s ON s.schema_id = t.schema_id
JOIN sys.types ty  ON ty.user_type_id = c.user_type_id
ORDER BY s.name, t.name, c.column_id;

/* -- 3. Relations (cles etrangeres) -----------------------------------------
      LE point le plus important : les FK decrivent le MODELE. Elles disent
      qu'un badge appartient a un porteur, qu'une permission relie un badge a
      une porte et a une plage horaire, etc. C'est le squelette du controle
      d'acces. */
PRINT '';
PRINT '=== 3. Relations entre tables (cles etrangeres) = LE MODELE ===';
SELECT
    fk.name                        AS contrainte,
    sp.name + '.' + tp.name        AS table_source,
    cp.name                        AS colonne_source,
    sr.name + '.' + tr.name        AS table_cible,
    cr.name                        AS colonne_cible
FROM sys.foreign_keys fk
JOIN sys.foreign_key_columns fkc ON fkc.constraint_object_id = fk.object_id
JOIN sys.tables  tp ON tp.object_id = fk.parent_object_id
JOIN sys.schemas sp ON sp.schema_id = tp.schema_id
JOIN sys.columns cp ON cp.object_id = tp.object_id AND cp.column_id = fkc.parent_column_id
JOIN sys.tables  tr ON tr.object_id = fk.referenced_object_id
JOIN sys.schemas sr ON sr.schema_id = tr.schema_id
JOIN sys.columns cr ON cr.object_id = tr.object_id AND cr.column_id = fkc.referenced_column_id
ORDER BY sp.name, tp.name, fk.name;

/* -- 4. Cles primaires / index uniques --------------------------------------
      Identifie ce qui fait l'unicite d'un badge, d'une porte, d'un profil. */
PRINT '';
PRINT '=== 4. Cles primaires et unicites ===';
SELECT s.name AS [schema], t.name AS [table], i.name AS index_nom,
       i.is_primary_key AS est_cle_primaire, i.is_unique AS est_unique,
       STUFF((SELECT ', ' + c2.name
              FROM sys.index_columns ic2
              JOIN sys.columns c2 ON c2.object_id = ic2.object_id AND c2.column_id = ic2.column_id
              WHERE ic2.object_id = i.object_id AND ic2.index_id = i.index_id
              ORDER BY ic2.key_ordinal
              FOR XML PATH('')), 1, 2, '') AS colonnes
FROM sys.indexes i
JOIN sys.tables t  ON t.object_id = i.object_id
JOIN sys.schemas s ON s.schema_id = t.schema_id
WHERE i.is_primary_key = 1 OR i.is_unique = 1
ORDER BY s.name, t.name, i.name;

/* -- 5. Contenu des TABLES DE REFERENCE (parametrage, pas des personnes) ----
      Une table de reference = petite (< 500 lignes) et nommee REF_/TYPE_/...
      Son contenu EST la semantique du systeme : la liste des types d'evenements,
      des statuts de badge, des classes d'objets. Indispensable a la doc.
      Genere dynamiquement, chaque table isolee dans un TRY/CATCH. */
PRINT '';
PRINT '=== 5. Contenu des tables de reference (parametrage) ===';
DECLARE @sch sysname, @tbl sysname, @full nvarchar(300), @n bigint;
DECLARE cur_ref CURSOR LOCAL FAST_FORWARD FOR
    SELECT s.name, t.name, SUM(p.rows)
    FROM sys.tables t
    JOIN sys.schemas s    ON s.schema_id = t.schema_id
    JOIN sys.partitions p ON p.object_id = t.object_id AND p.index_id IN (0, 1)
    WHERE (t.name LIKE 'REF[_]%' OR t.name LIKE '%[_]TYPE%' OR t.name LIKE 'TYPE[_]%'
        OR t.name LIKE '%Status%'  OR t.name LIKE '%Statut%' OR t.name LIKE '%Class%'
        OR t.name LIKE '%Categor%' OR t.name LIKE '%Profil%' OR t.name LIKE '%Role%'
        OR t.name LIKE '%Reason%'  OR t.name LIKE '%Motif%'  OR t.name LIKE '%Etat%')
    GROUP BY s.name, t.name
    HAVING SUM(p.rows) BETWEEN 1 AND 500     /* petit = parametrage, jamais un journal */
    ORDER BY s.name, t.name;
OPEN cur_ref;
FETCH NEXT FROM cur_ref INTO @sch, @tbl, @n;
WHILE @@FETCH_STATUS = 0
BEGIN
    SET @full = QUOTENAME(@sch) + N'.' + QUOTENAME(@tbl);
    PRINT '';
    PRINT '--- ' + @full + '  (' + CAST(@n AS varchar(12)) + ' lignes) ---';
    BEGIN TRY
        EXEC(N'SELECT TOP (200) * FROM ' + @full + N';');
    END TRY
    BEGIN CATCH
        PRINT '  [non lisible] ' + ERROR_MESSAGE();
    END CATCH
    FETCH NEXT FROM cur_ref INTO @sch, @tbl, @n;
END
CLOSE cur_ref; DEALLOCATE cur_ref;

/* -- 6. Vues et procedures : la logique metier deja ecrite ------------------ */
PRINT '';
PRINT '=== 6. Vues et procedures stockees (noms seulement) ===';
SELECT s.name AS [schema], o.name AS objet,
       o.type_desc AS type, o.create_date, o.modify_date
FROM sys.objects o
JOIN sys.schemas s ON s.schema_id = o.schema_id
WHERE o.type IN ('V', 'P', 'FN', 'IF', 'TF')
ORDER BY o.type_desc, s.name, o.name;

/* -- 7. CONTROLE RGPD : ou vivent les donnees sensibles ---------------------
      On LISTE ces colonnes (sans jamais lire leur contenu) pour attester
      qu'elles restent hors du perimetre SIEM -- element de preuve ISO. */
PRINT '';
PRINT '=== 7. Colonnes sensibles reperees (LISTE, contenu JAMAIS lu) ===';
SELECT s.name AS [schema], t.name AS [table], c.name AS colonne, ty.name AS type_sql
FROM sys.columns c
JOIN sys.tables t  ON t.object_id = c.object_id
JOIN sys.schemas s ON s.schema_id = t.schema_id
JOIN sys.types ty  ON ty.user_type_id = c.user_type_id
WHERE c.name LIKE '%PASSW%'  OR c.name LIKE '%HASH%'   OR c.name LIKE '%SEED%'
   OR c.name LIKE '%PHOTO%'  OR c.name LIKE '%BIOMET%' OR c.name LIKE '%EMPREINTE%'
   OR c.name LIKE '%NOM%'    OR c.name LIKE '%PRENOM%' OR c.name LIKE '%Lastname%'
   OR c.name LIKE '%Firstname%' OR c.name LIKE '%MAIL%' OR c.name LIKE '%TEL%'
ORDER BY s.name, t.name, c.name;

/* -- 8. Comptes et droits sur la base (gouvernance des acces) --------------- */
PRINT '';
PRINT '=== 8. Comptes ayant acces a la base et leurs roles ===';
SELECT dp.name AS compte, dp.type_desc AS type_compte,
       ISNULL(r.name, '(aucun role)') AS role_base
FROM sys.database_principals dp
LEFT JOIN sys.database_role_members rm ON rm.member_principal_id = dp.principal_id
LEFT JOIN sys.database_principals r    ON r.principal_id = rm.role_principal_id
WHERE dp.type IN ('S', 'U', 'G') AND dp.name NOT LIKE '##%'
  AND dp.name NOT IN ('guest', 'INFORMATION_SCHEMA', 'sys')
ORDER BY dp.name;

PRINT '';
PRINT '=== FIN - renvoyer ce fichier complet ===';
PRINT '  Il ne contient que des metadonnees et du parametrage.';
PRINT '############################################################';
GO
