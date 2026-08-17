/* ============================================================================
   06_recon_complements.sql - Les 3 questions qui restent (lecture seule)
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG
   >>> A LANCER SUR OMEGA (compte admin). QA en complement si utile.

   L'extraction du modele (05_) a repondu a l'essentiel et a INVALIDE trois
   hypotheses de la v1 du document. Il reste 3 questions, une requete chacune.
   Elles decident de la suite :
     1. le pont badge -> AD est-il immediat, ou faut-il d'abord peupler ?
     2. le cache de zones couvre-t-il le parc, ou faut-il passer par la hierarchie ?
     3. T_PASSAGES est-elle la piste courte (identite + zone d'un coup) ?

   AUCUNE donnee personnelle n'est lue : uniquement des COMPTAGES (COUNT), plus
   un echantillon de LIBELLES de zones (pas de personnes).
   Lecture seule, rejouable.

   Rediriger la sortie et me la renvoyer :
     sqlcmd -S localhost -d SEAL -E -i 06_recon_complements.sql -o complements.txt
   ============================================================================ */
USE [SEAL];
GO
SET NOCOUNT ON;

PRINT '';
PRINT '############################################################';
PRINT '#  COMPLEMENTS - 3 questions ouvertes                      #';
PRINT '############################################################';

/* -- Q1. Le pont badge -> AD ------------------------------------------------
   La colonne milf.BADGES.MATRICULE existe (443 badges). Est-elle REMPLIE ?
   ATTENDU : si avec_matricule est proche de badges_actifs, le pont est
   immediat (il suffit d'exposer le matricule dans la vue SIEM). S'il est
   proche de 0, la donnee est a peupler d'abord -> c'est alors, et seulement
   alors, un sujet de gouvernance. */
PRINT '';
PRINT '=== Q1. Remplissage du matricule (pont badge -> AD) ===';
BEGIN TRY
    SELECT 'milf.BADGES' AS source,
           COUNT(*)                    AS badges_total,
           COUNT(MATRICULE)            AS avec_matricule,
           COUNT(SEAL_ID)              AS relies_a_une_fiche,
           COUNT(BADGE_NUMBER)         AS avec_numero_badge,
           COUNT(PHYSICAL_NUMBER)      AS avec_numero_physique
    FROM milf.BADGES;

    /* meme mesure sur les seuls badges NON annules : c'est la population utile */
    SELECT 'milf.BADGES (non annules)' AS source,
           COUNT(*)         AS badges_actifs,
           COUNT(MATRICULE) AS avec_matricule,
           COUNT(SEAL_ID)   AS relies_a_une_fiche
    FROM milf.BADGES
    WHERE CANCELED IS NULL;

    /* le lien badge <-> fiche tient-il vraiment ? */
    SELECT 'jointure BADGES -> FICHE' AS controle,
           COUNT(*) AS badges_dont_le_SEAL_ID_resout
    FROM milf.BADGES b
    JOIN dbo.FICHE f ON f.FICH_ID = b.SEAL_ID;
END TRY
BEGIN CATCH
    PRINT '  [echec Q1] ' + ERROR_MESSAGE();
END CATCH

/* -- Q2. La couverture du cache de zones ------------------------------------
   POS_OBJECTS_IN_ZONES_CACHE (54 lignes) est le cache objet -> zone utilise par
   les plans SEAL. ATTENDU : le comparer aux 165 portes deployees. S'il couvre
   le parc, la vue de zone est triviale. Sinon il faudra passer par le
   hierarchyid (Hypervision.fn_GetObjectsCatalogPath). */
PRINT '';
PRINT '=== Q2. Couverture du cache objet -> zone ===';
BEGIN TRY
    SELECT 'POS_OBJECTS_IN_ZONES_CACHE' AS source,
           COUNT(*)                    AS associations,
           COUNT(DISTINCT SOURCE_ID)   AS objets_distincts,
           COUNT(DISTINCT TARGET_ID)   AS zones_distinctes
    FROM dbo.POS_OBJECTS_IN_ZONES_CACHE;

    /* combien de PORTES reelles sont rattachees a une zone ? (le chiffre qui compte) */
    SELECT 'portes rattachees a une zone' AS controle,
           COUNT(DISTINCT c.SOURCE_ID) AS portes_avec_zone
    FROM dbo.POS_OBJECTS_IN_ZONES_CACHE c
    JOIN dbo.Objet_Fiche obf ON obf.OBFI_ID = c.SOURCE_ID
    JOIN dbo.Objet o         ON o.OBJ_ID    = obf.OBJ_ID
    WHERE o.OBJ_LIBELLE LIKE '%orte%';

    /* a quoi ressemblent les zones ? (LIBELLES d'objets, pas de personnes) */
    PRINT '';
    PRINT '--- Echantillon : zones et leur libelle ---';
    SELECT TOP (30)
           c.TARGET_ID           AS zone_id,
           o.OBJ_LIBELLE         AS zone_type,
           obf.ContextualLabel   AS zone_libelle,
           COUNT(*)              AS nb_objets_dans_la_zone
    FROM dbo.POS_OBJECTS_IN_ZONES_CACHE c
    LEFT JOIN dbo.Objet_Fiche obf ON obf.OBFI_ID = c.TARGET_ID
    LEFT JOIN dbo.Objet o         ON o.OBJ_ID    = obf.OBJ_ID
    GROUP BY c.TARGET_ID, o.OBJ_LIBELLE, obf.ContextualLabel
    ORDER BY COUNT(*) DESC;
END TRY
BEGIN CATCH
    PRINT '  [echec Q2] ' + ERROR_MESSAGE();
END CATCH

/* -- Q2b. La hierarchie, via la fonction de l'editeur -----------------------
   ObjectsHierarchicalCatalog utilise un hierarchyid (pas de ParentNodeId).
   L'editeur fournit Hypervision.fn_GetObjectsCatalogPath : on la teste plutot
   que de reinventer la remontee d'arbre. */
PRINT '';
PRINT '=== Q2b. Catalogue hierarchique : contenu et fonction editeur ===';
BEGIN TRY
    SELECT TOP (30)
           NodeHierarchyId.ToString() AS chemin,
           NodeHierarchyId.GetLevel() AS niveau,
           NodeId, NodeObjectId, NodeObjectType
    FROM Hypervision.ObjectsHierarchicalCatalog
    ORDER BY NodeHierarchyId;

    SELECT 'types de noeuds' AS controle, NodeObjectType, COUNT(*) AS nb
    FROM Hypervision.ObjectsHierarchicalCatalog
    GROUP BY NodeObjectType ORDER BY COUNT(*) DESC;
END TRY
BEGIN CATCH
    PRINT '  [echec Q2b] ' + ERROR_MESSAGE();
END CATCH

/* signature de la fonction de chemin : dit comment l'appeler */
PRINT '';
PRINT '--- Parametres de Hypervision.fn_GetObjectsCatalogPath ---';
BEGIN TRY
    SELECT p.name AS parametre, ty.name AS type_sql, p.parameter_id AS ordre
    FROM sys.parameters p
    JOIN sys.types ty ON ty.user_type_id = p.user_type_id
    WHERE p.object_id = OBJECT_ID('Hypervision.fn_GetObjectsCatalogPath')
    ORDER BY p.parameter_id;
END TRY
BEGIN CATCH
    PRINT '  [echec] ' + ERROR_MESSAGE();
END CATCH

/* -- Q3. T_PASSAGES : la piste courte ---------------------------------------
   Cette table relie passage -> fiche -> zone -> sens. Si elle est bien remplie,
   elle resout d'un coup les DEUX manques (identite ET zone) et devient la
   meilleure source SIEM pour "qui est alle ou". */
PRINT '';
PRINT '=== Q3. T_PASSAGES : identite + zone deja resolues ? ===';
BEGIN TRY
    SELECT 'dbo.T_PASSAGES' AS source,
           COUNT(*)                            AS passages,
           COUNT(FICH_ID)                      AS avec_fiche,
           COUNT(NULLIF(NUM_PHYS,''))          AS avec_numero_badge,
           COUNT(ZONE_OBFI_ID)                 AS avec_zone,
           COUNT(NULLIF(ZONE_IN_OUT,''))       AS avec_sens,
           COUNT(EVEN_ID)                      AS relies_a_un_evenement,
           MIN(PASS_DATE_PASSAGE)              AS plus_ancien,
           MAX(PASS_DATE_PASSAGE)              AS plus_recent
    FROM dbo.T_PASSAGES;

    SELECT 'sens de passage' AS controle, ZONE_IN_OUT AS sens, COUNT(*) AS nb
    FROM dbo.T_PASSAGES GROUP BY ZONE_IN_OUT;

    /* la chaine complete tient-elle ? passage -> fiche -> badge -> matricule */
    SELECT 'chaine passage -> matricule' AS controle,
           COUNT(*)         AS passages_relies_a_une_fiche,
           COUNT(b.SEAL_ID) AS dont_relies_a_un_badge,
           COUNT(b.MATRICULE) AS dont_avec_matricule
    FROM dbo.T_PASSAGES p
    JOIN dbo.FICHE f      ON f.FICH_ID = p.FICH_ID
    LEFT JOIN milf.BADGES b ON b.SEAL_ID = f.FICH_ID;
END TRY
BEGIN CATCH
    PRINT '  [echec Q3] ' + ERROR_MESSAGE();
END CATCH

/* -- Q4. Verification du constat "aucune restriction horaire" ---------------
   Le modele ne montre que 2 semaines types. On confirme, et on regarde ce que
   les droits effectifs utilisent reellement. */
PRINT '';
PRINT '=== Q4. Semaines types reellement utilisees par les droits ===';
BEGIN TRY
    SELECT s.ID AS semaine_type_id, s.Libelle,
           (SELECT COUNT(*) FROM dbo.DROITS_ATOMIQUES_EFFECTIFS d
             WHERE d.SEM_TYPE_ID = s.ID) AS droits_effectifs_utilisant
    FROM dbo.SEMAINE_TYPE s ORDER BY s.ID;

    SELECT 'passes generaux actifs' AS controle,
           COUNT(*) AS droits_avec_maitre_cles
    FROM dbo.DROITS_ATOMIQUES_EFFECTIFS WHERE MAITRE_CLES = 1;

    SELECT 'derogations en vigueur' AS controle,
           SUM(CASE WHEN IMMUN_APB = 1 THEN 1 ELSE 0 END)    AS immunite_anti_passback,
           SUM(CASE WHEN IMMUN_APT = 1 THEN 1 ELSE 0 END)    AS immunite_anti_timeback,
           SUM(CASE WHEN IMMUN_DBLBDG = 1 THEN 1 ELSE 0 END) AS immunite_double_badge,
           SUM(CASE WHEN MODE_ESCORTE <> 0 THEN 1 ELSE 0 END) AS mode_escorte
    FROM dbo.DROITS_ATOMIQUES_EFFECTIFS;
END TRY
BEGIN CATCH
    PRINT '  [echec Q4] ' + ERROR_MESSAGE();
END CATCH

PRINT '';
PRINT '=== FIN - renvoyer ce fichier ===';
PRINT '############################################################';
GO
