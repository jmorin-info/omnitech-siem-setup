/* ============================================================================
   02_vw_SealEvents_SIEM.sql - Phase 1 SEAL : vue d'exposition EVENEMENTS -> SIEM
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG

   OBJET : surface de lecture minimisee (RGPD) des evenements d'acces pour
   l'ingestion Logstash/Graylog. Champs alignes sur CONTRACT D4.

   - Heure metier convertie en UTC (CONTRACT D0 / RECON 9.1) :
       EVEN_DATEHEURE AT TIME ZONE 'Romance Standard Time' AT TIME ZONE 'UTC'.
   - Watermark : CONVERT(BIGINT, EVEN_ROWVER) AS WatermarkBig (motif D5).
   - RGPD (CONTRACT D1) : uniquement EVEN_USER_DESCRIPTION_ANON (jamais la
     description en clair) ; cote badge on n'expose QUE le MATRICULE via la
     jointure milf.BADGES (aucune PII : ni nom, ni photo, ni naissance...).
   - Decodage REEV : EVENEMENTS ne porte pas de REEV_CODE ; event_action des
     evenements d'acces est resolu cote SIEM (lookup) / porte par l'ALARME
     correlee (EVEN_GROUP_ID). Ici on expose la description brute anonymisee.

   Idempotent : CREATE OR ALTER VIEW.
============================================================================ */
CREATE OR ALTER VIEW dbo.vw_SealEvents_SIEM
AS
SELECT
    /* --- normalisation D4 --- */
    CAST('seal'   AS varchar(16)) AS event_source,
    CAST('access' AS varchar(32)) AS event_domain,
    /* heure metier -> UTC (gere l'heure d'ete via la timezone Windows) */
    CAST(e.EVEN_DATEHEURE AT TIME ZONE 'Romance Standard Time'
                          AT TIME ZONE 'UTC' AS datetime2(3)) AS [timestamp],
    /* --- cle de correlation (evenement <-> alarme) --- */
    e.EVEN_ID,
    e.EVEN_GROUP_ID,
    /* --- hors plage ouvree (heure LOCALE metier ; 07h-19h = ouvre) --- */
    CAST(CASE WHEN DATEPART(HOUR, e.EVEN_DATEHEURE) < 7
              OR DATEPART(HOUR, e.EVEN_DATEHEURE) >= 19 THEN 'true'
              ELSE 'false' END AS varchar(8)) AS off_hours,
    /* --- cycle de vie (decodage D3) --- */
    e.EVEN_LIFESTAGE,
    e.REACHED_LIFESTATUS,
    /* --- libelle brut anonymise (jamais EVEN_DESCRIPTION en clair, D1) --- */
    CAST(e.EVEN_USER_DESCRIPTION_ANON AS nvarchar(1024)) AS event_action_raw,
    /* --- type + issue decodes via l'ALARME correlee (EVEN_GROUP_ID) :
       EVENEMENTS porte le badge mais pas de REEV ; l'ALARME porte le REEV mais
       pas de badge. On rapproche les deux ici -> refus/grant par badge exploitable
       (EVT-001, ACC-006). --- */
    al.REEV_CODE,
    CAST(re.REEV_LIBELLE AS nvarchar(256)) AS event_action,
    CAST(CASE
        WHEN re.REEV_LIBELLE LIKE '%efus%'            THEN 'deny'
        WHEN re.REEV_LIBELLE LIKE 'Acc%s d%un usager%' THEN 'grant'
        ELSE 'na' END AS varchar(8)) AS event_outcome,
    /* --- identite : badge -> matricule (D4 / chaine RECON 9.3) --- */
    e.EVEN_PHYSICAL_NUMBER AS badge_number,
    e.EVEN_KEY_RING_SN     AS key_ring_sn,
    b.MATRICULE            AS identity_matricule,
    /* --- objet cible (porte/lecteur...) via Objet_Fiche --- */
    obf.OBFI_ID        AS target_object_id,
    obf.OBJ_ID         AS target_object_obj_id,
    obf.ContextualLabel AS target_object_label,
    obf.OBFI_CLASS     AS target_object_type,
    /* --- site : NON resolu (TODO). La recon a montre que
       ObjectsHierarchicalCatalog.NodeObjectId NE correspond PAS a Objet_Fiche.OBJ_ID
       (0 correspondance) : l'espace d'ID de la topologie (77 noeuds Porte/Capteur/
       GroupeZone) reste a mapper avec l'operateur avant de fiabiliser le site.
       On expose NULL plutot qu'une jointure fabriquee. target_object_label reste
       fiable (via Objet_Fiche). --- */
    CAST(NULL AS nvarchar(256)) AS site,
    /* --- watermark Logstash (D5) --- */
    CONVERT(BIGINT, e.EVEN_ROWVER) AS WatermarkBig
FROM dbo.EVENEMENTS e
/* LEFT JOIN : ~38% des evenements recents ont RAW_ORIGIN_OBFI_ID NULL (RECON) ;
   un JOIN interne perdrait ces evenements de securite. */
LEFT JOIN dbo.Objet_Fiche obf
     ON obf.OBFI_ID = e.RAW_ORIGIN_OBFI_ID
/* ALARME correlee -> REEV_CODE + libelle + outcome (grant/deny). */
LEFT JOIN dbo.ALARMES al
     ON al.EVEN_GROUP_ID = e.EVEN_GROUP_ID
LEFT JOIN dbo.REF_EVENEMENT re
     ON re.REEV_CODE = al.REEV_CODE
/* Enrichissement matricule ; LEFT pour ne pas perdre les evenements sans badge
   resolu (couverture ~76,5% en QA, RECON 9.3). AUCUNE PII exposee (D1). */
LEFT JOIN milf.BADGES b
     ON b.PHYSICAL_NUMBER = e.EVEN_PHYSICAL_NUMBER;
GO
