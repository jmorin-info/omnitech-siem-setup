/* ============================================================================
   03_vw_SealAlarms_SIEM.sql - Phase 1 SEAL : vue d'exposition ALARMES -> SIEM
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG

   OBJET : surface de lecture des alarmes pour Logstash/Graylog (CONTRACT D4).

   ATTENTION colonnes ALARMES (D2) : PAS de EVEN_DATEHEURE. Les temps sont
   MIN_EVEN_DATEHEURE (heure metier, debut d'alarme) et MAX_EVEN_STORAGE_TIMESTAMP.
   -> timestamp = MIN_EVEN_DATEHEURE convertie en UTC (D0).

   - Watermark : CONVERT(BIGINT, VERSION) AS WatermarkBig (rowversion natif, D5).
     ALARMES re-emet VERSION a chaque UPDATE de cycle de vie -> flux de
     transitions exploitable (ALM-001/002).
   - Decodage : LEFT JOIN dbo.REF_EVENEMENT (REEV_CODE) -> REEV_LIBELLE
     (event_action). severity_num = EVEN_SEVERITE brut (D4 ; SEAL peu fiable,
     les detections s'appuient sur le code decode, cf. D0).
   - RGPD (D1) : uniquement AL_USER_DESCRIPTION_ANON.

   Idempotent : CREATE OR ALTER VIEW.
============================================================================ */
USE [SEAL];
GO
/* CREATE OR ALTER VIEW doit etre la 1re instruction de son batch -> le GO ci-dessus
   est necessaire (et protege d'une execution sur la mauvaise base depuis SSMS). */
CREATE OR ALTER VIEW dbo.vw_SealAlarms_SIEM
AS
SELECT
    /* --- normalisation D4 --- */
    CAST('seal'  AS varchar(16)) AS event_source,
    CAST('alarm' AS varchar(32)) AS event_domain,
    CAST(al.MIN_EVEN_DATEHEURE AT TIME ZONE 'Romance Standard Time'
                               AT TIME ZONE 'UTC' AS datetime2(3)) AS [timestamp],
    /* --- cle de correlation (alarme <-> evenements) --- */
    al.EVEN_GROUP_ID,
    /* --- code + libelle decode --- */
    al.REEV_CODE,
    CAST(re.REEV_LIBELLE AS nvarchar(256)) AS event_action,
    /* event_outcome derive du REEV decode (RECON : SEM120-133/21/426/546... =
       refus ; SEM138 = acces accorde). LIKE '%efus%' couvre Refus/refuse. */
    CAST(CASE
        WHEN re.REEV_LIBELLE LIKE '%efus%'            THEN 'deny'
        WHEN re.REEV_LIBELLE LIKE 'Acc%s d%un usager%' THEN 'grant'
        ELSE 'na' END AS varchar(8)) AS event_outcome,
    al.EVEN_SEVERITE AS severity_num,
    /* --- cycle de vie / declencheur (decodage D3) --- */
    al.EVEN_LIFESTATUS,
    al.EVEN_DECLENCHEUR AS trigger_code,
    /* --- acteur (usercode de priorisation, D4) --- */
    al.PRIORITY_USERCODE AS actor_usercode,
    /* --- libelle brut anonymise (jamais en clair, D1) --- */
    CAST(al.AL_USER_DESCRIPTION_ANON AS nvarchar(1024)) AS user_description_anon,
    /* --- qualificatifs alarme --- */
    /* PIEGE (constate 16/07/2026) : une colonne `bit` n'atteint JAMAIS Graylog.
       Logstash convertit bit -> booleen Ruby, et son output GELF n'emet pas les
       champs a `false` -> IS_INHIBITED (703 641 lignes, 100% renseignees) et
       IS_PRIORITY etaient ABSENTS de l'index (0 doc), rendant ALM-001
       (inhibition d'alarme, T1562.001) structurellement incapable de se
       declencher : un angle mort silencieux. Les colonnes varchar passent, elles
       (cf. off_hours, qui vaut la chaine 'true'/'false' et arrive correctement).
       -> on emet ces qualificatifs en TEXTE. NULL est preserve (champ absent =
       information reellement inconnue, et non un 'false' invente). */
    CAST(CASE WHEN al.IS_INHIBITED IS NULL THEN NULL
              WHEN al.IS_INHIBITED = 1     THEN 'true'
              ELSE 'false' END AS varchar(5)) AS IS_INHIBITED,
    al.IS_INTEMPESTIVE,   /* datetime (date de qualification), PAS un booleen */
    al.INTEMPESTIVE_COUNT,
    CAST(CASE WHEN al.IS_PRIORITY IS NULL THEN NULL
              WHEN al.IS_PRIORITY = 1     THEN 'true'
              ELSE 'false' END AS varchar(5)) AS IS_PRIORITY,
    al.ACK_EVEN_ID,
    al.END_EVEN_ID,
    /* --- objet cible via Objet_Fiche --- */
    obf.OBFI_ID         AS target_object_id,
    obf.OBJ_ID          AS target_object_obj_id,
    obf.ContextualLabel AS target_object_label,
    obf.OBFI_CLASS      AS target_object_type,
    /* --- site : NON resolu (TODO topologie, cf. 02 : NodeObjectId != OBJ_ID) --- */
    CAST(NULL AS nvarchar(256)) AS site,
    /* --- watermark Logstash (D5) --- */
    CONVERT(BIGINT, al.[VERSION]) AS WatermarkBig
FROM dbo.ALARMES al
/* LEFT JOIN : ne pas perdre d'alarme dont l'OBFI_ID ne resout pas. */
LEFT JOIN dbo.Objet_Fiche obf
     ON obf.OBFI_ID = al.OBFI_ID
LEFT JOIN dbo.REF_EVENEMENT re
     ON re.REEV_CODE = al.REEV_CODE;
GO
