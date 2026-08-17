/* ============================================================================
   05b_vw_SealIdentity_Nominatif.sql - VARIANTE NOMINATIVE (OPT-IN) de l'identite
   OMNITECH SECURITY - MISSION_SEAL_GRAYLOG

   =======================  AVERTISSEMENT - LIRE AVANT DEPLOIEMENT  =============
   VUE NOMINATIVE. Elle expose le NOM et le PRENOM des porteurs de badge
   (identity_name = FIRST_NAME + ' ' + LAST_NAME depuis milf.BADGES).

   CE FICHIER N'EST PAS DEPLOYE PAR DEFAUT. Il constitue une DEROGATION
   explicite a la minimisation RGPD posee dans CONTRACT D1 (qui EXCLUT
   LAST_NAME / FIRST_NAME* de toute vue SIEM). Coupler un nom a un flux de
   controle d'acces et d'alarmes revient a de la SURVEILLANCE NOMINATIVE des
   salaries : c'est un traitement a risque eleve qui exige une gouvernance
   prealable, PAS un simple deploiement technique.

   NE DEPLOYER QUE SI, POUR CE SEAL / CE SITE PRECIS :
     (a) le DPO a approuve (AIPD realisee, base legale documentee, information
         du CSE et des salaries faite) - cf. seal/docs/RGPD-NOMS.md ;
     (b) on a decide d'ajouter cette vue EN PLUS de vw_SealIdentity_SIEM
         (ou a sa place) sur CE serveur uniquement ;
     (c) cote SIEM : le mapping enrichit un champ identity_name DEDIE, et le
         dashboard / stream nominatif est a acces RESTREINT et journalise.

   Le choix se fait naturellement PAR SEAL : chaque serveur porte ses propres
   vues. Ne pas deployer ce fichier laisse le site en mode pseudonymise
   (matricule seul), qui reste le mode par defaut recommande.

   RGPD - PERIMETRE STRICT MEME EN NOMINATIF (CONTRACT D1) : on ajoute
   UNIQUEMENT le nom d'usage (FIRST_NAME + LAST_NAME). On continue de NE JAMAIS
   exposer : PHOTO, BIRTH_*, ADDRESS, CITY, ZIPCODE, NATIONALITY, SEX,
   MOTHER_*, FATHER_*, MAIDEN_*, PERSONNAL_PHONE, QR_CODE*.

   Pas de watermark (dimension de reference, comme 05_, cf. D5).
   Idempotent : CREATE OR ALTER VIEW.

   ACCES : cette vue n'est PAS accordee au compte de service par 90_provision.
   L'octroi (GRANT SELECT ... TO svc_graylog_seal) doit etre ajoute
   DELIBEREMENT et par site, une fois la condition (a) satisfaite. Tant que ce
   GRANT n'est pas pose, l'existence de la vue reste sans effet sur le flux SIEM.
============================================================================ */
CREATE OR ALTER VIEW dbo.vw_SealIdentity_Nominatif
AS
SELECT
    b.PHYSICAL_NUMBER AS badge_physical_number,
    b.BADGE_NUMBER    AS badge_number,
    b.MATRICULE       AS identity_matricule,
    /* Nom d'usage reconstitue, robuste aux NULL / espaces surnumeraires.
       NULLIF(...,'') => la ligne reste exploitable meme si un des deux champs
       est vide, sans produire un libelle bancal (' ' isole). */
    NULLIF(
        LTRIM(RTRIM(
            CONCAT(
                LTRIM(RTRIM(b.FIRST_NAME)),
                CASE
                    WHEN NULLIF(LTRIM(RTRIM(b.FIRST_NAME)), '') IS NOT NULL
                     AND NULLIF(LTRIM(RTRIM(b.LAST_NAME )), '') IS NOT NULL
                    THEN ' '
                    ELSE ''
                END,
                LTRIM(RTRIM(b.LAST_NAME))
            )
        )),
        ''
    )                 AS identity_name,
    b.STATUS          AS badge_status,
    b.USER_TYPE       AS user_type,
    b.COMPANY         AS company,
    b.SITE            AS site
FROM milf.BADGES b;
GO
