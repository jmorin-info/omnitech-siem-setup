#!/usr/bin/env python3
# =============================================================================
#  provision_detections.py - Catalogue de detection v1 SEAL -> Graylog
#  OMNITECH SECURITY - IaC SIEM (repo omnitech-siem-setup)
#
#  Provisionne les "Aggregation event definitions" du catalogue v1
#  (seal/detections/catalog.md) sur Graylog Open 7.1.x, + une notification
#  Teams (webhook = notification HTTP portant une Adaptive Card).
#
#  Regles d'engagement (cf. seal/docs/CONTRACT.md) :
#    - QA UNIQUEMENT ; aucune ecriture SQL ici (Graylog seulement).
#    - AUCUN secret en clair : GRAYLOG_API_TOKEN / TEAMS_WEBHOOK_URL par
#      variables d'environnement, jamais litteral.
#    - DRY-RUN PAR DEFAUT : --apply requis pour toute ecriture.
#    - IDEMPOTENT : recherche par titre avant creation (create-or-update).
#    - Champs de requete = champs NORMALISES du CONTRACT D4 uniquement.
#    - Les dead-man switches (globaux DMS-001/002/003 + par site DMS-004..009,
#      multi-site) sont crees DESACTIVES (pas de schedule) : une regle d'absence
#      se declencherait immediatement a vide (faux positif permanent) tant que le
#      flux SEAL ne coule pas. Activation post-recette.
#
#  Dependances : stdlib uniquement (urllib/ssl/json/base64).
#
#  Usage :
#    export GRAYLOG_API_URL="https://bx-it-graylog-vm.omnitech.security:9000"
#    export GRAYLOG_API_TOKEN="<token compte de service Graylog>"
#    export TEAMS_WEBHOOK_URL="<webhook Teams Workflows>"
#    ./provision_detections.py                 # dry-run (plan, aucune ecriture)
#    ./provision_detections.py --apply         # applique
#    ./provision_detections.py --apply --enable-deadman   # + active les DMS
#                                                          # (UNIQUEMENT flux stable)
#  Variables optionnelles :
#    GRAYLOG_API_CA=/etc/graylog/certs/omnitech-rootca.crt   # verif TLS stricte
#    GRAYLOG_TLS_INSECURE=1                                   # desactive la verif (deconseille)
# =============================================================================
from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

# --- Constantes de mission (NON secretes) -----------------------------------
NOTIF_TITLE = "OMNI - SEAL Teams (Adaptive Card)"
# Notification de TRIAGE (webhook -> omni-alert-triage:8089), creee par
# 38-alert-triage.sh. Constat 16/07/2026 : les detections SEAL ne poussaient QUE
# vers Teams -> une intrusion physique (ALM-003, Critical) n'envoyait AUCUN mail,
# alors que la chaine de triage/mail existait deja pour toutes les autres sources.
# On la branche sur les detections Critical/High : le triage decide ensuite si
# l'alerte merite un mail (regles + score + correlation), donc pas de flood.
# Si la notification n'existe pas (38-alert-triage.sh non joue), on l'ignore
# proprement : les detections restent provisionnees avec Teams seul.
TRIAGE_NOTIF_TITLE = "OMNI - Triage (mail critique)"
TITLE_PREFIX = "OMNI - SEAL"          # prefixe de tous les titres de definitions

# Streams SEAL (CONTRACT D0) : titre -> prefixe d'index (info/diagnostic).
STREAMS = {
    "audit": "OMNI - SEAL Audit",
    "access": "OMNI - SEAL Accès",
    "alarm": "OMNI - SEAL Alarmes",
}

# Priorite Graylog : 1=LOW(info) 2=NORMAL 3=HIGH. Pas de niveau "critical"
# distinct cote Graylog Open -> Critical et High mappent sur 3 (le libelle exact
# reste dans le titre + severite du catalogue / carte Teams).
SEV_PRIORITY = {"Critical": 3, "High": 3, "Medium": 2, "Info": 1}
# Notification immediate (Adaptive Card Teams) pour Critical/High ; Medium/Info
# = digest (pas de push temps reel).
IMMEDIATE_SEV = {"Critical", "High"}


# =============================================================================
#  CATALOGUE v1 - source de verite (aligne sur catalog.md / REG_030_delta.csv)
#  cond : ("count_ge", N) | ("card_ge", field, N) | ("count_lt", N)
#  Toutes les requetes n'emploient QUE des champs normalises CONTRACT D4.
# =============================================================================
RULES: list[dict] = [
    # --- HYP : audit hyperviseur / consoles (stream Audit) -------------------
    dict(id="HYP-001", title="Brute force console (échecs d'authentification)",
         stream="audit", sev="High", tech="T1110", statut="actif",
         query="event_domain:hypervisor_audit AND event_action:ConnectionFailure",
         group_by=["actor_login"], cond=("count_ge", 5), within=10, every=1),
    dict(id="HYP-002", title="Brute force suivie d'un succès (même compte)",
         stream="audit", sev="High", tech="T1110/T1078", statut="[SEQ]-approx",
         query="event_domain:hypervisor_audit AND alert_tag:seal_bf_then_success",
         group_by=["actor_login"], cond=("count_ge", 1), within=15, every=1),
    dict(id="HYP-003", title="Connexion console d'administration (SealAdmin)",
         stream="audit", sev="Medium", tech="T1078", statut="actif",
         query="event_domain:hypervisor_audit AND event_action:Connection AND operation_channel:SealAdmin",
         group_by=["actor_usercode"], cond=("count_ge", 1), within=10, every=5),
    dict(id="HYP-004", title="Changement de profil en session (SwitchProfile)",
         stream="audit", sev="Medium", tech="T1078", statut="actif",
         query="event_domain:hypervisor_audit AND event_action:SwitchProfile",
         group_by=["actor_usercode"], cond=("count_ge", 1), within=10, every=5),
    dict(id="HYP-005", title="Connexion admin hors heures ouvrées",
         stream="audit", sev="High", tech="T1078", statut="[SEQ]-approx",
         query="event_domain:hypervisor_audit AND event_action:Connection AND operation_channel:SealAdmin AND off_hours:true",
         group_by=["actor_usercode"], cond=("count_ge", 1), within=15, every=5),
    dict(id="HYP-006", title="Export/téléchargement de journaux d'audit",
         stream="audit", sev="Medium", tech="T1005", statut="actif",
         query="event_domain:hypervisor_audit AND seal_source_table:LogDownload",
         group_by=["actor_usercode"], cond=("count_ge", 1), within=15, every=5),
    dict(id="HYP-007", title="Création/modification de compte ou de rôle",
         stream="audit", sev="High", tech="T1136/T1098", statut="actif",
         query="event_domain:hypervisor_audit AND seal_source_table:(AccountsMovements OR AccountRolesMovements OR ProfilesMovements)",
         group_by=["actor_usercode"], cond=("count_ge", 1), within=10, every=5),
    dict(id="HYP-008", title="Modification des autorisations de profil",
         stream="audit", sev="Medium", tech="T1098", statut="actif",
         query="event_domain:hypervisor_audit AND seal_source_table:(ProfileAuthorizedObjectsMovements OR ProfileAllowedSwitch OR ProfileRoleMovements)",
         group_by=["actor_usercode"], cond=("count_ge", 1), within=10, every=5),
    dict(id="HYP-009", title="Migration d'unité locale (reconfig contrôleur)",
         stream="audit", sev="Medium", tech="T1565", statut="actif",
         query="event_domain:hypervisor_audit AND seal_source_table:LocalUnitMigrationMovements",
         group_by=["actor_usercode"], cond=("count_ge", 1), within=15, every=5),
    dict(id="HYP-010", title="Modification d'objet physique (porte/commande)",
         stream="audit", sev="Medium", tech="T1565.001", statut="actif",
         query="event_domain:hypervisor_audit AND seal_source_table:(CommandObject OR ObjectDeclarationMovements)",
         group_by=["actor_usercode"], cond=("count_ge", 1), within=15, every=5),
    dict(id="HYP-011", title="Sessions simultanées multi-IP (même compte)",
         stream="audit", sev="Medium", tech="T1078", statut="[SEQ]-approx",
         query="event_domain:hypervisor_audit AND event_action:Connection",
         group_by=["actor_login"], cond=("card_ge", "src_ip", 2), within=10, every=5),
    # MULTI-SITE : un meme compte console qui se connecte aux DEUX sites SEAL
    # (bx-qa-seal-vm ET bx-seal-omega) dans une fenetre courte. Signal de compte
    # partage / mouvement lateral inter-sites. Medium/digest (peut etre legitime
    # pour un admin transverse ; a examiner, sans push Teams -> anti-flood).
    dict(id="HYP-012", title="Compte console actif sur plusieurs sites (multi-site)",
         stream="audit", sev="Medium", tech="T1078", statut="actif",
         query="event_domain:hypervisor_audit AND event_action:Connection",
         group_by=["actor_login"], cond=("card_ge", "seal_site", 2), within=30, every=10),

    # --- ACC : administration du controle d'acces / badges -------------------
    dict(id="ACC-001", title="Attribution d'un passe général (master key)",
         stream="audit", sev="High", tech="T1098/T1078", statut="actif",
         query='event_domain:hypervisor_audit AND seal_source_table:TagMovements AND seal_MasterKeys:true AND seal_MasterKeysOld:false',
         group_by=["actor_usercode", "target_object_label"], cond=("count_ge", 1), within=10, every=5),
    dict(id="ACC-002", title="Attribution en masse de droits d'accès",
         stream="audit", sev="Medium", tech="T1098", statut="actif",
         query="event_domain:hypervisor_audit AND seal_source_table:AccessControlPermissionMovements",
         group_by=["actor_usercode"], cond=("count_ge", 5), within=10, every=5),
    dict(id="ACC-003", title="Création de badge",
         stream="audit", sev="Info", tech="T1136", statut="actif",
         query='event_domain:hypervisor_audit AND seal_source_table:TagMovements AND seal_Status:PRE',
         group_by=["actor_usercode"], cond=("count_ge", 1), within=15, every=10),
    dict(id="ACC-004", title="Réactivation de badge (Status ANN vers VAL)",
         stream="audit", sev="High", tech="T1078", statut="actif",
         query='event_domain:hypervisor_audit AND seal_source_table:TagMovements AND seal_StatusOld:ANN AND seal_Status:VAL',
         group_by=["actor_usercode", "target_login"], cond=("count_ge", 1), within=10, every=5),
    # FP (16/07) : group_by target_object_label -> le champ n'est peuple qu'a 8,5%
    # cote vue (NULL sinon) => toutes les portes tombaient dans le meme bucket
    # "(Empty Value)" : 5 refus sur 5 portes DIFFERENTES declenchaient "refus
    # repetes sur UNE porte" (faux positif) et l'alerte ne disait pas ou. On
    # regroupe sur target_object_id (99,5% peuple) + seal_site (OBFI_ID collisionne
    # entre sites). Le libelle lisible revient via seal_zone (topologie, 07_).
    dict(id="ACC-006", title="Accès refusés répétés sur une porte",
         stream="access", sev="Medium", tech="T1110", statut="actif",
         query="event_domain:access AND event_outcome:deny",
         group_by=["seal_site", "target_object_id"], cond=("count_ge", 5), within=10, every=1),
    # FP (16/07) : idem + badge_number n'est peuple que sur les VRAIS evenements de
    # badge (8,4%) -> sans le garde _exists_, les evenements techniques hors-badge
    # remontaient sous une entite vide.
    dict(id="ACC-007", title="Accès accordé hors plage horaire",
         stream="access", sev="Medium", tech="T1078", statut="[SEQ]-approx",
         query="event_domain:access AND event_outcome:grant AND off_hours:true AND _exists_:badge_number",
         group_by=["seal_site", "badge_number", "target_object_id"], cond=("count_ge", 1), within=15, every=5),
    # ACC-008 : ajoutee le 18/07/2026 a la demande de Julien. Trou de couverture confirme par
    # l'audit : ACC-006 = refus REPETES toute heure (seuil >=5/porte), ACC-007 = ACCORDE hors
    # horaire. Un badge presente et REFUSE hors plage (badge revoque/inconnu tente la nuit ou le
    # week-end) ne declenchait NI l'un NI l'autre. Mesure : 130 refus hors horaire/30j, 100% sur
    # bx-seal-omega, badge_number peuple a 100% sur ces evenements. Groupe par badge : un MEME
    # badge refuse >=3 fois hors plage en 60 min = tentative persistante (pas un refus unique
    # benin). High -> mail sur PROD ; QA gate au triage garantit qu'un test QA ne maile jamais.
    dict(id="ACC-008", title="Badge refusé hors plage horaire (tentative persistante)",
         stream="access", sev="High", tech="T1078/physique", statut="actif",
         query="event_domain:access AND event_outcome:deny AND off_hours:true AND _exists_:badge_number",
         group_by=["seal_site", "badge_number"], cond=("count_ge", 3), within=60, every=15),
    # --- ZON : detection au niveau ZONE physique (seal_zone, pose par 16-seal-zone
    # des que la topologie est finalisee : 07_vw_SealZone_SIEM + regen_zone_lookup).
    # Complement zone-level d'ACC-006 (par porte) : une rafale de refus repartie sur
    # PLUSIEURS portes d'une meme zone (sondage de zone). Inerte tant que seal_zone
    # est absent -> pas de faux positif avant la finalisation topologie.
    # PARQUEE le 17/07/2026 (audit) : seal_zone n'est peuple que sur 1 document de test
    # (topologie des zones non resolue, cf 06_recon_complements). Le _exists_:seal_zone
    # rend la regle inerte, mais provisionnee "active" elle affiche vert a tort. On la
    # parque explicitement (convention du fichier) ; --enable-parked la reactivera le jour
    # ou la vue de zones sera livree et seal_zone peuple.
    dict(id="ZON-001", title="Rafale de refus d'acces dans une zone",
         stream="access", sev="Medium", tech="T1110/physique",
         statut="PARQUEE (seal_zone non peuple - topologie zones a resoudre)",
         query="event_domain:access AND event_outcome:deny AND _exists_:seal_zone",
         group_by=["seal_zone"], cond=("count_ge", 10), within=10, every=5, parked=True),

    # --- ALM : alarmes (stream Alarmes) --------------------------------------
    # CORRECTIF 16/07 (toute la famille) : le group_by portait sur
    # target_object_label, peuple a 0,6% seulement sur les alarmes -> bucket unique
    # "(Empty Value)" : TOUTES les portes des DEUX sites fusionnaient en une seule
    # alerte, sans lieu. On regroupe desormais sur trigger_code (100% peuple, et
    # LISIBLE : "ENTREE PRINCIPALE", "LECT COURSIVE R+1") + seal_site.
    #
    # ALM-001 : IS_INHIBITED est un `bit` cote SQL ; l'output GELF de Logstash
    # supprime les booleens `false` -> le champ n'atteint JAMAIS Graylog (0 doc) et
    # `IS_INHIBITED:true` ne pouvait pas matcher (detection MORTE, angle mort sur
    # T1562.001). /tmp/sql/01_fix_bit_columns.sql caste les bits en varchar cote vue
    # (comme off_hours, qui lui arrive bien). Requete tolerante aux deux formes.
    dict(id="ALM-001", title="Inhibition d'une alarme (IS_INHIBITED)",
         stream="alarm", sev="High", tech="T1562.001", statut="actif (requiert 01_fix_bit_columns.sql)",
         query='event_domain:alarm AND IS_INHIBITED:("true" OR "1")',
         group_by=["seal_site", "trigger_code"], cond=("count_ge", 1), within=10, every=5),
    dict(id="ALM-003", title="Intrusion physique (effraction porte/bouton panique)",
         stream="alarm", sev="Critical", tech="T1200/physique", statut="actif",
         query='event_domain:alarm AND event_action:("Effraction porte" OR "Déclencheur manuel percuté")',
         group_by=["seal_site", "trigger_code"], cond=("count_ge", 1), within=5, every=1),
    # ALM-004 : IS_INTEMPESTIVE n'est PAS un booleen mais un `datetime` (date de
    # qualification en intempestif) -> `:true` ne matchait jamais (detection MORTE).
    # La presence du champ EST le signal. Seuil 20/10min conserve (flood capteur).
    dict(id="ALM-004", title="Alarme intempestive/flood capteur",
         stream="alarm", sev="Medium", tech="T1499/T1562.001", statut="actif",
         query='event_domain:alarm AND _exists_:IS_INTEMPESTIVE',
         group_by=["seal_site", "trigger_code"], cond=("count_ge", 20), within=10, every=5),

    # --- SLA : alarmes severes NON TRAITEES au-dela du delai ------------------
    # Marqueurs emis par seal/sla/seal_sla_poller.py (alert_tag:seal_sla_breach).
    # Graylog Open ne sait pas exprimer "alarme ouverte SANS cloture" (anti-
    # jointure) ; le poller correle l'etat par groupe (dernier statut LIV, non
    # acquitte, age > SLA) et emet un marqueur -> ces detections notifient. Fenetre
    # tumbling (within==every) = 1 alerte par marqueur ; le poller deduplique deja
    # (1 marqueur / breche / escalade) donc pas de flood. Par site + par alarme.
    dict(id="SLA-001", title="Alarme CRITIQUE non traitee au-dela du SLA",
         stream="alarm", sev="Critical", tech="A.8.16/physique", statut="actif",
         query="event_domain:alarm AND alert_tag:seal_sla_breach AND sla_class:critical AND NOT _exists_:TEST_SIEM",
         group_by=["seal_site", "EVEN_GROUP_ID"], cond=("count_ge", 1), within=2, every=2),
    dict(id="SLA-002", title="Alarme severe non traitee au-dela du SLA",
         stream="alarm", sev="High", tech="A.8.16/physique", statut="actif",
         query="event_domain:alarm AND alert_tag:seal_sla_breach AND sla_class:high AND NOT _exists_:TEST_SIEM",
         group_by=["seal_site", "EVEN_GROUP_ID"], cond=("count_ge", 1), within=5, every=5),

    # --- EVT : evenements d'acces physique (stream Acces) --------------------
    dict(id="EVT-001", title="Accès usager accordé (base corrélation/chasse)",
         stream="access", sev="Info", tech="-", statut="actif",
         query="event_domain:access AND event_outcome:grant AND _exists_:badge_number",
         group_by=["seal_site", "badge_number"], cond=("count_ge", 1), within=5, every=5),
    # PARQUEE 16/07 (faux positif systematique, 76 alertes/7j sur 39 badges).
    # La regle dit "badge non enrole" mais mesure en realite le REMPLISSAGE du pont
    # badge->AD : identity_matricule n'est peuple que sur 87 lignes / 961 303 (0,009%)
    # cote QA. Tout badge legitime remonte donc "inconnu". Tant que SEAL ne porte pas
    # d'identifiant d'usager rattachable a l'AD (gouvernance de donnee, cf README),
    # la regle ne peut pas distinguer "badge pirate" de "referentiel vide" : on la
    # cree DESACTIVEE et on suit le trou de donnee par DQ-001 (1 alerte/jour/site).
    # Reactivation : provision_detections.py --apply --enable-parked, une fois le
    # pont peuple (verifier : _exists_:identity_matricule majoritaire sur les grants).
    dict(id="EVT-002", title="Badge inconnu/non enrôlé présenté",
         stream="access", sev="Medium", tech="T1078", statut="PARQUEE (pont badge->AD non peuple)",
         query="event_domain:access AND event_outcome:grant AND _exists_:badge_number "
               "AND NOT _exists_:identity_matricule",
         group_by=["seal_site", "badge_number"], cond=("count_ge", 1), within=10, every=5,
         parked=True),

    # --- DQ : qualite de donnee (angles morts de detection) -------------------
    # Remplace le bruit d'EVT-002 par UN signal quotidien et honnete : le pont
    # badge->AD est vide, donc toute detection d'identite physique est aveugle.
    # Fenetre tumbling 24h (within==every) = 1 alerte/jour/site, severite Info
    # (pas de push Teams) : c'est une dette de donnee, pas un incident.
    dict(id="DQ-001", title="Pont badge->AD non peuplé (détection d'identité aveugle)",
         stream="access", sev="Info", tech="-", statut="actif",
         query="event_domain:access AND event_outcome:grant AND _exists_:badge_number "
               "AND NOT _exists_:identity_matricule",
         group_by=["seal_site"], cond=("count_ge", 20), within=1440, every=1440),

    # --- Dead-man switches : crees DESACTIVES (go-dark : pas de group_by) -----
    # SEVERITE = Medium (et non High). Decision de tri 21/07/2026 (RSSI) : un
    # dead-man de flux est un signal de SANTE/disponibilite (A.8.16), pas un
    # signal de securite immediat -> il ne doit JAMAIS partir en mail. Medium le
    # sort de IMMEDIATE_SEV : meme active (--enable-deadman), il ne pousse ni mail
    # ni Teams temps reel, il reste visible dans /soc (digest). Cela empeche la
    # dette RC-7 de re-introduire le flood mail p3 a chaque re-run. L'etat LIVE du
    # tri (globaux DMS-001/002/003 = desactives ; QA acces/alarmes = desactives ;
    # QA audit + PROD audit/acces/alarmes = console/Teams sans mail) est applique
    # par tools/seal-alert-tri.sh, pas par ce provisionneur (qui les cree disabled).
    dict(id="DMS-001", title="Flux Audit interrompu (>15 min)",
         stream="audit", sev="Medium", tech="A.8.16", statut="désactivé (tri 21/07 : redondant DMS-004/005)",
         query="event_source:seal AND event_domain:hypervisor_audit",
         group_by=[], cond=("count_lt", 1), within=15, every=5, deadman=True),
    dict(id="DMS-002", title="Flux Accès interrompu (>15 min)",
         stream="access", sev="Medium", tech="A.8.16", statut="désactivé (tri 21/07 : redondant DMS-006/007)",
         query="event_source:seal AND event_domain:access",
         group_by=[], cond=("count_lt", 1), within=15, every=5, deadman=True),
    dict(id="DMS-003", title="Flux Alarmes interrompu (>15 min)",
         stream="alarm", sev="Medium", tech="A.8.16", statut="désactivé (tri 21/07 : redondant DMS-008/009)",
         query="event_source:seal AND event_domain:alarm",
         group_by=[], cond=("count_lt", 1), within=15, every=5, deadman=True),
]

# --- Dead-man switches PAR SITE (multi-site) : crees DESACTIVES ---------------
# DMS-001/002/003 surveillent l'arret d'un DOMAINE tous sites confondus : si UN
# seul site tombe alors que l'autre continue d'emettre, ils restent muets. Les
# variantes ci-dessous ajoutent un DMS par (domaine x site) pour detecter qu'un
# site precis se tait. Meme motif "go-dark" que les DMS globaux : aucun group_by,
# count() < 1 (une aggregation a vide sans group_by evalue bien count = 0).
# Crees DESACTIVES comme les DMS globaux (activation post-recette, flux stable).
# SEVERITE = Medium (cf. note des DMS globaux) : sante de flux, jamais de mail.
# Tri 21/07/2026 (etat LIVE applique par tools/seal-alert-tri.sh) :
#   QA (bx-qa-seal-vm) acces/alarmes (DMS-006/008) -> DESACTIVES (banc de test) ;
#   QA audit (DMS-004) + PROD (bx-seal-omega) audit/acces/alarmes (DMS-005/007/009)
#   -> CONSOLE (Teams + /soc, sans mail : go-dark PROD a valeur securite conservee).
# Ce provisionneur les cree disabled (deadman) ; le tri live regle schedule + mail.
SEAL_SITES = ["bx-qa-seal-vm", "bx-seal-omega"]
_DMS_SITE_DOMAINS = [
    ("audit", "hypervisor_audit", "Audit"),
    ("access", "access", "Accès"),
    ("alarm", "alarm", "Alarmes"),
]
# Cible de tri par (domaine, site) : "console" (garde, sans mail) ou "desactiver".
_DMS_SITE_TRI = {
    ("audit", "bx-qa-seal-vm"): "console",     ("audit", "bx-seal-omega"): "console",
    ("access", "bx-qa-seal-vm"): "desactiver", ("access", "bx-seal-omega"): "console",
    ("alarm", "bx-qa-seal-vm"): "desactiver",  ("alarm", "bx-seal-omega"): "console",
}
_dms_site_seq = 4
for _stream, _domain, _label in _DMS_SITE_DOMAINS:
    for _site in SEAL_SITES:
        _tri = _DMS_SITE_TRI[(_stream, _site)]
        RULES.append(dict(
            id=f"DMS-{_dms_site_seq:03d}",
            title=f"Flux {_label} interrompu sur site {_site} (>15 min)",
            stream=_stream, sev="Medium", tech="A.8.16",
            statut=f"désactivé (recette) - tri 21/07 : {_tri} ({_site})",
            query=f'event_source:seal AND event_domain:{_domain} AND seal_site:"{_site}"',
            group_by=[], cond=("count_lt", 1), within=15, every=5, deadman=True))
        _dms_site_seq += 1

# NB : ACC-005, ALM-002, XCO-001/002/003 sont [SEQ]-v2 (correlation multi-stream,
# service oms-xdr) -> catalogues (catalog.md / REG_030_delta.csv) mais NON
# provisionnes ici. Voir catalog.md section 5.


def full_title(rule: dict) -> str:
    return f"{TITLE_PREFIX} {rule['id']} - {rule['title']}"


# --- Series / conditions (schema aggregation-v1, cf. 13-graylog-alerts.sh) ----
def build_series_conditions(cond: tuple):
    kind = cond[0]
    if kind == "count_ge":
        series = [{"id": "count()", "type": "count"}]
        expr = {"expr": ">=", "left": {"expr": "number-ref", "ref": "count()"},
                "right": {"expr": "number", "value": cond[1]}}
    elif kind == "count_lt":
        series = [{"id": "count()", "type": "count"}]
        expr = {"expr": "<", "left": {"expr": "number-ref", "ref": "count()"},
                "right": {"expr": "number", "value": cond[1]}}
    elif kind == "card_ge":
        field = cond[1]
        series = [{"id": f"card({field})", "type": "card", "field": field}]
        expr = {"expr": ">=", "left": {"expr": "number-ref", "ref": f"card({field})"},
                "right": {"expr": "number", "value": cond[2]}}
    else:
        raise ValueError(f"condition inconnue : {cond}")
    return series, {"expression": expr}


def build_definition(rule: dict, stream_id: str, notif_id: str | None,
                     triage_id: str | None = None) -> dict:
    series, conditions = build_series_conditions(rule["cond"])
    # MULTI-SITE : agreger PAR SITE. Sans seal_site dans le group_by, une rafale
    # (ex. deny>=5/porte) melangerait QA et OMEGA (collision de libelles + seuils
    # a cheval). On l'ajoute a tout group_by non vide (les dead-man switches ont un
    # group_by vide -> non concernes, ils filtrent deja par site dans la requete).
    gb = list(rule["group_by"])
    if gb and "seal_site" not in gb:
        gb = gb + ["seal_site"]
    within_ms = rule["within"] * 60000
    every = max(rule["every"], rule["within"]) if rule["every"] < rule["within"] else rule["every"]
    every_ms = every * 60000
    grace_ms = 15 * 60000 if rule.get("deadman") else 10 * 60000
    field_spec = {
        f: {"data_type": "string",
            "providers": [{"type": "template-v1", "template": "${source." + f + "}",
                           "require_values": False}]}
        for f in gb
    }
    notifications = []
    if rule["sev"] in IMMEDIATE_SEV:
        for nid in (notif_id, triage_id):
            if nid:
                notifications.append({"notification_id": nid, "notification_parameters": None})
    return {
        "title": full_title(rule),
        "description": f"{rule['id']} [{rule['sev']}] {rule['tech']} - {rule['statut']} "
                       f"- provisionne par seal/detections/provision_detections.py",
        "priority": SEV_PRIORITY[rule["sev"]],
        "alert": True,
        "config": {
            "type": "aggregation-v1",
            "query": rule["query"],
            "query_parameters": [],
            "streams": [stream_id],
            "group_by": gb,
            "series": series,
            "conditions": conditions,
            "search_within_ms": within_ms,
            "execute_every_ms": every_ms,
            "use_cron_scheduling": False,
            "event_limit": 100,
        },
        "field_spec": field_spec,
        "key_spec": gb,
        "notification_settings": {"grace_period_ms": grace_ms, "backlog_size": 5},
        "notifications": notifications,
    }


# --- Adaptive Card Teams (notification HTTP -> webhook) ----------------------
# Card renseignant : regle, severite (priorite), acteur/objet (event.key +
# backlog), et lien Graylog (replay_info). Templating Graylog (${...}).
def build_teams_card() -> str:
    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "msteams": {"width": "Full"},
        "body": [
            {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "color": "Attention",
             "text": "SEAL / SIEM OMNITECH - ${event_definition_title}"},
            {"type": "FactSet", "facts": [
                {"title": "Règle", "value": "${event_definition_title}"},
                {"title": "Sévérité", "value": "priorité ${event.priority} (1=info 2=haute 3=critique)"},
                {"title": "Contexte", "value": "${event_definition_description}"},
                {"title": "Quand", "value": "${event.timestamp} (UTC)"},
                {"title": "Acteur / Objet", "value": "${event.key}"},
                {"title": "Déclencheur", "value": "${event.message}"},
            ]},
            {"type": "TextBlock", "wrap": True, "isSubtle": True, "spacing": "Medium",
             "text": "${if backlog}${foreach backlog message}- ${message.timestamp} | "
                     "site:${message.fields.seal_site} | "
                     "acteur:${message.fields.actor_login}${message.fields.actor_usercode} | "
                     "badge:${message.fields.badge_number} | objet:${message.fields.target_object_label}"
                     "${message.fields.door_id} | action:${message.fields.event_action} | "
                     "issue:${message.fields.event_outcome} | ip:${message.fields.src_ip}\\n"
                     "${end}${end}"},
            {"type": "ActionSet", "actions": [
                {"type": "Action.OpenUrl", "title": "Ouvrir dans Graylog",
                 "url": "${event.replay_info.query}"}]},
        ],
    }
    return json.dumps(card, ensure_ascii=False)


# =============================================================================
#  Client Graylog (stdlib, token auth base64(token:token))
# =============================================================================
class Graylog:
    def __init__(self, base_url: str, authz: str) -> None:
        self.base = base_url.rstrip("/") + "/api"
        self.auth = authz
        ca = os.environ.get("GRAYLOG_API_CA", "/etc/graylog/certs/omnitech-rootca.crt")
        if os.environ.get("GRAYLOG_TLS_INSECURE") == "1":
            self.ctx = ssl._create_unverified_context()  # noqa: S323 - opt-in explicite
        elif os.path.exists(ca):
            self.ctx = ssl.create_default_context(cafile=ca)
        else:
            self.ctx = ssl.create_default_context()

    def _req(self, method: str, path: str, body: dict | None = None) -> tuple[int, object]:
        url = self.base + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", self.auth)
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Requested-By", "seal-provision")
        try:
            with urllib.request.urlopen(req, timeout=20, context=self.ctx) as resp:
                raw = resp.read().decode()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            try:
                return exc.code, json.loads(raw)
            except json.JSONDecodeError:
                return exc.code, {"_raw": raw}

    def get(self, path: str):
        return self._req("GET", path)

    def post_entity(self, path: str, body: dict):
        # Graylog 7.x : certaines entites exigent l'enveloppe {entity, share_request}.
        # On tente d'abord nu, puis enveloppe si "entity cannot be null".
        st, res = self._req("POST", path, body)
        if isinstance(res, dict) and "entity cannot be null" in json.dumps(res):
            st, res = self._req("POST", path,
                                {"entity": body, "share_request": {"selected_grantee_capabilities": {}}})
        return st, res

    def put(self, path: str, body: dict):
        return self._req("PUT", path, body)

    # -- helpers metier --
    def stream_id(self, title: str) -> str | None:
        st, res = self.get("/streams")
        if st != 200 or not isinstance(res, dict):
            return None
        for s in res.get("streams", []):
            if s.get("title") == title:
                return s.get("id")
        return None

    def all_definitions(self) -> list[dict]:
        out, page = [], 1
        while page <= 100:
            st, res = self.get(f"/events/definitions?per_page=100&page={page}")
            if st != 200 or not isinstance(res, dict):
                break
            batch = res.get("event_definitions") or res.get("elements") or []
            if not batch:
                break
            out.extend(batch)
            if page * 100 >= int(res.get("total", 0) or 0):
                break
            page += 1
        return out

    def definition_id(self, title: str) -> str | None:
        for d in self.all_definitions():
            if d.get("title") == title:
                return d.get("id")
        return None

    def notification_id(self, title: str) -> str | None:
        st, res = self.get("/events/notifications?per_page=300")
        if st != 200 or not isinstance(res, dict):
            return None
        for n in res.get("notifications", []):
            if n.get("title") == title:
                return n.get("id")
        return None


# =============================================================================
#  Provisioning
# =============================================================================
def ensure_notification(gl: Graylog, webhook: str, apply: bool) -> str | None:
    existing = gl.notification_id(NOTIF_TITLE)
    body = {
        "title": NOTIF_TITLE,
        "description": "Webhook Teams (Adaptive Card) - alertes SEAL immediates "
                       "(Critical/High) - provisionne par provision_detections.py",
        "config": {
            "type": "teams-notification-v2",
            "webhook_url": webhook,
            "backlog_size": 5,
            "adaptive_card": build_teams_card(),
        },
    }
    if existing:
        print(f"  [=] notification '{NOTIF_TITLE}' existe ({existing})")
        if apply:
            st, _ = gl.put(f"/events/notifications/{existing}", {**body, "id": existing})
            print(f"      {'maj OK' if st in (200, 201) else f'maj refusee (HTTP {st})'}")
        else:
            print("      (dry-run) mise a jour de la carte/config prevue")
        return existing
    print(f"  [+] notification '{NOTIF_TITLE}' a CREER")
    if not apply:
        return None
    st, res = gl.post_entity("/events/notifications", body)
    nid = res.get("id") if isinstance(res, dict) else None
    print(f"      {'creee ' + nid if nid else f'REFUSEE (HTTP {st}: {res})'}")
    return nid


def provision_rule(gl: Graylog, rule: dict, stream_id: str, notif_id: str | None,
                   apply: bool, enable_deadman: bool, enable_parked: bool = False,
                   triage_id: str | None = None) -> str:
    title = full_title(rule)
    deadman = rule.get("deadman", False)
    # PARQUEE : regle conservee (tracabilite du catalogue) mais creee SANS schedule
    # car la donnee sur laquelle elle repose n'existe pas encore -> elle ne
    # produirait que du faux positif. Reactivable par --enable-parked.
    parked = rule.get("parked", False)
    # go-dark : schedule=false par defaut (cree desactive), sauf --enable-deadman.
    schedule = ((not deadman) or enable_deadman) and ((not parked) or enable_parked)
    q = "true" if schedule else "false"
    definition = build_definition(rule, stream_id, notif_id, triage_id)
    existing = gl.definition_id(title)
    state = "ACTIVE" if schedule else ("PARQUEE (donnee absente)" if parked
                                       else "DESACTIVE (recette)")

    if existing:
        line = f"  [=] {rule['id']:8} MAJ    [{state:16}] {title}"
        if not apply:
            print(line + "  (dry-run)")
            return "update"
        st, _ = gl.get(f"/events/definitions/{existing}")
        body = {**definition, "id": existing}
        st, res = gl.put(f"/events/definitions/{existing}?schedule={q}", body)
        print(line + ("  OK" if st in (200, 201) else f"  REFUSE (HTTP {st})"))
        return "update"

    line = f"  [+] {rule['id']:8} CREATE [{state:16}] {title}"
    if not apply:
        print(line + "  (dry-run)")
        return "create"
    st, res = gl.post_entity(f"/events/definitions?schedule={q}", definition)
    ok = isinstance(res, dict) and res.get("id")
    print(line + (f"  OK {res.get('id')}" if ok else f"  REFUSE (HTTP {st}: {res})"))
    return "create"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Provisionne le catalogue de detection v1 SEAL sur Graylog (dry-run par defaut)")
    ap.add_argument("--apply", action="store_true", help="applique reellement (defaut : dry-run)")
    ap.add_argument("--enable-deadman", action="store_true",
                    help="active aussi les dead-man switches (UNIQUEMENT si le flux SEAL est stable)")
    ap.add_argument("--enable-parked", action="store_true",
                    help="active aussi les regles PARQUEES (UNIQUEMENT si la donnee qui leur "
                         "manque est desormais peuplee, ex. pont badge->AD pour EVT-002)")
    args = ap.parse_args()

    mode = "APPLY" if args.apply else "DRY-RUN (aucune ecriture)"
    print("=" * 78)
    print(f" SEAL -> Graylog : provisioning detections v1  [{mode}]")
    print("=" * 78)

    url = os.environ.get("GRAYLOG_API_URL")
    token = (os.environ.get("GRAYLOG_API_TOKEN") or "").strip()
    webhook = os.environ.get("TEAMS_WEBHOOK_URL")
    if not url:
        print("  [x] GRAYLOG_API_URL absent (a fournir via l'environnement)")
        return 2
    # Auth : token de service si fourni, sinon repli basic auth admin (cf
    # lib-graylog.sh / provision_seal.py). Aucun secret en clair.
    if token:
        authz = "Basic " + base64.b64encode(f"{token}:token".encode()).decode()
    else:
        pwd = os.environ.get("GRAYLOG_ADMIN_PASS", "")
        if not pwd:
            print("  [x] ni GRAYLOG_API_TOKEN ni GRAYLOG_ADMIN_PASS fournis")
            return 2
        authz = "Basic " + base64.b64encode(f"admin:{pwd}".encode()).decode()
    if not webhook:
        print("  [!] TEAMS_WEBHOOK_URL absent -> notification Teams non provisionnee "
              "(regles Critical/High crees sans push immediat).")

    gl = Graylog(url, authz)
    st, sysinfo = gl.get("/system")
    if st != 200:
        print(f"  [x] API Graylog injoignable (HTTP {st}). Verifier URL/token/TLS.")
        return 2
    print(f"  API Graylog OK : version {sysinfo.get('version') if isinstance(sysinfo, dict) else '?'}\n")

    # Resolution des streams (par titre).
    stream_ids: dict[str, str | None] = {}
    print("== Streams SEAL (pre-requis) ==")
    for key, title in STREAMS.items():
        sid = gl.stream_id(title)
        stream_ids[key] = sid
        print(f"  {'[+]' if sid else '[!]'} {title:24} {sid or 'INTROUVABLE (regle sautee)'}")
    print()

    # Notification Teams (idempotente).
    print("== Notification Teams (Adaptive Card) ==")
    notif_id = ensure_notification(gl, webhook, args.apply) if webhook else None
    # Triage/mail : on se BRANCHE sur la notification existante (creee par
    # 38-alert-triage.sh), on ne la cree pas -- c'est le composant transverse a
    # toutes les sources, pas un objet SEAL.
    triage_id = gl.notification_id(TRIAGE_NOTIF_TITLE)
    if triage_id:
        print(f"  [=] notification '{TRIAGE_NOTIF_TITLE}' trouvee ({triage_id}) "
              "-> branchee sur les detections Critical/High (mail via triage)")
    else:
        print(f"  [!] notification '{TRIAGE_NOTIF_TITLE}' ABSENTE -> les alertes SEAL "
              "n'enverront PAS de mail (Teams seul). Jouer 38-alert-triage.sh.")
    print()

    # Definitions.
    print("== Definitions d'evenements ==")
    stats = {"create": 0, "update": 0, "skip": 0}
    for rule in RULES:
        sid = stream_ids.get(rule["stream"])
        if not sid:
            print(f"  [!] {rule['id']:8} SAUTE  (stream '{STREAMS[rule['stream']]}' absent)")
            stats["skip"] += 1
            continue
        action = provision_rule(gl, rule, sid, notif_id, args.apply, args.enable_deadman,
                                args.enable_parked, triage_id)
        stats[action] = stats.get(action, 0) + 1

    print("\n" + "-" * 78)
    print(f"  Bilan : {stats.get('create',0)} a creer, {stats.get('update',0)} a mettre a jour, "
          f"{stats['skip']} saute(s) (stream absent).")
    print(f"  Dead-man switches : {'ACTIVES' if args.enable_deadman else 'crees DESACTIVES'} "
          "(activation post-recette, flux stable requis).")
    parked = [r["id"] for r in RULES if r.get("parked")]
    if parked:
        print(f"  Regles PARQUEES  : {'ACTIVEES' if args.enable_parked else 'creees DESACTIVEES'} "
              f"({', '.join(parked)}) - donnee source absente, cf. commentaires du catalogue.")
    if not args.apply:
        print("  DRY-RUN : aucune ecriture. Relancer avec --apply pour appliquer.")
    print("-" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
