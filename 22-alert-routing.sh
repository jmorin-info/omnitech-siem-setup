#!/usr/bin/env bash
# =============================================================================
# 22-alert-routing.sh - DEPRECIE (2026-06-27). NE PLUS UTILISER.
#
# Ce script faisait le routage mail/Teams en 2 tiers via une liste KEEP statique.
# Il est REMPLACE par la couche de triage dynamique : 38-alert-triage.sh +
# service omni-alert-triage (scoring multi-signaux + LLM zone grise).
#
# Pourquoi il a ete retire (cf audit 27/06) :
#   - liste KEEP en NON-ACCENTUE alors que les titres ont ete re-accentues
#     -> 4 alertes critiques (Integrite des logs, Acces massif, Mouvement lateral,
#        Compte M365 a risque) perdaient leur mail SILENCIEUSEMENT ;
#   - IDs de notification (MAIL/TEAMS) codes en DUR -> casse apres restore Mongo ;
#   - re-ajoutait du MAIL DIRECT, court-circuitant le triage (conflit).
#
# Desormais : Teams reste cable en direct (firehose) ; le mail passe par la notif
# "OMNI - Triage (mail critique)" -> omni-alert-triage decide. Voir 38-alert-triage.sh.
# =============================================================================
echo "22-alert-routing.sh est DEPRECIE et remplace par 38-alert-triage.sh (triage dynamique)."
echo "Aucune action effectuee. Lancer 38-alert-triage.sh a la place."
exit 0
