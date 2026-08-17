#!/usr/bin/env bash
# =============================================================================
# 44-incidents.sh - DÉPRÉCIÉ (28/06/2026).
#
#   L'ancien moteur de corrélation `omni-incident-correlate` (event_source=incident,
#   reconstruction de kill-chain par entité) est REMPLACÉ par **oms-xdr**
#   (event_source=xdr_incident) : corrélation par règles curées, mapping MITRE,
#   pont cross-entité user<->host, signaux ML, narration LLM, réponse SOAR.
#
#   Moteur d'incidents UNIQUE désormais. La console SOC (mobile-api) et les
#   dashboards consomment déjà `xdr_incident`. Ce script se contente de désactiver
#   l'ancien moteur (idempotent) pour éviter le double-comptage.
#
#   Le script et le service `omni-incident-correlate` restent présents (désactivés)
#   au cas où ; ré-activation manuelle possible si besoin d'un angle « kill-chain
#   par accumulation » complémentaire.
# =============================================================================
set -euo pipefail
systemctl disable --now omni-incident-correlate.timer omni-incident-correlate.service 2>/dev/null || true
echo "44-incidents.sh : DÉPRÉCIÉ — moteur d'incidents unique = oms-xdr (xdr_incident)."
echo "  Ancien moteur omni-incident-correlate désactivé (anti double-comptage)."
