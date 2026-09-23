#!/usr/bin/env bash
# =============================================================================
# fp-tuning-2026-09.sh - Reduction des faux positifs (tri des alertes 09/2026).
#   Analyse 7 j : 208k events, dont 92% = Tor/Spamhaus sur du trafic BLOQUE.
#   4 correctifs cibles (chacun = modif de la REQUETE d'une detection, ou
#   desactivation d'une detection non-prod). Aucune donnee touchee, reversible.
#
#   1. Tor/Spamhaus : + "AND action:accept" -> ne garde que le trafic AUTORISE
#      vers/depuis une IP malveillante (158k deny = firewall OK = non actionnable).
#   2. LSASS        : exclure njbinarymetering (NinjaOne) + WerFaultSecure (1076/1078 FP).
#   3. RAT/RMM      : retirer TeamViewer (outil support IT sanctionne, usage org-wide).
#   4. SEAL QA      : desactiver DMS-004/006/008 sur bx-qa-seal-vm (non-prod ; OMEGA conserve).
#
#   DRY-RUN par defaut (GET seulement, imprime le diff). Appliquer : APPLY=1 ./fp-tuning-2026-09.sh
#   Idempotent (re-applique = sans effet si deja conforme).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
require_api
APPLY="${APPLY:-0}"

DEFS="$(api_get '/events/definitions?per_page=400')"
id_by_title(){ echo "$DEFS" | jq -r --arg t "$1" '.event_definitions[]?|select(.title|test($t))|.id' | head -1; }

# --- modifie la requete d'une detection (par titre) ---------------------------
set_query(){ # $1=motif_titre  $2=nouvelle_query
  local id t cur new
  id="$(id_by_title "$1")"; [[ -z "$id" ]] && { warn "detection absente: $1"; return; }
  t="$(echo "$DEFS" | jq -r --arg i "$id" '.event_definitions[]?|select(.id==$i)|.title')"
  cur="$(echo "$DEFS" | jq -r --arg i "$id" '.event_definitions[]?|select(.id==$i)|.config.query')"
  if [[ "$cur" == "$2" ]]; then skip "[$t] deja a jour"; return; fi
  echo "  ~ [$t]"
  echo "     AVANT: $cur"
  echo "     APRES: $2"
  [[ "$APPLY" != "1" ]] && return
  local rep
  rep="$(api_get "/events/definitions/$id" | jq --arg q "$2" '.config.query=$q' | api_put "/events/definitions/$id?schedule=true")"
  echo "$rep" | jq -e '.id' >/dev/null 2>&1 && ok "[$t] requete mise a jour" || warn "[$t] echec: $(echo "$rep"|head -c160)"
}

# --- desactive une detection (par id exact) -----------------------------------
disable_def(){ # $1=id  $2=libelle
  local id="$1"
  [[ -z "$id" ]] && { warn "id vide ($2)"; return; }
  local st; st="$(echo "$DEFS" | jq -r --arg i "$id" '.event_definitions[]?|select(.id==$i)|.state')"
  if [[ "$st" == "DISABLED" ]]; then skip "[$2] deja desactivee"; return; fi
  echo "  x DESACTIVER [$2] (id=$id, etat=$st)"
  [[ "$APPLY" != "1" ]] && return
  if "${CURL[@]}" -X PUT "${API}/events/definitions/${id}/unschedule" >/dev/null 2>&1; then
    ok "[$2] desactivee"
  else warn "[$2] echec desactivation"; fi
}

echo "=== fp-tuning-2026-09.sh (mode $([[ $APPLY == 1 ]] && echo APPLY || echo DRY-RUN)) ==="

echo "[1/4] Tor/Spamhaus -> action:accept uniquement"
set_query "IP malveillante \\(Tor" 'alert_tag:threat_intel AND action:accept'

echo "[2/4] LSASS -> exclure agents legitimes"
set_query "Acces memoire LSASS|Accès mémoire LSASS" \
  'alert_tag:lsass_access AND NOT winlogbeat_winlog_event_data_SourceImage:(*njbinarymetering* OR *NinjaOne* OR *WerFaultSecure*)'

echo "[3/4] RAT/RMM -> retirer TeamViewer (sanctionne)"
set_query "RAT/RMM" \
  'event_source:sysmon AND winlogbeat_winlog_event_id:1 AND (winlogbeat_winlog_event_data_OriginalFileName:("AnyDesk.exe" OR "RustDesk.exe" OR "ngrok.exe") OR winlogbeat_winlog_event_data_Image:(*anydesk* OR *screenconnect* OR *splashtop* OR *atera* OR *rustdesk* OR *gotoassist* OR *remoteutilities* OR *zohoassist* OR *action1* OR *pulseway* OR *quickassist*)) AND NOT winlogbeat_winlog_event_data_Image:*ninjarmm* AND NOT source:bx\-hl\-*'

echo "[4/4] SEAL QA (bx-qa-seal-vm) -> desactiver DMS-004/006/008"
disable_def "6a577b8eef35b1c51c666e4f" "SEAL DMS-004 QA"
disable_def "6a577b8eef35b1c51c666e65" "SEAL DMS-006 QA"
disable_def "6a577b8fef35b1c51c666e79" "SEAL DMS-008 QA"

echo "=== termine ($([[ $APPLY == 1 ]] && echo APPLIQUE || echo 'DRY-RUN, rien ecrit')). ==="
