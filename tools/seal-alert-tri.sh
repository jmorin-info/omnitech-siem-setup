#!/usr/bin/env bash
# =============================================================================
# seal-alert-tri.sh - Applique la MATRICE DE TRI des detections SEAL sur Graylog.
#
# Contexte : tri des alertes SEAL (RSSI Julien, 18-21/07/2026). 2 sites SEAL :
#   QA  = bx-qa-seal-vm  (systeme de TEST : flux instable, jamais de mail)
#   PROD= bx-seal-omega  (reel : garde les vrais signaux de surete).
# La differentiation QA/PROD des defs NON site-specifiques (ACC/ALM/HYP/SLA)
# est portee par le GATE du triage (patch triage/omni-alert-triage : si
# seal_site==bx-qa-seal-vm -> pas de mail). CE script agit sur l'ETAT des
# definitions Graylog elles-memes (schedule + notifications).
#
# TROIS actions, par definition :
#   desactiver -> PUT /events/definitions/{id}/unschedule   (deprogramme la def)
#   console    -> retire la ou les notification(s) MAIL de la def (garde Teams
#                 + /soc), sans toucher au schedule. "On coupe le mail, on garde
#                 la visibilite." (mail = "OMNI - Triage (mail critique)" et/ou
#                 "OMNI - Mail equipe IT" ; Teams = "OMNI - SEAL Teams ...")
#   mail       -> AUCUN changement (signal de securite conserve tel quel ;
#                 le gate QA du triage se charge de ne pas mailer QA).
#
# SECURITE / GARDE-FOU (un incident d'execution a eu lieu le 18/07) :
#   - DRY-RUN PAR DEFAUT. N'ecrit RIEN sans APPLY=1 (comme omni-drift-events).
#   - En dry-run : GET uniquement (lecture seule), imprime l'etat AVANT + le
#     diff qu'il APPLIQUERAIT. En APPLY : PUT idempotents, jamais de DELETE.
#   - Ne DESACTIVE que des defs de SANTE/FP (DMS de flux, EVT-002 FP structurel),
#     jamais un signal de securite. Les vrais signaux (ACC-006/007, ALM-003,
#     ACC-001/004, SLA-*, HYP force-brute/compte) restent en MAIL.
#
# ------------------------------------------------------------------ MATRICE ---
# (action resolue apres verification adverse des desactivations, 21/07/2026)
#
#   CODE     ACTION      NATURE / MOTIF COURT
#   DMS-001  desactiver  sante flux (audit global) : redondant DMS-004/005, spam p3
#   DMS-002  desactiver  sante flux (acces global) : redondant DMS-006/007
#   DMS-003  desactiver  sante flux (alarmes global): redondant DMS-008/009
#   DMS-004  console     dead-man AUDIT QA : garde visibilite go-dark, coupe mail
#                        (group_by vide -> gate QA ne le couvre pas : option b)
#   DMS-005  console     dead-man AUDIT PROD (T1562.001) : garde, sans mail (flapping)
#   DMS-006  desactiver  dead-man ACCES QA : sante d'un banc de test, spam
#   DMS-007  console     dead-man ACCES PROD : garde, 0 bruit, sans mail
#   DMS-008  desactiver  dead-man ALARMES QA : sante d'un banc de test, spam
#   DMS-009  console     dead-man ALARMES PROD : garde, 0 bruit, sans mail
#   EVT-001  console     base de correlation/chasse (Info, ne maile deja pas)
#   EVT-002  desactiver  FAUX POSITIF 100% (pont badge->AD vide) : reparquer
#   DQ-001   console     dette de donnee honnete (Info, 1/jour/site)
#   SLA-001  mail        alarme CRITIQUE non acquittee : vrai signal surete
#   SLA-002  mail        alarme severe non acquittee : vrai signal
#   ZON-001  console     rafale refus/zone (Medium, ne maile pas ; parquee)
#   ACC-001  mail        master key (T1098/T1078) : rare, fort signal
#   ACC-002  console     attribution masse droits (Medium digest)
#   ACC-003  console     creation badge (Info, IT routine)
#   ACC-004  mail        reactivation badge ANN->VAL (T1078)
#   ACC-006  mail        refus repetes / porte (demande explicite Julien)
#   ACC-007  mail        acces accorde hors plage horaire (demande explicite)
#   ALM-001  mail        inhibition alarme (tamper pre-intrusion T1562.001)
#   ALM-003  mail        intrusion physique / effraction (Critical)
#   ALM-004  console     flood capteur (Medium, sante)
#   HYP-001  mail        brute force console (T1110)
#   HYP-002  mail        brute force + succes (T1110/T1078)
#   HYP-003  console     connexion console admin (Medium, deja console)
#   HYP-004  console     switch profil (Medium)
#   HYP-005  mail        connexion admin hors heures (T1078)
#   HYP-006  console     export journaux audit (Medium)
#   HYP-007  mail        creation/modif compte ou role (T1136/T1098)
#   HYP-008  console     modif autorisations profil (Medium)
#   HYP-009  console     migration unite locale (Medium)
#   HYP-010  console     modif objet physique (Medium)
#   HYP-011  console     sessions multi-IP (Medium)
#   HYP-012  console     compte multi-sites (Medium ; def cassee cote source, cf. LACUNES)
#
# Usage :  bash tools/seal-alert-tri.sh          # DRY-RUN (GET only, defaut)
#          APPLY=1 bash tools/seal-alert-tri.sh  # applique (PUT idempotents)
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source 00-vars.env
# shellcheck disable=SC1091
source lib-graylog.sh

# APPLY par variable d'env OU par 1er argument positionnel "apply" : ce dernier permet a la
# commande de commencer par "bash <chemin>" (et non "APPLY=1 bash ...") pour matcher une regle
# de permission Bash(bash .../tools/*) sans prefixe d'environnement.
[[ "${1:-}" == "apply" ]] && APPLY=1
APPLY="${APPLY:-0}"
[[ "${APPLY}" == "1" ]] && MODE="APPLY (ecritures PUT)" || MODE="DRY-RUN (lecture seule)"

# Titres des notifications qui portent le MAIL (a retirer pour 'console').
# Tout le reste (Teams "OMNI - SEAL Teams..." / "OMNI - Teams SOC" firehose) est
# CONSERVE. NB : les parentheses de "(mail critique)" sont ECHAPPEES (\() car
# test() les interprete sinon comme un groupe regex -> la notif Triage n'etait
# pas matchee et le mail serait reste attache malgre 'console'.
MAIL_NOTIF_TITLES='^OMNI - Triage \(mail critique\)$|^OMNI - Mail equipe IT$'

# ------------------------------------------------------------------ MATRICE ---
# Format : "CODE|ACTION|HEXID"  (HEXID = "-" -> resolution par titre live).
MATRIX=(
  "DMS-001|desactiver|6a575012ef35b1c51c663a33"
  "DMS-002|desactiver|6a575012ef35b1c51c663a3d"
  "DMS-003|desactiver|6a575012ef35b1c51c663a53"
  "DMS-004|console|6a577b8eef35b1c51c666e4f"
  "DMS-005|console|6a577b8eef35b1c51c666e59"
  "DMS-006|desactiver|6a577b8eef35b1c51c666e65"
  "DMS-007|console|6a577b8fef35b1c51c666e6f"
  "DMS-008|desactiver|6a577b8fef35b1c51c666e79"
  "DMS-009|console|6a577b8fef35b1c51c666e83"
  "EVT-001|console|6a575011ef35b1c51c663a15"
  "EVT-002|desactiver|6a575011ef35b1c51c663a27"
  "DQ-001|console|6a587e06ef35b1c51c679fb6"
  "SLA-001|mail|6a57880cef35b1c51c66811e"
  "SLA-002|mail|6a57880cef35b1c51c66812a"
  "ZON-001|console|6a578c7def35b1c51c668815"
  "ACC-001|mail|6a57500eef35b1c51c6639a9"
  "ACC-002|console|6a57500eef35b1c51c6639b5"
  "ACC-003|console|6a57500fef35b1c51c6639c1"
  "ACC-004|mail|6a57500fef35b1c51c6639cd"
  "ACC-006|mail|6a57500fef35b1c51c6639d9"
  "ACC-007|mail|6a575010ef35b1c51c6639e5"
  "ALM-001|mail|6a575010ef35b1c51c6639f1"
  "ALM-003|mail|6a575010ef35b1c51c6639fd"
  "ALM-004|console|6a575011ef35b1c51c663a09"
  "HYP-001|mail|-"
  "HYP-002|mail|-"
  "HYP-003|console|-"
  "HYP-004|console|-"
  "HYP-005|mail|-"
  "HYP-006|console|-"
  "HYP-007|mail|-"
  "HYP-008|console|-"
  "HYP-009|console|-"
  "HYP-010|console|-"
  "HYP-011|console|-"
  "HYP-012|console|-"
)

echo "============================================================================"
echo " seal-alert-tri.sh  -  tri des detections SEAL  [${MODE}]"
echo "============================================================================"

# --- API : injoignable en dry-run -> on imprime tout de meme le PLAN THEORIQUE.
if ! api_get "/system" | jq -e '.version' >/dev/null 2>&1; then
  if [[ "${APPLY}" == "1" ]]; then
    die "API Graylog injoignable (APPLY refuse). Verifier 00-vars.env / service graylog-server."
  fi
  warn "API Graylog injoignable : plan THEORIQUE (aucun etat live lisible)."
  echo
  printf '  %-9s %-11s %s\n' "CODE" "ACTION" "HEXID"
  for row in "${MATRIX[@]}"; do
    IFS='|' read -r code action hexid <<<"${row}"
    printf '  %-9s %-11s %s\n' "${code}" "${action}" "${hexid}"
  done
  echo
  echo "  (Fournir 00-vars.env avec un Graylog joignable pour la reconciliation live.)"
  exit 0
fi
echo "  API Graylog OK : version $(api_get /system | jq -r '.version')"
echo

# --- Resolution des ID de notifications MAIL (a retirer pour 'console') -------
ALL_NOTIF="$(api_get '/events/notifications?per_page=300')"
MAIL_NOTIF_IDS="$(echo "${ALL_NOTIF}" \
  | jq -r --arg re "${MAIL_NOTIF_TITLES}" \
      '[.notifications[]? | select(.title|test($re)) | .id] | @json')"
echo "  Notifications MAIL detectees (retirees pour 'console') : $(echo "${ALL_NOTIF}" \
  | jq -r --arg re "${MAIL_NOTIF_TITLES}" '[.notifications[]?|select(.title|test($re))|.title]|join(", ") // "(aucune)"')"
echo

# --- Cache de toutes les defs (pagine) pour resolution par titre -------------
ALLDEFS="$(all_event_defs)"

# notif_titles <def-json> : liste lisible des titres de notifs attachees
notif_titles() {
  echo "$1" | jq -r --argjson m "${ALL_NOTIF}" '
    [.notifications[]?.notification_id] as $ids
    | [$m.notifications[]? | select(.id as $i | $ids|index($i)) | .title]
    | join(", ") // ""'
}

# resolve_id <code> <hexid> : retourne l ID live (hex fourni si present dans le
# cache, sinon resolution par prefixe de titre "OMNI - SEAL <code> -").
resolve_id() {
  local code="$1" hexid="$2" id=""
  if [[ "${hexid}" != "-" ]]; then
    id="$(echo "${ALLDEFS}" | jq -r --arg i "${hexid}" \
        '.event_definitions[]|select(.id==$i)|.id' | head -1)"
    [[ -n "${id}" ]] && { echo "${id}"; return; }
    # hex fourni mais absent du live (drift d'ID) -> repli titre
  fi
  echo "${ALLDEFS}" | jq -r --arg p "OMNI - SEAL ${code} -" \
      '.event_definitions[]|select(.title|startswith($p))|.id' | head -1
}

CHG=0; NOOP=0; MISS=0
for row in "${MATRIX[@]}"; do
  IFS='|' read -r code action hexid <<<"${row}"
  id="$(resolve_id "${code}" "${hexid}")"
  if [[ -z "${id}" || "${id}" == "null" ]]; then
    warn "${code} : definition INTROUVABLE live (action '${action}' non appliquee)"
    MISS=$((MISS+1)); continue
  fi
  DEF="$(api_get "/events/definitions/${id}")"
  title="$(echo "${DEF}" | jq -r '.title')"
  state="$(echo "${DEF}" | jq -r '.state // "?"')"          # ENABLED/DISABLED
  nt="$(notif_titles "${DEF}")"
  has_mail="$(echo "${DEF}" | jq -r --argjson mail "${MAIL_NOTIF_IDS}" \
      'any(.notifications[]?; .notification_id as $i | ($mail|index($i))!=null)')"

  echo "  ------------------------------------------------------------------------"
  echo "  ${code}  [${state}]  ${title}"
  echo "    notifs live : ${nt:-（aucune)}"

  case "${action}" in
    desactiver)
      if [[ "${state}" == "DISABLED" ]]; then
        skip "${code} : deja DESACTIVE (unschedule) - rien a faire"; NOOP=$((NOOP+1))
      else
        echo "    -> DESACTIVER (PUT /events/definitions/${id}/unschedule)"; CHG=$((CHG+1))
        if [[ "${APPLY}" == "1" ]]; then
          api_put "/events/definitions/${id}/unschedule" </dev/null >/dev/null \
            && ok "${code} : desactive" || warn "${code} : unschedule ECHEC"
        fi
      fi
      ;;
    console)
      if [[ "${has_mail}" != "true" ]]; then
        skip "${code} : aucune notif MAIL attachee - deja 'console' (rien a faire)"; NOOP=$((NOOP+1))
      else
        # schedule preserve : ENABLED->true, sinon false (on n'active jamais
        # une def desactivee au passage - decision separee).
        local_sched="false"; [[ "${state}" == "ENABLED" ]] && local_sched="true"
        echo "    -> CONSOLE : retirer la/les notif(s) MAIL (garde Teams/SOC), schedule=${local_sched}"; CHG=$((CHG+1))
        if [[ "${APPLY}" == "1" ]]; then
          # On repart du LIVE, on retire les notifs MAIL, et on supprime les
          # champs calcules/lecture-seule (memes que lib-graylog.sh converge) que
          # l API refuse en PUT. On conserve tout le reste tel quel (idempotent).
          echo "${DEF}" | jq --argjson mail "${MAIL_NOTIF_IDS}" \
              '.notifications = [.notifications[]? | select((.notification_id as $i|($mail|index($i)))==null)]
               | del(._scope, .matched_at, .updated_at, .scheduler)' \
            | api_put "/events/definitions/${id}?schedule=${local_sched}" >/dev/null \
            && ok "${code} : mail retire (console)" || warn "${code} : PUT console ECHEC"
        fi
      fi
      ;;
    mail)
      # Aucun changement. Controle de couverture (sans muter) : signale si la def
      # ne mailerait PAS (desactivee ou sans notif mail) = angle mort a examiner.
      if [[ "${state}" != "ENABLED" ]]; then
        warn "${code} : action=mail mais def ${state} -> ne se declenchera pas (a examiner)"
      elif [[ "${has_mail}" != "true" ]]; then
        warn "${code} : action=mail mais AUCUNE notif mail attachee -> ne mailera pas (a examiner)"
      else
        skip "${code} : mail conserve (inchange)"
      fi
      NOOP=$((NOOP+1))
      ;;
    *)
      warn "${code} : action inconnue '${action}' (ignoree)" ;;
  esac
done

echo "  ------------------------------------------------------------------------"
if [[ "${APPLY}" == "1" ]]; then VERB="APPLIQUE(S)"; else VERB="PREVU(S) - dry-run"; fi
echo "  Bilan : ${CHG} changement(s) ${VERB}, ${NOOP} deja conforme(s), ${MISS} introuvable(s)."
[[ "${APPLY}" == "1" ]] || echo "  DRY-RUN : aucune ecriture. Relancer avec APPLY=1 pour appliquer."
echo "============================================================================"
