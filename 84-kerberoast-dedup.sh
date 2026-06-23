#!/usr/bin/env bash
# =============================================================================
# 84-kerberoast-dedup.sh - Consolidation des alertes Kerberos (anti-bruit)
#
#   CONSTAT (mesure live, 90 j) :
#     - Posture AES confirmee : 4769 vus en 0x12 (AES, 2250) + 0xffffffff
#       (null/S4U, 8893). ZERO 0x17 (RC4) -> aucun kerberoasting reel a ce jour.
#     - MAIS triple/double alertage LATENT sur un meme evenement :
#         Kerberoasting/RC4 x3 :
#           [GARDE ] OMNI - Kerberoasting (ticket Kerberos RC4 demande)   (73, count>=1, 5min)
#           [SUPPR ] OMNI - Kerberoasting suspect (>=5 SPN / compte/10min) (13, card>=5)
#           [SUPPR ] OMNI - Kerberos RC4 / downgrade (kerberoasting)       (13, tag kerberos_rc4)
#         AS-REP roasting x2 :
#           [GARDE ] OMNI - AS-REP Roasting (compte sans pré-auth Kerberos) (73, count>=1, 5min)
#           [SUPPR ] OMNI - AS-REP roasting (compte sans pre-auth)          (13, count>=1, 30min)
#
#   DECISION : 73 (script de detection AD dedie) est la source canonique.
#   Les 3 definitions issues du lot 13 sont strictement redondantes (plus
#   lentes ; ne peuvent pas se declencher sans que le garde count>=1 se
#   declenche d'abord). On passe de 5 -> 2 alertes, SANS perte de detection.
#
#   SECURITE : aucune suppression n'est faite tant que le GARDE du cluster
#   n'est pas verifie present (jamais de perte totale de couverture).
#
#   DRY-RUN PAR DEFAUT. Pour appliquer : APPLY=1 ./84-kerberoast-dedup.sh
#   Idempotent. Reversible : ré-executer 13-graylog-alerts.sh recree les
#   definitions (mais voir le garde-fou ajoute dans 13 pour eviter le doublon).
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

APPLY="${APPLY:-0}"
if [[ "$APPLY" == "1" ]]; then
  echo "==> MODE APPLIQUE (APPLY=1) : suppression effective des doublons"
else
  echo "==> MODE DRY-RUN (defaut) : aucune suppression. APPLY=1 pour appliquer."
fi
echo

DEFS_JSON="$(api_get "/events/definitions?per_page=500")"

def_id() {  # titre -> id (vide si absent)
  jq -r --arg t "$1" '.event_definitions[]?|select(.title==$t)|.id' <<<"$DEFS_JSON" | head -1
}

# cluster <titre-garde> <titre-a-supprimer...>
dedup_cluster() {
  local keep_title="$1"; shift
  local keep_id; keep_id="$(def_id "$keep_title")"
  if [[ -z "$keep_id" ]]; then
    warn "GARDE absent : « $keep_title » -> cluster IGNORE (pas de suppression, securite)"
    return
  fi
  ok "GARDE present : « $keep_title » ($keep_id)"
  local t id
  for t in "$@"; do
    id="$(def_id "$t")"
    if [[ -z "$id" ]]; then
      skip "deja absent : « $t »"
      continue
    fi
    if [[ "$APPLY" == "1" ]]; then
      if api_del "/events/definitions/$id" >/dev/null 2>&1; then
        ok "SUPPRIME : « $t » ($id)"
      else
        warn "ECHEC suppression : « $t » ($id)"
      fi
    else
      echo "   [DRY-RUN] supprimerait : « $t » ($id)"
    fi
  done
}

echo "--- Cluster Kerberoasting / RC4 (x3 -> x1) ---"
dedup_cluster \
  "OMNI - Kerberoasting (ticket Kerberos RC4 demande)" \
  "OMNI - Kerberoasting suspect (>=5 SPN / compte / 10 min)" \
  "OMNI - Kerberos RC4 / downgrade (kerberoasting)"

echo
echo "--- Cluster AS-REP roasting (x2 -> x1) ---"
dedup_cluster \
  "OMNI - AS-REP Roasting (compte sans pré-auth Kerberos)" \
  "OMNI - AS-REP roasting (compte sans pré-auth)"

echo
echo "--- Tag orphelin kerberos_rc4 ---"
echo "   La regle pipeline omni-l3-10-kerberos-rc4 (50) pose encore alert_tag=kerberos_rc4."
echo "   Plus aucune alerte ne consomme ce tag ; il reste indexe (dashboards 14 le"
echo "   surlignent encore). Laisse en place (non bloquant) ou a retirer du lot 50"
echo "   lors d'une revue ulterieure. Non touche par ce script."
echo
if [[ "$APPLY" == "1" ]]; then
  echo "=== 84 termine (APPLIQUE). Alertes Kerberos : 5 -> 2. Relancer 57 (carte couverture). ==="
else
  echo "=== 84 termine (DRY-RUN). Relancer avec APPLY=1 pour consolider. ==="
fi
