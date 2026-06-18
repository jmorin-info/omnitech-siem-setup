#!/usr/bin/env bash
# =============================================================================
# 58-identity-correlation.sh - Identite unifiee (corrélation inter-sources).
#   Pose un champ canonique `identity` = le COMPTE normalise (minuscules, sans
#   domaine DOMAINE\, sans suffixe @upn) a partir de `user` (AD/endpoint/VPN/
#   FortiGate/vSphere) ou `upn` (M365). Permet de pivoter sur UNE identite a
#   travers TOUTES les sources en investigation ("tout ce qu'a fait jmorin :
#   ouvertures AD + connexions M365 + VPN + endpoint + detections").
#   Complete l'attribution IP->hote (DHCP) par l'attribution evenement->humain.
#   Pipeline DEDIE (stage 18, apres normalisation user/upn). Idempotent.
# Prerequis : 12 (streams/normalisation), 49 (account_class). Relancer 14.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "root requis"
require_api

echo "==> [1/3] Regles d'identite canonique"

# Anti-HALT : regle pass-through presente dans CHAQUE stage. Sans elle, un stage
# 'match either' a regle unique conditionnelle (strip-domain, from-upn, human...)
# STOPPE le pipeline pour les messages qui ne matchent pas cette regle -> les
# stages suivants (et donc les overrides + identity_human) sont sautes. La regle
# pass matche tout message identifiable -> le pipeline traverse tous les stages.
ensure_rule "omni-ident-00-pass" <<'EOF'
rule "omni-ident-00-pass"
when
  has_field("user") OR has_field("upn")
then
  let noop = true;
end
EOF

# Base : identity depuis `user` (deja "bare" cote Windows : adm-jmorin, jmorin).
# Exclut les comptes machine ($) qui ne sont pas des humains.
ensure_rule "omni-ident-10-from-user" <<'EOF'
rule "omni-ident-10-from-user"
when
  has_field("user")
  AND to_string($message.user) != ""
  AND to_string($message.user) != "N/A"
  AND to_string($message.user) != "-"
  AND NOT ends_with(to_string($message.user), "$")
  AND NOT starts_with(lowercase(to_string($message.user)), "host/")
  AND NOT contains(lowercase(to_string($message.user)), "autorite nt")
  AND NOT contains(lowercase(to_string($message.user)), "autorité nt")
  AND NOT contains(lowercase(to_string($message.user)), "nt authority")
then
  set_field("identity", lowercase(to_string($message.user)));
end
EOF

# Override domaine : si `user` portait encore DOMAINE\compte (ex. vSphere
# VSPHERE.LOCAL\administrator), on garde la partie apres le dernier backslash.
ensure_rule "omni-ident-12-strip-domain" <<'EOF'
rule "omni-ident-12-strip-domain"
when
  has_field("identity") AND contains(to_string($message.identity), "\\")
then
  let m = regex("([^\\\\]+)$", to_string($message.identity));
  set_field("identity", to_string(m["0"]));
end
EOF

# Override M365 : `upn` (jmorin@omnitech-security.fr) est la source la plus fiable
# pour l'identite cloud -> on prend la partie avant @ (prioritaire sur user).
ensure_rule "omni-ident-15-from-upn" <<'EOF'
rule "omni-ident-15-from-upn"
when
  has_field("upn") AND to_string($message.upn) != ""
then
  let m = regex("^([^@]+)", lowercase(to_string($message.upn)));
  set_field("identity", to_string(m["0"]));
end
EOF

# Lien humain : un compte d'admin (adm-jmorin) ou de service (svc-x) appartient a
# une personne -> identity_human strippe le prefixe pour relier l'activite admin
# et l'activite normale du MEME humain. account_class (pose par 49) distingue deja
# le TYPE de compte ; identity_human = a QUI il appartient.
ensure_rule "omni-ident-20-human" <<'EOF'
rule "omni-ident-20-human"
when
  has_field("identity")
  AND ( starts_with(to_string($message.identity), "adm-")
     OR starts_with(to_string($message.identity), "svc-")
     OR starts_with(to_string($message.identity), "adm_")
     OR starts_with(to_string($message.identity), "svc_") )
then
  set_field("identity_human", substring(to_string($message.identity), 4));
end
EOF

# BASE (toujours, des qu'il y a une identity) : identity_human = identity. Doit
# etre dans un stage AVANT l'override admin : un stage 'match either' a regle unique
# conditionnelle STOPPE le pipeline si elle ne matche pas -> mettre la regle qui
# matche TOUJOURS en base evite de sauter l'override (et inversement halterait tout).
ensure_rule "omni-ident-21-human-base" <<'EOF'
rule "omni-ident-21-human-base"
when
  has_field("identity")
then
  set_field("identity_human", to_string($message.identity));
end
EOF

echo "==> [2/3] Pipeline 'OMNI - Identite unifiee' (stage 18) + connexion streams"
# Chaque etape d'override dans son PROPRE stage : les mutations d'une regle ne sont
# PAS garanties visibles par une autre regle du MEME stage (piege base+override).
# 18 base user -> 19 strip domaine -> 20 override upn (M365) -> 21 humain -> 22 defaut.
PL="$(ensure_pipeline "OMNI - Identite unifiee" <<'EOF'
pipeline "OMNI - Identite unifiee"
stage 18 match either
rule "omni-ident-00-pass"
rule "omni-ident-10-from-user"
stage 19 match either
rule "omni-ident-00-pass"
rule "omni-ident-12-strip-domain"
stage 20 match either
rule "omni-ident-00-pass"
rule "omni-ident-15-from-upn"
stage 21 match either
rule "omni-ident-00-pass"
rule "omni-ident-21-human-base"
stage 22 match either
rule "omni-ident-00-pass"
rule "omni-ident-20-human"
end
EOF
)"
for ST in "OMNI - Windows Security" "OMNI - Sysmon" "OMNI - Windows autres" \
          "OMNI - M365" "OMNI - FortiGate" "OMNI - vSphere"; do
  SID="$(get_stream_id "${ST}")"
  [[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL}" || warn "stream absent: ${ST}"
done

echo "==> [3/3] Termine."
echo
echo "=== 58 termine. identity / identity_human poses sur les nouveaux evenements."
echo "    Relancer 14 pour la page 'Identite'. Pivot en investigation : identity:<compte>. ==="
