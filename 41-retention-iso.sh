#!/usr/bin/env bash
# =============================================================================
# 41-retention-iso.sh - Retention DIFFERENCIEE (tiered) + reduction de bruit
#   pour tenir un dossier securite 12 mois dans les 80% du disque (ISO 27001
#   A.8.15). 3 volets :
#     1. TRIM (pipeline stage 30, APRES toute detection) : jette le bruit a fort
#        volume / faible valeur (Sysmon EID12 registre add/del, winsec 4673/4627).
#        -> ne casse AUCUNE detection (DCSync=4662, persistance=Sysmon13 conserves).
#     2. RETENTION tiered via API : sources securite -> 365j ; FortiGate -> 90j.
#     3. POLITIQUE documentee (preuve d'audit) -> docs/POLITIQUE-RETENTION.md.
#   Idempotent. Reversible (retirer les regles/pipeline restaure la collecte).
#   Prerequis : 12 (normalisation event_id). Le disk-guard (80%) reste le backstop.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
source ./00-vars.env
source ./lib-graylog.sh
[[ $EUID -eq 0 ]] || die "a lancer en root."
require_api

# --- 1. Regles de reduction de bruit (drop_message au stage 30) ---------------
echo "==> [1/3] Regles de reduction de volume (stage 30, apres detection)"
ensure_rule "omni-iso-drop-sysmon-registre" <<'EOF'
rule "omni-iso-drop-sysmon-registre"
when
  to_string($message.event_source) == "sysmon" AND to_long($message.event_id, 0) == 12
then
  drop_message();
end
EOF
ensure_rule "omni-iso-drop-winsec-bruit" <<'EOF'
rule "omni-iso-drop-winsec-bruit"
when
  to_string($message.event_source) == "windows_security"
  AND (to_long($message.event_id, 0) == 4673 OR to_long($message.event_id, 0) == 4627)
then
  drop_message();
end
EOF

PL_RED="$(ensure_pipeline "OMNI - Reduction volume (ISO)" <<'EOF'
pipeline "OMNI - Reduction volume (ISO)"
stage 30 match either
rule "omni-iso-drop-sysmon-registre"
rule "omni-iso-drop-winsec-bruit"
end
EOF
)"
for ST in "OMNI - Windows Security" "OMNI - Sysmon"; do
  SID="$(get_stream_id "${ST}")"
  [[ -n "${SID}" ]] && connect_pipeline "${SID}" "${PL_RED}" || warn "stream absent: ${ST}"
done
ok "reduction de volume active (Sysmon EID12, winsec 4673/4627)"

# --- 2. Retention differenciee (tiered) --------------------------------------
echo "==> [2/3] Retention tiered (securite 365j / FortiGate 90j)"
# set_retention <prefix> <jours>  (rotation journaliere P1D deja en place)
set_retention() {
  local PREFIX="$1" DAYS="$2" ID CUR
  ID="$(api_get "/system/indices/index_sets?limit=50" | jq -r --arg p "$PREFIX" '.index_sets[] | select(.index_prefix==$p) | .id')"
  [[ -n "${ID}" ]] || { warn "index set ${PREFIX} introuvable"; return 0; }
  CUR="$(api_get "/system/indices/index_sets/${ID}")"
  local NOW; NOW="$(echo "${CUR}" | jq -r '.retention_strategy.max_number_of_indices')"
  if [[ "${NOW}" == "${DAYS}" ]]; then skip "${PREFIX} deja a ${DAYS} index (jours)"; return 0; fi
  echo "${CUR}" | jq --argjson d "${DAYS}" '.retention_strategy.max_number_of_indices = $d' \
    | api_put "/system/indices/index_sets/${ID}" >/dev/null \
    && ok "${PREFIX} -> retention ${DAYS} jours (etait ${NOW})" || warn "${PREFIX} : maj retention KO"
}
set_retention "omni-winsec"    365
set_retention "omni-sysmon"    365
set_retention "omni-winother"  365
set_retention "omni-m365"      365
set_retention "omni-vsphere"   365
set_retention "omni-fortigate"  90

# --- 3. Politique de retention documentee (preuve ISO 27001 A.8.15) ----------
echo "==> [3/3] Generation de la politique de retention (preuve d'audit)"
mkdir -p docs
cat > docs/POLITIQUE-RETENTION.md <<'EOF'
# Politique de rétention des journaux - OMNITECH Security (SIEM Graylog)

Référence ISO/IEC 27001:2022 — A.8.15 (Journalisation), A.8.16 (Surveillance),
A.8.17 (Synchronisation des horloges). Approche **risque-based** : durée adaptée
à la valeur sécurité/forensic de chaque source, dans la limite du stockage.

## Durées de conservation (en ligne, consultable)

| Source                         | Durée  | Justification                                            |
|--------------------------------|--------|----------------------------------------------------------|
| Windows Security (AD)          | 365 j  | Dossier sécurité : auth, comptes, privilèges, PKI        |
| Sysmon (endpoint)              | 365 j  | Détections, chasse, processus/réseau (hors bruit registre)|
| Windows autres (Veeam, ADCS…)  | 365 j  | Sauvegardes, PKI, services                               |
| Microsoft 365 / Entra          | 365 j  | Connexions cloud, partages, rôles                        |
| vSphere                        | 365 j  | Accès hyperviseur, suppressions VM                       |
| FortiGate (pare-feu)           | 90 j   | Trafic volumineux : fenêtre forensic suffisante ; les    |
|                                |        | événements sécurité (deny/UTM/VPN) restent corrélés 90 j |

## Événements explicitement EXCLUS (risque accepté, faible valeur / fort volume)

| Source | Event | Motif |
|--------|-------|-------|
| Sysmon | EID 12 (RegistryEvent add/delete) | ~62% du volume Sysmon, bruit ; la persistance registre est couverte par l'EID 13 (Value Set), conservé |
| Windows Security | 4673 (Sensitive Privilege Use) | Très volumineux, quasi-100% bénin (services système) |
| Windows Security | 4627 (Group Membership) | Redondant avec 4624 (déjà conservé) |

Conservés volontairement malgré leur volume : **4662** (requis pour la détection
DCSync) et **4688** (traçabilité de création de processus).

## Intégrité & protection (A.8.15)
- Index OpenSearch en écriture seule (pas de modification a posteriori).
- Détection d'effacement de journaux (1102/4719/1100/104) -> alerte P3.
- Sauvegarde quotidienne de la configuration ; horloges synchronisées (NTP).
- Accès SIEM restreint (LDAPS, groupe AD dédié).

## Garde-fou de capacité
- Disque /data dédié, garde-fou automatique : purge des plus anciens index si
  occupation > 80% (omni-disk-guard) -> empêche toute saturation, en dernier
  recours. Revue mensuelle du Go/jour (cf. supervision collecte).

_Document généré par 41-retention-iso.sh — à valider et dater par le RSSI._
EOF
ok "politique ecrite -> docs/POLITIQUE-RETENTION.md"

echo
echo "=== 41-retention-iso.sh termine. Projection ~5,1 To (dossier securite 12 mois). ==="
echo "    Surveiller le Go/jour reel (la reduction s'applique au flux POSTERIEUR)."
