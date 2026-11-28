# shellcheck shell=bash
# ==============================================================================
# lib-modules.sh - Activation des modules par la configuration de site (docs/MODULES.md).
#   omni_module_enabled <id> : vrai si /etc/omni-siem/modules.d/<id>.enabled existe,
#   ou si le site n'a pas encore de modules.d (site historique : tout reste actif).
#   Les marqueurs sont écrits par « omni-integrations modules apply --apply ».
# ==============================================================================
OMNI_MODULES_DIR="${OMNI_MODULES_DIR:-/etc/omni-siem/modules.d}"

omni_module_enabled() {
  local id="${1:-}"
  [[ "$id" =~ ^[a-z][a-z0-9_]{1,31}$ ]] || return 1
  [[ -d "$OMNI_MODULES_DIR" ]] || return 0
  [[ -f "$OMNI_MODULES_DIR/$id.enabled" ]]
}
