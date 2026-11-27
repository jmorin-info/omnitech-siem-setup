#!/usr/bin/env bash
# =============================================================================
# Chantier 5 SIEM v5 (réponse / ATT&CK / résilience) - RETOUR ARRIÈRE
# Supprime UNIQUEMENT les objets du chantier 5, par nom :
#   - service omni-v5-reponse (unité, code, configuration) ; l'état et le
#     journal d'audit sont DÉPLACÉS dans le dossier de sauvegarde (traçabilité)
#   - bloc nginx « BEGIN/END OMNI V5 REPONSE » de sites-enabled/graylog
#   - index de test restore-test-v5-* (OpenSearch)
# Ne redémarre jamais graylog-server, opensearch, mongod (nginx : reload).
# Usage : bash retour.sh [--simuler]
# =============================================================================
set -uo pipefail
SIM=0; [[ "${1:-}" == "--simuler" ]] && SIM=1
# Dossier de sauvegarde de l'état au retour (jamais dans le dépôt) : REPONSE_SAUVEGARDE ou /var/backups/siem.
ICI="${REPONSE_SAUVEGARDE:-/var/backups/siem/v5-reponse-retour-$(date +%Y%m%d-%H%M)}"
[[ $SIM == 1 ]] || install -d -m 700 "$ICI"
NGX=/etc/nginx/sites-enabled/graylog
UNIT=/etc/systemd/system/omni-v5-reponse.service
f() { if [[ $SIM == 1 ]]; then echo "[simulation] $*"; else echo "[retour] $*"; eval "$*"; fi; }

echo "== Retour chantier 5 ($([[ $SIM == 1 ]] && echo simulation || echo REEL)) - sauvegarde : $ICI"
# 1. service
if systemctl list-unit-files omni-v5-reponse.service >/dev/null 2>&1 && [[ -e "$UNIT" ]]; then
  f "systemctl disable --now omni-v5-reponse.service"
  f "rm -f '$UNIT'"
  f "rm -rf /etc/systemd/system/omni-v5-reponse.service.d"
  f "systemctl daemon-reload"
else
  echo "service omni-v5-reponse absent : rien à faire"
fi
[[ -d /usr/local/lib/omni-v5-reponse ]] && f "rm -rf /usr/local/lib/omni-v5-reponse"
[[ -d /etc/omni-v5-reponse ]] && f "mkdir -p '$ICI/etat-au-retour' && cp -a /etc/omni-v5-reponse '$ICI/etat-au-retour/etc' && rm -rf /etc/omni-v5-reponse"
for d in /var/lib/omni-v5-reponse /var/lib/private/omni-v5-reponse; do
  [[ -e "$d" ]] && f "mkdir -p '$ICI/etat-au-retour' && cp -a '$d' '$ICI/etat-au-retour/' && rm -rf '$d'"
done
# 2. nginx : retrait du seul bloc balisé, contrôle, reload
if grep -q '# BEGIN OMNI V5 REPONSE' "$NGX" 2>/dev/null; then
  f "cp -a '$NGX' '$ICI/graylog.nginx.au-retour' && sed -i '/# BEGIN OMNI V5 REPONSE/,/# END OMNI V5 REPONSE/d' '$NGX'"
  if [[ $SIM == 0 ]]; then
    if nginx -t 2>&1; then systemctl reload nginx && echo "nginx rechargé"
    else echo "ERREUR nginx -t : remise du fichier d'avant retour"; cp -a "$ICI/graylog.nginx.au-retour" "$NGX"; fi
  else
    echo "[simulation] nginx -t && systemctl reload nginx"
  fi
else
  echo "bloc nginx OMNI V5 REPONSE absent : rien à faire"
fi
# 3. index de test
for i in $(curl -s 'http://127.0.0.1:9200/_cat/indices/restore-test-v5-*?h=index' 2>/dev/null | grep -E '^restore-test-v5-' || true); do
  f "curl -s -X DELETE 'http://127.0.0.1:9200/$i' ; echo"
done
echo "== Fin du retour chantier 5"
