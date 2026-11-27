#!/usr/bin/env bash
# Chantier 5 SIEM v5 - installation de omni-v5-reponse (SIMULATION) + bloc nginx /m/reponse/
# Usage : bash installer.sh <dossier_sources> [--simuler]
#   <dossier_sources> contient les fichiers de ce dossier, avec reponse.env (copie adaptée de
#   reponse.env.exemple) et, à la première installation, cibles-protegees (copie complétée de
#   cibles-protegees.exemple). Un fichier /etc/omni-v5-reponse/cibles-protegees existant n'est jamais remplacé.
# Ne redémarre jamais graylog-server / opensearch / mongod ; nginx : test puis reload.
set -uo pipefail
SRC="${1:?dossier sources}"; SIM=0; [[ "${2:-}" == "--simuler" ]] && SIM=1
NGX=/etc/nginx/sites-enabled/graylog
CIB=/etc/omni-v5-reponse/cibles-protegees
f() { if [[ $SIM == 1 ]]; then echo "[simulation] $*"; else echo "[install] $*"; eval "$*" || { echo "ECHEC : $*"; exit 1; }; fi; }
for x in omni_v5_reponse.py extraire-soc-admins.sh omni-v5-reponse.service reponse.env nginx-bloc-reponse.conf; do
  [[ -s "$SRC/$x" ]] || { echo "manquant : $SRC/$x"; exit 1; }
  sed -i 's/\r$//' "$SRC/$x"
done
if [[ ! -s "$CIB" ]]; then
  [[ -s "$SRC/cibles-protegees" ]] || { echo "manquant : $SRC/cibles-protegees (copie complétée de cibles-protegees.exemple)"; exit 1; }
  cmp -s "$SRC/cibles-protegees" "$SRC/cibles-protegees.exemple" && { echo "cibles-protegees = modèle non complété : refus"; exit 1; }
  sed -i 's/\r$//' "$SRC/cibles-protegees"
fi
python3 -I -m py_compile "$SRC/omni_v5_reponse.py" || { echo "erreur de syntaxe Python"; exit 1; }
ss -ltn | grep -q '127.0.0.1:8091 ' && ! systemctl is-active -q omni-v5-reponse && { echo "port 8091 déjà pris"; exit 1; }
f "install -d -m 755 /usr/local/lib/omni-v5-reponse /etc/omni-v5-reponse"
f "install -m 644 '$SRC/omni_v5_reponse.py' /usr/local/lib/omni-v5-reponse/omni_v5_reponse.py"
f "install -m 755 '$SRC/extraire-soc-admins.sh' /usr/local/lib/omni-v5-reponse/extraire-soc-admins.sh"
f "install -m 644 '$SRC/reponse.env' /etc/omni-v5-reponse/reponse.env"
[[ -s "$CIB" ]] || f "install -m 644 '$SRC/cibles-protegees' '$CIB'"
f "install -m 644 '$SRC/omni-v5-reponse.service' /etc/systemd/system/omni-v5-reponse.service"
f "systemctl daemon-reload"
f "systemctl enable --now omni-v5-reponse.service"
[[ $SIM == 0 ]] && { sleep 2; systemctl is-active omni-v5-reponse; ss -ltnp | grep ':8091 '; }
# nginx : insertion idempotente avant le bloc /m/ (cookie de session Path=/m)
if grep -q '# BEGIN OMNI V5 REPONSE' "$NGX"; then
  echo "bloc nginx déjà présent"
else
  ANCRE='    # 12/11/2026 : /m/ remplacée par /soc/'
  grep -qF "$ANCRE" "$NGX" || { echo "ancre nginx introuvable : rien modifié"; exit 1; }
  if [[ $SIM == 1 ]]; then
    echo "[simulation] insertion du bloc avant : $ANCRE ; nginx -t ; systemctl reload nginx"
  else
    cp -a "$NGX" "/tmp/v5rep-graylog.nginx.$$"
    python3 -I - "$NGX" "$SRC/nginx-bloc-reponse.conf" "$ANCRE" <<'PY'
import sys
p, b, a = sys.argv[1:4]
t = open(p, encoding="utf-8").read(); bloc = open(b, encoding="utf-8").read()
assert t.count(a) == 1
open(p, "w", encoding="utf-8").write(t.replace(a, bloc + a, 1))
PY
    if nginx -t 2>&1 | tail -2; nginx -t >/dev/null 2>&1; then
      systemctl reload nginx && echo "nginx rechargé"
    else
      echo "nginx -t en ERREUR : remise du fichier"; cp -a "/tmp/v5rep-graylog.nginx.$$" "$NGX"; exit 1
    fi
    rm -f "/tmp/v5rep-graylog.nginx.$$"
  fi
fi
echo "installation terminée"
