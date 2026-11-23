#!/usr/bin/env bash
# =============================================================================
# migrer-depot-snapshots.sh : relocalisation du dépôt de snapshots OpenSearch
# de /home (graylog_fs) vers /data (graylog_fs_data).
#
#   bash tools/migrer-depot-snapshots.sh                    plan (défaut, lecture seule, GET)
#   sudo bash tools/migrer-depot-snapshots.sh --apply       migration contrôlée
#   sudo bash tools/migrer-depot-snapshots.sh --rollback    retour à graylog_fs
#   sudo bash tools/migrer-depot-snapshots.sh --retirer-ancien
#                                                           désenregistrement de graylog_fs,
#                                                           après 3 snapshots réussis dans le nouveau dépôt
#
# --apply, dans l'ordre, avec arrêt au premier échec :
#   1. contrôles : root, /data monté, OpenSearch vert, aucun snapshot en cours,
#      oms-snap-siem et oms-snap-siem-test inactifs, oms-snap-siem déployé avec
#      la variable DEPOT, place libre suffisante sur /data après le premier snapshot complet ;
#   2. répertoire du nouveau dépôt (propriétaire opensearch, 0750) ;
#   3. path.repo : ajout du nouveau chemin EN GARDANT l'ancien (copie de opensearch.yml dans
#      le répertoire d'état), puis redémarrage contrôlé d'OpenSearch : santé verte avant,
#      attente de l'API puis du vert après ; si l'API ne revient pas, opensearch.yml est
#      restauré et OpenSearch redémarré une seconde fois ;
#   4. enregistrement du dépôt graylog_fs_data (type fs, compress) et vérification (_verify) ;
#   5. bascule de /etc/oms-snap-siem.conf (copie conservée) : DEPOT, DEPOT_CHEMIN et seuils
#      de place libre adaptés à /data (voir SEUILS ci-dessous) ;
#   6. premier snapshot (systemctl start oms-snap-siem.service, premier passage complet,
#      non incrémental) et vérification de son état (SUCCESS, 0 shard en échec).
#      --sans-snapshot laisse ce premier passage au timer de 01:30.
#   L'ancien dépôt graylog_fs reste enregistré et lisible ; ses snapshots ne sont plus
#   tournés (la rotation d'oms-snap-siem ne touche que le dépôt configuré).
#
# --rollback : remet la configuration d'oms-snap-siem sauvegardée par --apply et
#   désenregistre graylog_fs_data (les fichiers restent sur /data). opensearch.yml n'est
#   restauré qu'avec --avec-redemarrage (nouveau redémarrage contrôlé) : le chemin
#   supplémentaire dans path.repo est sans effet tant qu'aucun dépôt ne l'utilise.
#
# --retirer-ancien : refuse tant que graylog_fs_data ne compte pas 3 snapshots oms-sel-*
#   réussis sans shard en échec et que la configuration ne pointe pas dessus ; désenregistre
#   alors graylog_fs (DELETE _snapshot/graylog_fs : enregistrement seulement, aucun fichier
#   supprimé). Le retrait du chemin dans path.repo (au prochain redémarrage planifié) et la
#   suppression des fichiers de /home sont affichés, jamais exécutés.
#
# Variables (tests hors ligne ; jamais nécessaires en production) :
#   OS_URL (http://127.0.0.1:9200), OPENSEARCH_YML (/etc/opensearch/opensearch.yml),
#   SNAP_CONF (/etc/oms-snap-siem.conf), SNAP_BIN (/usr/local/sbin/oms-snap-siem),
#   MIGR_ETAT (/var/lib/oms-migration-snapshots), ANCIEN_DEPOT (graylog_fs),
#   ANCIEN_CHEMIN (/home/siem-backup/opensearch-snapshots), NOUVEAU_DEPOT (graylog_fs_data),
#   NOUVEAU_CHEMIN (/data/siem-backup/opensearch-snapshots), POINT_MONTAGE (/data),
#   PROPRIETAIRE (opensearch), ATTENTE_API_S (600), ATTENTE_VERT_S (1800),
#   OMNI_SIEM_HOME (dépôt pour la lecture facultative du journal Graylog), MIGR_TEST_MODE.
# =============================================================================
set -uo pipefail
export LANG=C.UTF-8

OS="${OS_URL:-http://127.0.0.1:9200}"
YML="${OPENSEARCH_YML:-/etc/opensearch/opensearch.yml}"
CONF="${SNAP_CONF:-/etc/oms-snap-siem.conf}"
SNAP_BIN="${SNAP_BIN:-/usr/local/sbin/oms-snap-siem}"
ETAT="${MIGR_ETAT:-/var/lib/oms-migration-snapshots}"
ANCIEN="${ANCIEN_DEPOT:-graylog_fs}"
ANCIEN_CHEMIN="${ANCIEN_CHEMIN:-/home/siem-backup/opensearch-snapshots}"
NOUVEAU="${NOUVEAU_DEPOT:-graylog_fs_data}"
CHEMIN="${NOUVEAU_CHEMIN:-/data/siem-backup/opensearch-snapshots}"
MONTAGE="${POINT_MONTAGE:-/data}"
PROPRIETAIRE="${PROPRIETAIRE:-opensearch}"
ATTENTE_API_S="${ATTENTE_API_S:-600}"
ATTENTE_VERT_S="${ATTENTE_VERT_S:-1800}"
CANON="${OMNI_SIEM_HOME:-/opt/omni-siem/repository}"
# SEUILS sur /data : omni-disk-guard alerte à 80 % et purge les index les plus anciens à
# 88 %. Le snapshot ne doit jamais provoquer cette purge : il n'est pas lancé sous 25 %
# libres (75 % occupés) et il est annulé sous 15 % libres (85 % occupés).
NOUV_LIBRE_MIN=25
NOUV_LIBRE_ARRET=15
SNAPS_REQUIS=3

MODE=plan; AVEC_SNAPSHOT=1; AVEC_REDEMARRAGE=0
for arg in "$@"; do
  case "$arg" in
    --plan) MODE=plan ;;
    --apply) MODE=apply ;;
    --rollback) MODE=rollback ;;
    --retirer-ancien) MODE=retirer ;;
    --sans-snapshot) AVEC_SNAPSHOT=0 ;;
    --avec-redemarrage) AVEC_REDEMARRAGE=1 ;;
    -h|--help) sed -n '3,50p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "option inconnue : $arg (voir --help)" >&2; exit 2 ;;
  esac
done

BLOCAGES=0
ok()   { echo "  OK      $*"; }
info() { echo "  INFO    $*"; }
bloc() { echo "  BLOCAGE $*"; BLOCAGES=$((BLOCAGES + 1)); }
die()  { echo "ERREUR : $*" >&2; exit 1; }
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT

# os_req METHODE CHEMIN [CORPS] : corps de la réponse dans $TMPD/corps, code HTTP sur stdout.
os_req() {
  local args=(-s -m 60 -o "$TMPD/corps" -w '%{http_code}' -X "$1" "$OS$2")
  [[ -n "${3:-}" ]] && args+=(-H 'Content-Type: application/json' -d "$3")
  curl "${args[@]}" 2>/dev/null || echo 000
}
os_get() { [[ "$(os_req GET "$1")" == 200 ]] && cat "$TMPD/corps"; }
sante()  { os_get "/_cluster/health" | jq -r '.status // "injoignable"' 2>/dev/null || echo injoignable; }
snapshots_en_cours() { os_get "/_snapshot/_status" | jq -r '.snapshots | length' 2>/dev/null || echo "?"; }
depot_existe() { [[ "$(os_req GET "/_snapshot/$1")" == 200 ]] && jq -e --arg d "$1" 'has($d)' "$TMPD/corps" >/dev/null 2>&1; }
# succes_oms_sel DEPOT : nombre de snapshots oms-sel-* SUCCESS sans shard en échec.
succes_oms_sel() {
  os_get "/_snapshot/$1/_all" | jq -r '[.snapshots[]? | select(.snapshot|startswith("oms-sel-"))
     | select(.state=="SUCCESS" and ((.shards.failed // 0) == 0))] | length' 2>/dev/null || echo 0
}
pct_libre() { df --output=pcent "$1" 2>/dev/null | tail -1 | tr -dc 0-9 | awk '{print 100-$1}'; }
go_libres() { df --output=avail -BG "$1" 2>/dev/null | tail -1 | tr -dc 0-9; }
go_taille() { df --output=size -BG "$1" 2>/dev/null | tail -1 | tr -dc 0-9; }
# Premier répertoire existant en remontant (df d'un chemin pas encore créé).
existant() { local p="$1"; while [[ ! -e "$p" && "$p" != / ]]; do p="$(dirname "$p")"; done; echo "$p"; }
service_actif() { [[ "$(systemctl is-active "$1" 2>/dev/null)" == active || "$(systemctl is-active "$1" 2>/dev/null)" == activating ]]; }

# path.repo actuel (liste JSON) ou vide si la ligne est absente ou illisible.
path_repo_json() {
  python3 - "$YML" <<'PY'
import json, re, sys
lignes = [l for l in open(sys.argv[1], encoding="utf-8") if re.match(r"\s*path\.repo\s*:", l)]
if len(lignes) != 1:
    sys.exit(1)
valeur = lignes[0].split(":", 1)[1].split("#", 1)[0].strip()
try:
    liste = json.loads(valeur)
except ValueError:
    sys.exit(1)
if not isinstance(liste, list) or not all(isinstance(x, str) for x in liste):
    sys.exit(1)
print(json.dumps(liste))
PY
}
# ecrire_path_repo FICHIER_SORTIE : copie de opensearch.yml avec le nouveau chemin ajouté.
ecrire_path_repo() {
  python3 - "$YML" "$CHEMIN" "$1" <<'PY'
import json, re, sys
source, chemin, sortie = sys.argv[1:4]
texte = open(source, encoding="utf-8").read().splitlines(keepends=True)
resultat = []
for ligne in texte:
    if re.match(r"\s*path\.repo\s*:", ligne):
        liste = json.loads(ligne.split(":", 1)[1].split("#", 1)[0].strip())
        if chemin not in liste:
            liste.append(chemin)
        ligne = "path.repo: " + json.dumps(liste) + "\n"
    resultat.append(ligne)
open(sortie, "w", encoding="utf-8").writelines(resultat)
PY
}
# Estimation du premier snapshot complet : somme des index retenus par la sélection
# d'oms-snap-siem (même règle préfixe:jours), en Go.
estimation_go() {
  local selection
  selection="$(sed -n 's/^SELECTION="\(.*\)"$/\1/p' "$CONF" 2>/dev/null | tail -1)"
  [[ -n "$selection" ]] || { echo "?"; return; }
  os_get "/_cat/indices?h=index,creation.date,store.size&bytes=b" | awk -v sel="$selection" -v now="$(( $(date +%s) * 1000 ))" '
    BEGIN { n = split(sel, e, " "); for (i = 1; i <= n; i++) { split(e[i], kv, ":"); pre[i] = kv[1]; jours[i] = kv[2] } }
    { for (i = 1; i <= n; i++) if ($1 ~ ("^" pre[i] "_[0-9]+$") && (jours[i] == 0 || $2 >= now - (jours[i] + 1) * 86400000)) { s += $3; break } }
    END { printf "%.0f", s / 1073741824 }'
}

redemarrer_opensearch() {  # $1 = libellé ; retour 0 si vert après redémarrage
  local debut fin t
  echo "== Redémarrage contrôlé d'OpenSearch ($1)"
  [[ "$(sante)" == green ]] || { echo "  OpenSearch n'est pas vert avant redémarrage : abandon"; return 2; }
  [[ "$(snapshots_en_cours)" == 0 ]] || { echo "  snapshot en cours : abandon"; return 2; }
  debut=$(date +%s)
  systemctl restart opensearch.service || { echo "  systemctl restart opensearch a échoué"; return 1; }
  t=0
  until [[ "$(os_req GET /)" == 200 ]]; do
    (( t >= ATTENTE_API_S )) && { echo "  API OpenSearch absente après ${ATTENTE_API_S} s"; return 1; }
    sleep 5; t=$((t + 5))
  done
  echo "  API revenue en $(( $(date +%s) - debut )) s ; attente du vert"
  t=0
  until [[ "$(sante)" == green ]]; do
    (( t >= ATTENTE_VERT_S )) && { echo "  cluster $(sante) après ${ATTENTE_VERT_S} s"; return 3; }
    sleep 10; t=$((t + 10))
  done
  fin=$(date +%s)
  echo "  OpenSearch vert, indisponibilité totale $(( fin - debut )) s"
  return 0
}

conf_valeur() { sed -n "s/^$1=\"\{0,1\}\([^\"]*\)\"\{0,1\}$/\1/p" "$CONF" 2>/dev/null | tail -1; }
# conf_poser CLE VALEUR : remplace la ligne CLE= ou l'ajoute (fichier de configuration oms-snap-siem).
conf_poser() {
  if grep -q "^$1=" "$CONF"; then sed -i "s|^$1=.*|$1=$2|" "$CONF"; else echo "$1=$2" >> "$CONF"; fi
}

# ----------------------------------------------------------------------------- constat
constat() {
  echo "Relocalisation du dépôt de snapshots OpenSearch (mode : $MODE)"
  echo "  ancien : $ANCIEN ($ANCIEN_CHEMIN)"
  echo "  nouveau : $NOUVEAU ($CHEMIN)"
  echo
  echo "[1] OpenSearch"
  local st; st="$(sante)"
  [[ "$st" == green ]] && ok "cluster vert" || bloc "cluster : $st"
  local enc; enc="$(snapshots_en_cours)"
  [[ "$enc" == 0 ]] && ok "aucun snapshot en cours" || bloc "snapshot(s) en cours : $enc"
  echo "[2] path.repo ($YML)"
  PR="$(path_repo_json)" || { bloc "path.repo absent, multiple ou illisible dans $YML"; PR="[]"; }
  info "actuel : $PR"
  if jq -e --arg c "$CHEMIN" 'index($c) != null' <<<"$PR" >/dev/null; then
    ok "le nouveau chemin est déjà déclaré : aucun redémarrage nécessaire"; REDEMARRAGE=0
  else
    info "à ajouter : $CHEMIN (l'ancien est conservé) ; redémarrage d'OpenSearch nécessaire"; REDEMARRAGE=1
  fi
  echo "[3] Dépôts enregistrés"
  if depot_existe "$ANCIEN"; then ok "$ANCIEN enregistré, $(succes_oms_sel "$ANCIEN") snapshot(s) oms-sel réussi(s)"; else info "$ANCIEN non enregistré"; fi
  if depot_existe "$NOUVEAU"; then ok "$NOUVEAU enregistré, $(succes_oms_sel "$NOUVEAU") snapshot(s) oms-sel réussi(s) (requis avant retrait : $SNAPS_REQUIS)"; else info "$NOUVEAU non enregistré"; fi
  echo "[4] oms-snap-siem"
  local depot_conf; depot_conf="$(conf_valeur DEPOT)"; info "dépôt configuré : ${depot_conf:-graylog_fs (défaut)}"
  grep -q 'REPO="\$DEPOT"' "$SNAP_BIN" 2>/dev/null && ok "$SNAP_BIN gère DEPOT/DEPOT_CHEMIN" \
    || bloc "$SNAP_BIN ne gère pas DEPOT : déployer d'abord deploye/sbin/oms-snap-siem (omni-deploy)"
  for u in oms-snap-siem.service oms-snap-siem-test.service; do
    service_actif "$u" && bloc "$u en cours d'exécution" || ok "$u inactif"
  done
  echo "[5] Place disque"
  local base; base="$(existant "$CHEMIN")"
  if [[ "$MONTAGE" != / ]] && ! findmnt -n "$MONTAGE" >/dev/null 2>&1; then bloc "$MONTAGE non monté"; fi
  local est libres taille occ_apres
  est="$(estimation_go)"; libres="$(go_libres "$base")"; taille="$(go_taille "$base")"
  info "$(existant "$ANCIEN_CHEMIN") : $(pct_libre "$(existant "$ANCIEN_CHEMIN")") % libres ; $base : $(pct_libre "$base") % libres (${libres:-?} Go)"
  if [[ "$est" =~ ^[0-9]+$ && "$libres" =~ ^[0-9]+$ && "$taille" =~ ^[1-9][0-9]*$ ]]; then
    occ_apres=$(( 100 - (libres - est) * 100 / taille ))
    info "premier snapshot complet estimé : ~${est} Go bruts (sélection de $CONF) ; occupation estimée ensuite : ${occ_apres} %"
    (( occ_apres < 100 - NOUV_LIBRE_MIN )) && ok "reste sous $(( 100 - NOUV_LIBRE_MIN )) % après le premier snapshot" \
      || bloc "occupation estimée ${occ_apres} % : au-delà du seuil de lancement ($(( 100 - NOUV_LIBRE_MIN )) %)"
  else
    bloc "estimation de taille impossible (sélection ou df illisibles)"
  fi
  info "le nouveau dépôt partage le disque physique de path.data : il protège contre une erreur logique (suppression, corruption d'index), pas contre la perte de ce disque"
  echo "[6] Impact d'un redémarrage d'OpenSearch (lecture seule)"
  impact_redemarrage
}

impact_redemarrage() {
  local j
  if [[ -r "$CANON/00-vars.env" && -r "$CANON/lib-graylog.sh" ]]; then
    j="$(cd "$CANON" && bash -c 'set -a; . ./00-vars.env; set +a; . ./lib-graylog.sh; api_get /system/journal' 2>/dev/null)"
  fi
  if jq -e '.journal_size_limit' <<<"${j:-}" >/dev/null 2>&1; then
    jq -r '"  INFO    journal Graylog : \(.journal_size/1048576|floor) Mo utilisés sur \(.journal_size_limit/1073741824|floor) Go, \(.uncommitted_journal_entries) message(s) non écrits, \(.append_events_per_second) msg/s en entrée",
      (if .append_events_per_second > 0 then "  INFO    à 1,8 Ko par message (mesure du 22/11/2026), le journal absorbe environ \((.journal_size_limit / (.append_events_per_second * 1800) / 3600 * 10 | floor) / 10) h d indisponibilité d OpenSearch (plafond d âge du journal : \((.journal_config.max_age // 0) / 3600000) h) ; débit instantané, variable ; 7 min représentent environ \((.append_events_per_second * 420 * 1800 / 1048576) | floor) Mo" else empty end)' <<<"$j"
  else
    info "journal Graylog non lu (00-vars.env du dépôt canonique illisible) : voir docs/exploitation/GUIDE-EXPLOITATION.md"
  fi
  local hist
  hist="$(journalctl -u opensearch.service -o short-iso --no-pager 2>/dev/null \
    | awk '/Starting opensearch/ {d=$1} /Started opensearch/ && d {print "lancé " d " -> prêt " $1; d=""}' | tail -3)"
  [[ -n "$hist" ]] && while read -r ligne; do info "démarrage récent : $ligne"; done <<<"$hist"
  info "relevé du 22/11/2026 : arrêt 8 à 25 s, démarrage 60 à 80 s, retour au vert 3 à 6,5 min après le démarrage"
}

# ----------------------------------------------------------------------------- modes
mode_plan() {
  constat
  echo
  echo "Plan ($BLOCAGES blocage(s)). Appliquer : sudo bash $0 --apply"
  exit $(( BLOCAGES > 0 ? 2 : 0 ))
}

mode_apply() {
  [[ $EUID -eq 0 || "${MIGR_TEST_MODE:-}" == 1 ]] || die "--apply exige root"
  constat
  echo
  [[ $BLOCAGES -eq 0 ]] || die "migration refusée : $BLOCAGES blocage(s)"
  local stamp; stamp="$(date +%Y%m%d-%H%M%S)"
  install -d -m 700 "$ETAT"
  echo "== Répertoire du nouveau dépôt"
  if [[ "${MIGR_TEST_MODE:-}" == 1 ]]; then install -d -m 750 "$CHEMIN"
  else install -d -m 750 -o "$PROPRIETAIRE" -g "$PROPRIETAIRE" "$CHEMIN"; fi
  ok "$CHEMIN"
  if [[ $REDEMARRAGE == 1 ]]; then
    echo "== path.repo"
    cp -p "$YML" "$ETAT/opensearch.yml.$stamp"
    echo "YML_SAUVEGARDE=$ETAT/opensearch.yml.$stamp" >> "$ETAT/migration.env"
    ecrire_path_repo "$TMPD/opensearch.yml" || die "réécriture de path.repo impossible"
    cat "$TMPD/opensearch.yml" > "$YML"   # garde propriétaire et droits du fichier en place
    ok "path.repo : $(path_repo_json)"
    redemarrer_opensearch "ajout de $CHEMIN à path.repo"; local rc=$?
    if [[ $rc == 1 ]]; then
      echo "== Échec : restauration de opensearch.yml et nouveau redémarrage"
      cat "$ETAT/opensearch.yml.$stamp" > "$YML"
      systemctl restart opensearch.service
      die "OpenSearch n'est pas revenu avec la nouvelle configuration ; configuration d'origine restaurée"
    elif [[ $rc != 0 ]]; then
      die "OpenSearch n'est pas vert après redémarrage ; rien d'autre n'est modifié (contrôler _cluster/health)"
    fi
    os_get "/_nodes/settings" | jq -e --arg c "$CHEMIN" '[.nodes[].settings.path.repo] | flatten | index($c) != null' >/dev/null \
      || die "path.repo du nœud n'inclut pas $CHEMIN après redémarrage"
    ok "path.repo actif sur le nœud"
  fi
  echo "== Enregistrement du dépôt $NOUVEAU"
  if depot_existe "$NOUVEAU"; then
    [[ "$(jq -r --arg d "$NOUVEAU" '.[$d].settings.location' "$TMPD/corps")" == "$CHEMIN" ]] \
      || die "$NOUVEAU existe déjà avec un autre emplacement"
    ok "$NOUVEAU déjà enregistré sur $CHEMIN"
  else
    local code
    code="$(os_req PUT "/_snapshot/$NOUVEAU" "$(jq -nc --arg l "$CHEMIN" '{type:"fs",settings:{location:$l,compress:true}}')")"
    [[ "$code" == 200 ]] || die "enregistrement refusé (HTTP $code) : $(head -c 300 "$TMPD/corps")"
    ok "$NOUVEAU enregistré"
  fi
  [[ "$(os_req POST "/_snapshot/$NOUVEAU/_verify")" == 200 ]] || die "vérification du dépôt en échec : $(head -c 300 "$TMPD/corps")"
  ok "dépôt vérifié (écriture/lecture par le nœud)"
  echo "== Bascule de $CONF"
  if [[ ! -f "$ETAT/oms-snap-siem.conf.avant" ]]; then
    if [[ -f "$CONF" ]]; then cp -p "$CONF" "$ETAT/oms-snap-siem.conf.avant"; else : > "$ETAT/oms-snap-siem.conf.absent"; fi
  fi
  [[ -f "$CONF" ]] || install -m 644 /dev/null "$CONF"
  conf_poser DEPOT "$NOUVEAU"
  conf_poser DEPOT_CHEMIN "$CHEMIN"
  conf_poser LIBRE_MIN_PCT "$NOUV_LIBRE_MIN"
  conf_poser LIBRE_ARRET_PCT "$NOUV_LIBRE_ARRET"
  ok "DEPOT=$NOUVEAU DEPOT_CHEMIN=$CHEMIN LIBRE_MIN_PCT=$NOUV_LIBRE_MIN LIBRE_ARRET_PCT=$NOUV_LIBRE_ARRET (copie : $ETAT/oms-snap-siem.conf.avant)"
  if [[ $AVEC_SNAPSHOT == 1 ]]; then
    echo "== Premier snapshot (complet, peut durer plusieurs heures)"
    systemctl start oms-snap-siem.service || die "oms-snap-siem en échec : journalctl -u oms-snap-siem.service"
    local n; n="$(succes_oms_sel "$NOUVEAU")"
    [[ "$n" =~ ^[1-9][0-9]*$ ]] || die "aucun snapshot oms-sel réussi dans $NOUVEAU après le premier passage"
    ok "$n snapshot(s) oms-sel réussi(s) dans $NOUVEAU"
  else
    info "premier snapshot laissé au timer oms-snap-siem (01:30)"
  fi
  cat <<EOF

Migration appliquée. L'ancien dépôt $ANCIEN reste enregistré et lisible.
Ensuite :
  - test de restauration sur le nouveau dépôt : sudo systemctl start oms-snap-siem-test.service
  - après $SNAPS_REQUIS snapshots réussis dans $NOUVEAU : sudo bash $0 --retirer-ancien
Retour arrière : sudo bash $0 --rollback [--avec-redemarrage]
EOF
}

mode_rollback() {
  [[ $EUID -eq 0 || "${MIGR_TEST_MODE:-}" == 1 ]] || die "--rollback exige root"
  echo "Retour arrière de la relocalisation des snapshots"
  [[ "$(snapshots_en_cours)" == 0 ]] || die "snapshot en cours : attendre sa fin"
  service_actif oms-snap-siem.service && die "oms-snap-siem en cours d'exécution"
  if [[ -f "$ETAT/oms-snap-siem.conf.avant" ]]; then
    cp -p "$ETAT/oms-snap-siem.conf.avant" "$CONF"; ok "$CONF restauré"
  elif [[ -f "$ETAT/oms-snap-siem.conf.absent" ]]; then
    rm -f "$CONF"; ok "$CONF supprimé (absent avant la migration)"
  else
    info "aucune copie de $CONF dans $ETAT : configuration laissée telle quelle"
  fi
  depot_existe "$ANCIEN" || die "$ANCIEN n'est plus enregistré : le ré-enregistrer (08-backup.sh, étape 1) avant de désenregistrer $NOUVEAU"
  if depot_existe "$NOUVEAU"; then
    [[ "$(os_req DELETE "/_snapshot/$NOUVEAU")" == 200 ]] && ok "$NOUVEAU désenregistré (fichiers conservés dans $CHEMIN)" \
      || die "désenregistrement de $NOUVEAU refusé : $(head -c 300 "$TMPD/corps")"
  else
    info "$NOUVEAU déjà absent"
  fi
  local sauvegarde; sauvegarde="$(sed -n 's/^YML_SAUVEGARDE=//p' "$ETAT/migration.env" 2>/dev/null | head -1)"
  if [[ $AVEC_REDEMARRAGE == 1 && -f "$sauvegarde" ]]; then
    cat "$sauvegarde" > "$YML"; ok "opensearch.yml restauré depuis $sauvegarde"
    redemarrer_opensearch "retour arrière de path.repo" || die "OpenSearch non vert après le retour arrière"
  elif [[ -n "$sauvegarde" ]]; then
    info "path.repo garde $CHEMIN (sans effet sans dépôt) ; restauration : --rollback --avec-redemarrage"
  fi
  echo "Retour arrière terminé : oms-snap-siem écrit de nouveau dans $ANCIEN."
}

mode_retirer() {
  echo "Retrait de l'ancien dépôt $ANCIEN"
  local n; n="$(succes_oms_sel "$NOUVEAU")"
  [[ "$(conf_valeur DEPOT)" == "$NOUVEAU" ]] || bloc "$CONF ne pointe pas sur $NOUVEAU"
  [[ "$n" =~ ^[0-9]+$ ]] && (( n >= SNAPS_REQUIS )) && ok "$NOUVEAU : $n snapshot(s) oms-sel réussi(s)" \
    || bloc "$NOUVEAU : ${n:-0} snapshot(s) oms-sel réussi(s), $SNAPS_REQUIS requis"
  depot_existe "$ANCIEN" || { info "$ANCIEN déjà désenregistré"; exit 0; }
  [[ $BLOCAGES -eq 0 ]] || die "retrait refusé : $BLOCAGES blocage(s)"
  [[ $EUID -eq 0 || "${MIGR_TEST_MODE:-}" == 1 ]] || die "--retirer-ancien exige root"
  [[ "$(snapshots_en_cours)" == 0 ]] || die "snapshot en cours : attendre sa fin"
  [[ "$(os_req DELETE "/_snapshot/$ANCIEN")" == 200 ]] || die "désenregistrement refusé : $(head -c 300 "$TMPD/corps")"
  ok "$ANCIEN désenregistré ; ses fichiers restent dans $ANCIEN_CHEMIN"
  cat <<EOF
Étapes manuelles restantes, NON exécutées :
  - retirer $ANCIEN_CHEMIN de path.repo dans $YML au prochain redémarrage planifié d'OpenSearch ;
  - supprimer les fichiers après décision : rm -rf $ANCIEN_CHEMIN/*  (environ 500 Go sur /home).
Ré-enregistrement en cas de besoin (lecture des anciens snapshots) :
  curl -s -X PUT $OS/_snapshot/$ANCIEN -H 'Content-Type: application/json' -d '{"type":"fs","settings":{"location":"$ANCIEN_CHEMIN","compress":true}}'
EOF
}

case "$MODE" in
  plan) mode_plan ;;
  apply) mode_apply ;;
  rollback) mode_rollback ;;
  retirer) mode_retirer ;;
esac
