# shellcheck shell=bash
# ==============================================================================
# lib-regles-versionnees.sh - Regles de pipeline versionnees raccordees a des
# pipelines possedes par d'autres scripts.
#
#   Inventaire unique : objets-graylog/raccordements.txt
#     titre|fichier .rule|description|pipeline|etape|position (debut ou fin)
#   Sources uniques : les fichiers .rule designes (objets-graylog/regles/,
#   tools/alertes-v2/regles/). Aucune copie de leur contenu ailleurs.
#
#   Les scripts proprietaires d'un pipeline (49-expo-port-class.sh,
#   49-enrich-lots.sh, 81-fp-allowlist.sh ; tools/omni-v3/v3_build.py en a
#   l'equivalent Python) inserent eux-memes ces regles dans la source complete
#   qu'ils ecrivent : un rejeu de ces scripts ne les retire donc plus.
#
#   Fonctions pures (aucun appel API, utilisables hors ligne) :
#     raccordements_pipeline <pipeline>     lignes titre|fichier|desc|etape|position
#     inclure_regles_versionnees <pipeline> source de base (stdin) -> source complete
#     verifier_raccordements                coherence inventaire / fichiers .rule
#     proprietaire_pipeline <pipeline>      script qui ecrit ce pipeline
#   Fonction API (lib-graylog.sh sourcee au prealable) :
#     ensure_regles_versionnees <pipeline>  cree les regles absentes ; une regle
#                                           presente n'est jamais modifiee
#                                           (ecart signale).
#   Ne depend ni de 00-vars.env ni de lib-graylog.sh pour les fonctions pures.
# ==============================================================================

OMNI_DEPOT_RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RACCORDEMENTS_FICHIER="${RACCORDEMENTS_FICHIER:-${OMNI_DEPOT_RACINE}/objets-graylog/raccordements.txt}"

# Lignes utiles de l'inventaire (sans commentaires ni lignes vides).
_raccordements_lignes() {
  [[ -r "${RACCORDEMENTS_FICHIER}" ]] || { echo "inventaire illisible : ${RACCORDEMENTS_FICHIER}" >&2; return 1; }
  grep -vE '^[[:space:]]*(#|$)' "${RACCORDEMENTS_FICHIER}"
}

# raccordements_pipeline <pipeline> : titre|fichier|description|etape|position
raccordements_pipeline() {
  local LIGNES
  LIGNES="$(_raccordements_lignes)" || return 1
  awk -F'|' -v p="$1" '$4 == p { print $1 "|" $2 "|" $3 "|" $5 "|" $6 }' <<< "${LIGNES}"
}

# proprietaire_pipeline <pipeline> : script qui ecrit la source complete du pipeline.
proprietaire_pipeline() {
  case "$1" in
    "OMNI - Exposition reseau") echo "49-expo-port-class.sh (ou 49-enrich-lots.sh)" ;;
    "OMNI - Allowlist FP") echo "81-fp-allowlist.sh" ;;
    "OMNI v3 - Detections et correlation") echo "tools/omni-v3/v3_build.py --appliquer" ;;
    *) echo "inconnu" ;;
  esac
}

# verifier_raccordements : 6 champs, position debut|fin, etape numerique, fichier
# present qui declare bien rule "<titre>", titres uniques. Code 1 si un defaut.
verifier_raccordements() {
  local LIGNES TITRE FICHIER _DESC PIPE ETAPE POS RESTE RC=0
  LIGNES="$(_raccordements_lignes)" || return 1
  while IFS='|' read -r TITRE FICHIER _DESC PIPE ETAPE POS RESTE; do
    if [[ -z "${POS}" || -n "${RESTE}" ]]; then
      echo "ligne mal formee (6 champs attendus) : ${TITRE}" >&2; RC=1; continue
    fi
    [[ "${POS}" == "debut" || "${POS}" == "fin" ]] || { echo "${TITRE} : position '${POS}' (debut|fin)" >&2; RC=1; }
    [[ "${ETAPE}" =~ ^-?[0-9]+$ ]] || { echo "${TITRE} : etape '${ETAPE}' non numerique" >&2; RC=1; }
    [[ -n "${PIPE}" ]] || { echo "${TITRE} : pipeline vide" >&2; RC=1; }
    if [[ ! -r "${OMNI_DEPOT_RACINE}/${FICHIER}" ]]; then
      echo "${TITRE} : source absente ${FICHIER}" >&2; RC=1
    elif ! grep -q "^rule \"${TITRE}\"" "${OMNI_DEPOT_RACINE}/${FICHIER}"; then
      echo "${FICHIER} ne declare pas rule \"${TITRE}\"" >&2; RC=1
    fi
  done <<< "${LIGNES}"
  if [[ -n "$(cut -d'|' -f1 <<< "${LIGNES}" | sort | uniq -d)" ]]; then
    echo "titres en double dans ${RACCORDEMENTS_FICHIER}" >&2; RC=1
  fi
  return "${RC}"
}

# inclure_regles_versionnees <pipeline> : lit la source de base du pipeline sur
# stdin, ecrit la source complete. Pour chaque regle versionnee du pipeline :
#   position debut -> en tete de son etape, dans l'ordre de l'inventaire ;
#   position fin   -> en fin de son etape, dans l'ordre de l'inventaire ;
#   etape absente  -> creee (match either) a sa place dans l'ordre numerique.
# Une regle deja presente dans la source n'est pas dupliquee. Rien n'est retire.
inclure_regles_versionnees() {
  local ENTREES
  ENTREES="$(raccordements_pipeline "$1" | cut -d'|' -f1,4,5)" || return 1
  awk -v entrees="${ENTREES}" '
    function regle(t) { if (!(t in present)) { print "rule \"" t "\""; present[t] = 1 } }
    function debut(s,  i) { for (i = 1; i <= n; i++) if (E[i] == s && P[i] == "debut") regle(T[i]) }
    function fin(s,  i)   { for (i = 1; i <= n; i++) if (E[i] == s && P[i] == "fin") regle(T[i]) }
    # etapes de l inventaire absentes de la base, de numero < borne, dans l ordre
    function nouvelles(borne, illimite,  i, j, k, m, tmp, L) {
      m = 0
      for (i = 1; i <= ns; i++) if (!(S[i] in base) && !(S[i] in emise) && (illimite || S[i] < borne)) L[++m] = S[i]
      for (j = 2; j <= m; j++) { tmp = L[j]; for (k = j - 1; k >= 1 && L[k] > tmp; k--) L[k + 1] = L[k]; L[k + 1] = tmp }
      for (j = 1; j <= m; j++) { emise[L[j]] = 1; print "stage " L[j] " match either"; debut(L[j]); fin(L[j]) }
    }
    BEGIN {
      n = 0; ns = 0
      m = split(entrees, X, "\n")
      for (i = 1; i <= m; i++) {
        if (X[i] == "") continue
        split(X[i], c, "|"); n++; T[n] = c[1]; E[n] = c[2] + 0; P[n] = c[3]
        if (!(E[n] in vue)) { vue[E[n]] = 1; S[++ns] = E[n] }
      }
    }
    { ligne[++nl] = $0
      if ($0 ~ /^[[:space:]]*stage[[:space:]]+-?[0-9]+/) base[$2 + 0] = 1
      l = $0; gsub(/^[[:space:]]+|[[:space:]]+$/, "", l)
      if (l ~ /^rule "[^"]*"$/) { sub(/^rule "/, "", l); sub(/"$/, "", l); present[l] = 1 }
    }
    END {
      cour = ""
      for (i = 1; i <= nl; i++) {
        x = ligne[i]
        if (x ~ /^[[:space:]]*stage[[:space:]]+-?[0-9]+/) {
          split(x, f); s = f[2] + 0
          if (cour != "") fin(cour)
          nouvelles(s, 0)
          print x; debut(s); cour = s; continue
        }
        if (x ~ /^[[:space:]]*end[[:space:]]*$/) {
          if (cour != "") fin(cour)
          cour = ""; nouvelles(0, 1); print x; continue
        }
        print x
      }
    }'
}

# _normaliser_source : blancs de fin de ligne et lignes vides finales retires
# (la production stocke certaines regles sans saut de ligne final).
_normaliser_source() { sed -e 's/[[:space:]]*$//' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}'; }

# ensure_regles_versionnees <pipeline> : cree (POST) les regles versionnees du
# pipeline absentes de Graylog, avec la description de l'inventaire. Une regle
# presente n'est jamais modifiee : un ecart de source est seulement signale
# (meme politique que 26-graylog-objets-manuels.sh). Code 1 si un fichier
# manque ou si une creation est refusee.
ensure_regles_versionnees() {
  local PIPE="$1" LIGNES REGLES TITRE FICHIER DESC _ETAPE _POS COURANTE ID RC=0
  LIGNES="$(raccordements_pipeline "${PIPE}")" || return 1
  [[ -n "${LIGNES}" ]] || return 0
  REGLES="$(api_get "/system/pipelines/rule")" || { warn "lecture des regles impossible"; return 1; }
  while IFS='|' read -r TITRE FICHIER DESC _ETAPE _POS; do
    FICHIER="${OMNI_DEPOT_RACINE}/${FICHIER}"
    [[ -r "${FICHIER}" ]] || { warn "source absente : ${FICHIER}"; RC=1; continue; }
    COURANTE="$(jq -r --arg t "${TITRE}" '[.[] | select(.title == $t)][0] // empty | .source' <<< "${REGLES}")"
    if [[ -n "${COURANTE}" ]]; then
      if [[ "$(printf '%s' "${COURANTE}" | _normaliser_source)" == "$(_normaliser_source < "${FICHIER}")" ]]; then
        skip "regle versionnee '${TITRE}' inchangee"
      else
        warn "regle versionnee '${TITRE}' : source en service differente de ${FICHIER#"${OMNI_DEPOT_RACINE}"/} (non modifiee)"
      fi
      continue
    fi
    ID="$(jq -n --arg t "${TITRE}" --arg d "${DESC}" --rawfile s "${FICHIER}" '{title: $t, description: $d, source: $s}' \
          | api_post "/system/pipelines/rule" | jqr '.id')"
    if [[ -n "${ID}" && "${ID}" != "null" ]]; then ok "regle versionnee '${TITRE}' (${ID})"; else warn "regle versionnee '${TITRE}' REFUSEE"; RC=1; fi
  done <<< "${LIGNES}"
  return "${RC}"
}
