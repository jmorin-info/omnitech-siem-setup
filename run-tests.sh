#!/usr/bin/env bash
# run-tests.sh — suite de tests hors-ligne (aucun OpenSearch / Graylog requis).
#
#   1. py_compile  : les sources Python compilent (oms-ml + oms-xdr + backend) ;
#   2. pytest      : rédaction du backend mobile (tests/) ;
#   3. pytest      : oms-ml anomalie + réduction de FP (oms-ml/tests/) ;
#   4. pytest      : oms-xdr corrélation + robustesse (oms-xdr/tests/).
#
# Interpréteur : on privilégie le venv oms-ml (numpy/sklearn/joblib présents),
# car les tests ML en ont besoin ; le backend mobile s'importe en stdlib seule.
# pytest est garanti dans ce venv (installé au besoin, best-effort).
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 2

# --- choix de l'interpréteur ------------------------------------------------
pick_py() {
  for p in \
    "$ROOT/oms-ml/.venv/bin/python" \
    "$ROOT/.venv/bin/python" \
    "$(command -v python3 || true)"; do
    if [ -n "$p" ] && [ -x "$p" ]; then
      # le venv ML doit voir numpy (sinon les tests anomaly échouent à l'import)
      if "$p" -c "import numpy, sklearn" >/dev/null 2>&1; then echo "$p"; return 0; fi
    fi
  done
  # repli : premier python exécutable trouvé (les tests ML seront alors skippés)
  for p in "$ROOT/oms-ml/.venv/bin/python" "$(command -v python3 || true)"; do
    [ -n "$p" ] && [ -x "$p" ] && { echo "$p"; return 0; }
  done
  return 1
}

PY="$(pick_py)" || { echo "FATAL: aucun interpréteur Python utilisable" >&2; exit 2; }
echo "== interpréteur : $PY"
"$PY" --version

# pytest disponible ? sinon installation best-effort (sans réseau -> message clair)
if ! "$PY" -c "import pytest" >/dev/null 2>&1; then
  echo "== pytest absent : tentative d'installation dans le venv..."
  "$PY" -m pip install --quiet --disable-pip-version-check pytest >/dev/null 2>&1 || true
fi
if ! "$PY" -c "import pytest" >/dev/null 2>&1; then
  echo "FATAL: pytest indisponible (installez-le : '$PY -m pip install pytest')" >&2
  exit 2
fi

rc=0

# --- 1) compilation des sources --------------------------------------------
# py_compile ne prend que des FICHIERS (pas un dossier) : on énumère les .py.
echo
echo "== py_compile (sources)"
COMPILE_FILES=()
if [ -d "$ROOT/oms-ml/oms_ml" ]; then
  while IFS= read -r f; do COMPILE_FILES+=("$f"); done \
    < <(find "$ROOT/oms-ml/oms_ml" -name '*.py' -not -path '*/__pycache__/*' | sort)
fi
if [ -d "$ROOT/oms-xdr/oms_xdr" ]; then
  while IFS= read -r f; do COMPILE_FILES+=("$f"); done \
    < <(find "$ROOT/oms-xdr/oms_xdr" -name '*.py' -not -path '*/__pycache__/*' | sort)
fi
# backend mobile : nom de fichier à tiret -> chemin explicite (un seul fichier .py)
[ -f "$ROOT/mobile/omni-mobile-api.py" ] && COMPILE_FILES+=("$ROOT/mobile/omni-mobile-api.py")
if [ "${#COMPILE_FILES[@]}" -gt 0 ]; then
  if "$PY" -m py_compile "${COMPILE_FILES[@]}"; then
    echo "   OK : ${#COMPILE_FILES[@]} fichier(s) compilé(s)"
  else
    echo "   ECHEC py_compile"; rc=1
  fi
else
  echo "   (aucune source à compiler trouvée)"
fi

# --- 2) tests de rédaction (backend mobile) --------------------------------
echo
echo "== pytest : rédaction backend mobile (tests/)"
if [ -d "$ROOT/tests" ]; then
  "$PY" -m pytest "$ROOT/tests" -q || rc=1
else
  echo "   (dossier tests/ absent — ignoré)"
fi

# --- 3) tests oms-ml (anomalie + FP) ---------------------------------------
echo
echo "== pytest : oms-ml (oms-ml/tests/)"
if [ -d "$ROOT/oms-ml/tests" ]; then
  ( cd "$ROOT/oms-ml" && "$PY" -m pytest tests -q ) || rc=1
else
  echo "   (dossier oms-ml/tests/ absent — ignoré)"
fi

# --- 4) tests oms-xdr (corrélation + robustesse) ---------------------------
# Lancés depuis oms-xdr/ pour que le package oms_xdr s'importe (PyYAML requis,
# présent dans le venv ML). Aucun appel réseau : GraylogClient est simulé.
echo
echo "== pytest : oms-xdr (oms-xdr/tests/)"
if [ -d "$ROOT/oms-xdr/tests" ] && "$PY" -c "import yaml" >/dev/null 2>&1; then
  ( cd "$ROOT/oms-xdr" && "$PY" -m pytest tests -q ) || rc=1
elif [ -d "$ROOT/oms-xdr/tests" ]; then
  echo "   (PyYAML absent de l'interpréteur — oms-xdr ignoré)"
else
  echo "   (dossier oms-xdr/tests/ absent — ignoré)"
fi

echo
if [ "$rc" -eq 0 ]; then
  echo "== RESULTAT : OK (toutes les suites passent)"
else
  echo "== RESULTAT : ECHEC (voir ci-dessus)"
fi
exit "$rc"
