#!/usr/bin/env bash
# All offline suites. Install requirements-dev.txt in a venv before running.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PY="${OMNI_TEST_PYTHON:-}"
if [[ -z "$PY" ]]; then
  for candidate in "$ROOT/.venv/bin/python" "$ROOT/oms-ml/.venv/bin/python" "$(command -v python3 || true)"; do
    if [[ -x "$candidate" ]]; then PY="$candidate"; break; fi
  done
fi
[[ -n "$PY" && -x "$PY" ]] || { echo "Python required (or set OMNI_TEST_PYTHON)." >&2; exit 2; }
"$PY" -c 'import pytest, yaml, requests, numpy, sklearn, joblib' || {
  echo "Missing test dependencies: install requirements-dev.txt in the selected venv." >&2; exit 2;
}
echo "Python: $PY"
"$PY" --version
rc=0
"$PY" -m compileall -q manager omni_deploy omni_integrations mobile/omni-mobile-api.py oms-ml/oms_ml oms-xdr/oms_xdr oms-graph/oms_graph tools || rc=1
"$PY" tools/check-manifest.py || rc=1
"$PY" -m pytest tests -q || rc=1
for project in oms-ml oms-xdr oms-graph; do
  ( cd "$ROOT/$project" && "$PY" -m pytest tests -q ) || rc=1
done
if [[ $rc -eq 0 ]]; then echo "All offline suites passed."; else echo "Offline checks failed." >&2; fi
exit "$rc"
