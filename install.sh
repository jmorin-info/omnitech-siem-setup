#!/usr/bin/env bash
# One entry point for a fresh host. Default is a read-only installation plan.
set -euo pipefail
cd "$(dirname "$0")"
exec python3 ./tools/install-platform.py "$@"
