"""Exercise the actual routing branch without provisioning or calling Graylog."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name == "nt" or not shutil.which("jq"), reason="Linux Bash and jq fixtures")


@pytest.mark.parametrize("fresh,triage,teams,expected", [
    ("1", "", "", ["mail-id"]),
    ("1", "", "teams-id", ["mail-id", "teams-id"]),
    ("1", "triage-id", "", ["triage-id"]),
    ("0", "triage-id", "teams-id", ["triage-id", "teams-id"]),
])
def test_fresh_notifications_work_with_optional_triage(fresh, triage, teams, expected):
    source = (ROOT / "13-graylog-alerts.sh").read_text(encoding="utf-8")
    branch = source[source.index('TRIAGE_TITLE="OMNI - Triage (mail critique)"'):]
    branch = branch.split("all_event_defs \\\n", 1)[0]
    script = """set -euo pipefail
api_get() { printf '%s' "$NOTIFICATIONS_FIXTURE"; }
warn() { printf '%s\\n' "$*" >&2; }
die() { printf '%s\\n' "$*" >&2; exit 1; }
""" + branch + '\nprintf "%s\\n" "$W_ALL"\n'
    notifications = [{"title": "OMNI - Triage (mail critique)", "id": triage}] if triage else []
    env = {**os.environ, "OMNI_FRESH_INSTALL": fresh, "NOTIF_ID": "mail-id", "TEAMS_ID": teams,
           "NOTIFICATIONS_FIXTURE": json.dumps({"notifications": notifications})}
    result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert [item["notification_id"] for item in json.loads(result.stdout)] == expected


def test_existing_instance_does_not_silently_switch_from_triage_to_direct_mail():
    source = (ROOT / "13-graylog-alerts.sh").read_text(encoding="utf-8")
    branch = source[source.index('TRIAGE_TITLE="OMNI - Triage (mail critique)"'):].split("all_event_defs \\\n", 1)[0]
    script = """set -euo pipefail
api_get() { printf '%s' '{"notifications":[]}'; }
warn() { :; }
die() { printf '%s\\n' "$*" >&2; exit 1; }
""" + branch
    result = subprocess.run(["bash", "-c", script], env={**os.environ, "OMNI_FRESH_INSTALL": "0",
                            "NOTIF_ID": "mail-id", "TEAMS_ID": ""}, capture_output=True, text=True)
    assert result.returncode != 0
    assert "triage introuvable" in result.stderr
