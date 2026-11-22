"""21-alert-hygiene.sh : alertes de sauvegarde cohérentes avec omni-mongo-backup et oms-snap-siem."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
OBSOLETE = "OMNI - Sauvegarde quotidienne SIEM absente (>26h)"


def test_obsolete_daily_backup_absence_alert_is_neither_created_nor_rescheduled():
    text = (ROOT / "21-alert-hygiene.sh").read_text()
    created = re.findall(r'ensure_def_simple "([^"]+)"', text)
    assert OBSOLETE not in created
    loop = text.split("for T in", 1)[1].split("; do", 1)[0]
    assert OBSOLETE not in loop           # le PUT ?schedule=true la réactiverait
    assert "OMNI - Snapshot OpenSearch absent (>26h)" in created
    assert "OMNI - Snapshot OpenSearch absent (>26h)" in loop
    assert {"OMNI - Sauvegarde MongoDB absente (>26h)", "OMNI - Sauvegarde quotidienne SIEM en échec"} <= set(created)


def test_snapshot_absence_alert_matches_the_events_of_oms_snap_siem():
    text = (ROOT / "21-alert-hygiene.sh").read_text()
    assert "'event_action:backup_daily_ok AND backup_outil:\"oms-snap-siem\"'" in text
    robot = (ROOT / "deploye" / "sbin" / "oms-snap-siem").read_text()
    assert '\\"_event_action\\":\\"backup_daily_${1}\\"' in robot
    assert '\\"_backup_outil\\":\\"oms-snap-siem\\"' in robot
