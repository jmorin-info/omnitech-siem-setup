"""Missing optional collectors must not create definitions with invalid stream IDs."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != "posix" or not shutil.which("jq"), reason="Bash/jq detection fixtures")
SOURCE = (ROOT / "13-graylog-alerts.sh").read_text()


@pytest.mark.parametrize("streams,created_id,passed", [('[]', 'created', True), ('["' + 'a' * 24 + '"]', 'created', True),
                                                       ('[""]', 'created', False), ('["null"]', 'created', False),
                                                       ('["' + 'a' * 24 + '"]', None, False)])
def test_detection_creation_rejects_invalid_streams_and_missing_api_id(tmp_path, streams, created_id, passed):
    body = SOURCE[SOURCE.index("ensure_event() {"):SOURCE.index("\nNOCOND=")]
    script = '''set -euo pipefail
die() { exit 1; }
ok() { :; }
skip() { :; }
event_def_id() { printf ''; }
jqr() { jq -r "$1"; }
post_entity() { cat > "$CAPTURE"; printf '%s' "$RESPONSE"; }
NOTIF_ID=fixture
''' + body + '\nensure_event fixture 2 query "$STREAMS" \'[]\' \'[]\' \'{"expression":null}\' 10 5\n'
    capture = tmp_path / "request.json"
    result = subprocess.run(["bash", "-c", script], env={**os.environ, "STREAMS": streams,
        "CAPTURE": str(capture), "RESPONSE": '{"id":"created"}' if created_id else '{}'}, capture_output=True, text=True)
    assert (result.returncode == 0) == passed
    if streams in ('[""]', '["null"]'):
        assert not capture.exists()


@pytest.mark.parametrize("stream", ["", "a" * 24])
def test_ndr_definition_is_only_created_when_its_optional_stream_exists(tmp_path, stream):
    start = SOURCE.index('# ===== Alertes Lot 3')
    end = SOURCE.index('ensure_event "OMNI - Accès credentials GPP', start)
    script = 'set -euo pipefail\nensure_event() { printf "created"; }\nskip() { :; }\ncount_ge() { printf "{}"; }\nCOUNT_SERIES="[]"\n' + SOURCE[start:end]
    result = subprocess.run(["bash", "-c", script], env={**os.environ, "ST_INT": stream}, capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout == ("created" if stream else "")
