"""Changing native processor order must preserve deliberate site disablements."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name != "posix" or not shutil.which("jq"), reason="Bash/jq processor configuration")


@pytest.mark.parametrize("anchor", ["Stream Rule Processor", "Message Filter Chain"])
@pytest.mark.parametrize("disabled", [[], ["fixture.1", "fixture.2"]])
def test_reordering_keeps_disabled_processors_and_their_configuration(tmp_path, anchor, disabled):
    source = (ROOT / "12-graylog-pipelines.sh").read_text()
    body = source[source.index('CURRENT="$(api_get "/system/messageprocessors/config")"'):]
    processors = [{"name": name, "class_name": "fixture." + str(i)} for i, name in enumerate([
        "GeoIP Resolver", "Pipeline Processor", "Custom Processor", anchor])]
    config = {"processor_order": processors, "disabled_processors": disabled}
    capture = tmp_path / "request.json"
    script = '''set -euo pipefail
api_get() { printf '%s' "$PROCESSORS"; }
api_put() { cat > "$CAPTURE"; }
ok() { :; }
skip() { :; }
''' + body
    result = subprocess.run(["bash", "-c", script], env={**os.environ, "PROCESSORS": json.dumps(config),
        "CAPTURE": str(capture)}, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    payload = json.loads(capture.read_text())
    assert payload["disabled_processors"] == disabled
    names = [item["name"] for item in payload["processor_order"]]
    assert names.index("Pipeline Processor") == names.index(anchor) + 1
    assert names[-1] == "GeoIP Resolver"
    assert sorted(payload["processor_order"], key=lambda item: item["name"]) == sorted(processors, key=lambda item: item["name"])
