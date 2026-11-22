"""omni_api_setup normalise l'URL de l'API Graylog (suffixe /api), sans appel réseau."""
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("configured,expected", [
    ("https://siem.example.test:9000", "https://siem.example.test:9000/api"),
    ("https://siem.example.test:9000/", "https://siem.example.test:9000/api"),
    ("https://siem.example.test:9000/api", "https://siem.example.test:9000/api"),
    ("https://siem.example.test:9000/api/", "https://siem.example.test:9000/api"),
    ("", "http://127.0.0.1:9000/api"),
])
def test_api_url_always_ends_with_api(configured, expected, tmp_path):
    script = f'source "{ROOT}/lib-platform.sh"; GRAYLOG_API_URL="$1"; GRAYLOG_ADMIN_PASS=x; ' \
             'grep() { return 1; }; omni_api_setup && printf "%s" "$API"'
    result = subprocess.run(["bash", "-c", script, "test", configured], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected
