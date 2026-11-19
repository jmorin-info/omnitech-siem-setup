"""Exercise actual Bash/curl API fallback against an isolated HTTP server."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name == "nt" or not shutil.which("jq"), reason="Linux Bash, curl and jq fixtures")


@pytest.mark.parametrize("status,needs_envelope,expected_calls", [
    (200, False, 1), (400, True, 2), (400, False, 1), (401, False, 1), (500, True, 1),
])
def test_post_entity_only_retries_the_specific_envelope_validation(status, needs_envelope, expected_calls):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(body)
            code = 200 if len(calls) > 1 else status
            reply = {"id": "created-entity"} if code == 200 else {"message": "entity cannot be null" if needs_envelope else "rejected", "sensitive": "dummy-private-rejected-value"}
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(reply).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        script = 'set -euo pipefail; source "$1"; API="$2"; printf \'%s\' \'{"title":"fixture"}\' | post_entity /entities'
        result = subprocess.run(["bash", "-c", script, "test", str(ROOT / "lib-graylog.sh"),
                                 f"http://127.0.0.1:{server.server_port}"],
                                env={**os.environ, "GRAYLOG_API_URL": "http://127.0.0.1:9000/api", "GRAYLOG_ADMIN_PASS": "dummy-test-only-password"},
                                capture_output=True, text=True, timeout=10)
        assert len(calls) == expected_calls
        assert "dummy-private-rejected-value" not in result.stdout + result.stderr
        if status == 200 or status == 400 and needs_envelope:
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout) == {"id": "created-entity"}
            if needs_envelope:
                assert calls[1] == {"entity": {"title": "fixture"}, "share_request": {"selected_grantee_capabilities": {}}}
        else:
            assert result.returncode != 0
            assert not result.stdout.strip()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
