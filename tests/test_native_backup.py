"""Run the generated native backup with isolated database/API fixtures."""
import datetime as dt
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name == "nt" or not shutil.which("jq"), reason="Linux Bash/jq backup fixtures")


TOOL = r'''#!/usr/bin/env python3
import gzip, io, json, os, sys, tarfile
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['FIXTURE_CALLS'],'a') as log:
    if name != 'mongodump': log.write(json.dumps({'tool':name,'args':args})+'\n')
if name == 'mongodump':
    if os.environ.get('FIXTURE_BAD_MONGO'): sys.exit(0)
    path = next(arg.split('=',1)[1] for arg in args if arg.startswith('--archive='))
    with gzip.open(path,'wb') as target: target.write(b'fixture Mongo archive')
elif name == 'tar':
    if args[0] == 'czf':
        if os.environ.get('FIXTURE_BAD_TAR'): sys.exit(2)
        with tarfile.open(args[1],'w:gz') as target:
            for name in args[2:]:
                info = tarfile.TarInfo(name.lstrip('/'))
                target.addfile(info,io.BytesIO())
    else:
        with tarfile.open(args[1],'r:gz') as target:
            for member in target.getmembers(): print(member.name)
elif name == 'curl':
    url = next(arg for arg in args if arg.startswith('http'))
    method = args[args.index('-X')+1] if '-X' in args else 'GET'
    if url.endswith('/gelf'):
        with open(os.environ['FIXTURE_GELF'],'a') as target: target.write(json.dumps(json.load(sys.stdin))+'\n')
        print('{}')
    elif method == 'DELETE': print('{"acknowledged":true}')
    elif method == 'PUT': print('{"accepted":true}')
    elif url.endswith('/graylog_fs'): print('{"graylog_fs":{"type":"fs"}}')
    elif url.endswith('/_all'):
        print(json.dumps({'snapshots':[{'snapshot':name,'state':'SUCCESS','end_time_in_millis':1} for name in ['snap-20200101-0000','snap-20200101-000000','snap-20201301-000000','oms-sel-20200101-0000','custom-backup']]}))
    elif '*' in url: print('{"snapshots":[]}')
    else: print(json.dumps({'snapshots':[{'state':os.environ.get('FIXTURE_SNAPSHOT_STATE','SUCCESS')}]}))
'''


@pytest.fixture
def backup(tmp_path):
    source = (ROOT / "08-backup.sh").read_text(encoding="utf-8")
    runtime = source.split("cat > /usr/local/sbin/siem-backup.sh <<'EOF'\n", 1)[1].split("\nEOF\n", 1)[0]
    script = tmp_path / "backup.sh"
    script.write_text(runtime)
    directory = tmp_path / "backups"
    (directory / "mongo").mkdir(parents=True)
    (directory / "configs").mkdir()
    config = tmp_path / "00-vars.env"
    config.write_text("BACKUP_DIR=" + shlex.quote(str(directory)) + "\nRETENTION_DAYS=14\nSIEM_HOSTNAME=fixture-siem\nMONGO_ADMIN_PASS='dummy-backup-credential'\n")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    for name in ("mongodump", "curl", "tar"):
        executable = binaries / name
        executable.write_text(TOOL)
        executable.chmod(0o755)
    calls, gelf, log = (tmp_path / name for name in ("calls.jsonl", "gelf.jsonl", "backup.log"))
    env = {**os.environ, "PATH": str(binaries)+os.pathsep+os.environ["PATH"],
           "OMNI_CONFIG_FILE": str(config), "OMNI_BACKUP_LOG": str(log),
           "FIXTURE_CALLS": str(calls), "FIXTURE_GELF": str(gelf)}
    def run(**extra):
        return subprocess.run(["bash", str(script)], env={**env, **extra}, capture_output=True, text=True, timeout=20)
    return directory, config, calls, gelf, log, run


def test_first_and_second_backup_succeed_without_yesterday_and_preserve_other_snapshots(backup):
    directory, config, calls, gelf, log, run = backup
    unrelated = directory / "mongo" / "other.archive.gz"
    unrelated.write_bytes(b"preserve")
    os.utime(unrelated, (1,1))
    expired = directory / "mongo" / "graylog-mongo-20200101-000000.archive.gz"
    expired.write_bytes(b"old native archive")
    os.utime(expired, (1,1))
    for _ in range(2):
        result = run()
        assert result.returncode == 0, log.read_text()
    assert unrelated.exists() and not expired.exists()
    assert (directory / ".native-backup-first-success").read_text().strip() == dt.date.today().strftime("%Y%m%d")
    events = [json.loads(line) for line in gelf.read_text().splitlines()]
    assert len(events) == 2 and all(event["host"] == "fixture-siem" for event in events)
    assert all(event["_event_action"] == "backup_daily_ok" for event in events)
    requests = [json.loads(line) for line in calls.read_text().splitlines()]
    deleted = [item["args"][item["args"].index("-X")+2] for item in requests if item["tool"] == "curl" and "DELETE" in item["args"]]
    assert len(deleted) == 4
    assert all(url.endswith(("/snap-20200101-0000", "/snap-20200101-000000")) for url in deleted)
    archived = [item["args"] for item in requests if item["tool"] == "tar" and item["args"][0] == "czf"]
    assert all(str(config) in args for args in archived)
    assert len(list((directory / "mongo").glob("graylog-mongo-*.archive.gz"))) == 2
    assert log.stat().st_mode & 0o077 == 0
    assert (directory / ".native-backup-first-success").stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("extra", [{"FIXTURE_SNAPSHOT_STATE":"FAILED"}, {"FIXTURE_BAD_MONGO":"1"}, {"FIXTURE_BAD_TAR":"1"}])
def test_incomplete_components_never_mark_backup_successful(backup, extra):
    directory, config, calls, gelf, log, run = backup
    previous_archive = directory / "mongo" / "graylog-mongo-20200101-000000.archive.gz"
    previous_archive.write_bytes(b"keep the last backup when this run fails")
    os.utime(previous_archive, (1,1))
    result = run(**extra)
    assert result.returncode != 0
    assert not (directory / ".native-backup-first-success").exists()
    assert previous_archive.exists()
    assert all(json.loads(line)["_event_action"] == "backup_daily_echec" for line in gelf.read_text().splitlines())


def test_missing_previous_day_is_detected_after_first_successful_day(backup):
    directory, config, calls, gelf, log, run = backup
    (directory / ".native-backup-first-success").write_text((dt.date.today()-dt.timedelta(days=1)).strftime("%Y%m%d"))
    result = run()
    assert result.returncode != 0
    assert "veille" in log.read_text()


@pytest.mark.parametrize("timeout", ["0", "-1", "86401", "99999999999999999999999999", "invalid"])
def test_invalid_snapshot_deadline_is_refused_before_backup_writes(backup, timeout):
    directory, config, calls, gelf, log, run = backup
    result = run(BACKUP_SNAPSHOT_TIMEOUT_SECONDS=timeout)
    assert result.returncode != 0
    assert "BACKUP_SNAPSHOT_TIMEOUT_SECONDS" in result.stderr
    assert not list((directory / "mongo").iterdir())
    assert not calls.exists()


@pytest.mark.parametrize("timeout", ["1", "86400"])
def test_snapshot_deadline_accepts_the_documented_bounds(backup, timeout):
    directory, config, calls, gelf, log, run = backup
    result = run(BACKUP_SNAPSHOT_TIMEOUT_SECONDS=timeout)
    assert result.returncode == 0, log.read_text()
