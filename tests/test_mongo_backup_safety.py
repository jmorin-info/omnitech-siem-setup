"""Exercise backup and restoration with fake Mongo executables only."""
import fcntl
import gzip
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
FAKE = r'''#!/usr/bin/env python3
import gzip, json, os, signal, socket, stat, sys, time
from pathlib import Path
root=Path(sys.argv[0]).parent
settings=json.loads((root/'scenario.json').read_text())
name=Path(sys.argv[0]).name
def log(**extra):
    with (root/'calls.jsonl').open('a') as stream:
        stream.write(json.dumps(dict(name=name,argv=sys.argv[1:],pid=os.getpid(),**extra))+'\n')
if name=='mongodump':
    conf=Path(next(a.split('=',1)[1] for a in sys.argv if a.startswith('--config=')))
    value=json.loads(conf.read_text())['password']
    log(config_valid=value==settings['password'],mode=stat.S_IMODE(conf.stat().st_mode))
    if settings.get('dump_fail'):sys.exit(3)
    target=Path(next(a.split('=',1)[1] for a in sys.argv if a.startswith('--archive=')))
    target.write_bytes(b'bad' if settings.get('corrupt') else gzip.compress(b'fixture'))
elif name=='mongorestore':
    log()
    if settings.get('restore_fail'):sys.exit(4)
elif name=='mongod':
    log(secret_in_environment='MONGO_ADMIN_PASS' in os.environ)
    if settings.get('start_fail'):sys.exit(5)
    address=sys.argv[sys.argv.index('--bind_ip')+1]
    if not address.startswith('/'):sys.exit(6)
    sock=socket.socket(socket.AF_UNIX);sock.bind(address);sock.listen(1)
    def stop(*_):log(stopped=True);sys.exit(0)
    signal.signal(signal.SIGTERM,stop)
    while True:time.sleep(.1)
elif name=='mongosh':
    log(secret_in_environment='MONGO_ADMIN_PASS' in os.environ)
    source=any('127.0.0.1:27017' in a for a in sys.argv)
    print(json.dumps({'streams': 3 if source and settings.get('mismatch') else 2}))
else:log()
'''


@pytest.fixture
def lab(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    for name in ('mongod', 'mongodump', 'mongorestore', 'mongosh', 'curl'):
        target = bin_dir / name
        target.write_text(FAKE)
        target.chmod(0o755)
    password = 'fake' + 'quote" slash\\ and newline\nend'
    settings = {'password': password}
    config = tmp_path / 'vars.env'
    config.write_text('MONGO_ADMIN_PASS=' + shlex.quote(password) + '\nBACKUP_DIR=' + shlex.quote(str(tmp_path / 'backups')) + '\n')
    backup_script = tmp_path / 'backup.sh'
    backup_script.write_text((ROOT / 'deploye/sbin/omni-mongo-backup').read_text())
    dest = tmp_path / 'backups/mongo'
    dest.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix='omni-mongo-test-') as compact:
        env = {**os.environ, 'PATH': str(bin_dir) + os.pathsep + os.environ['PATH'],
               'OMNI_VARS_FILE': str(config), 'MONGO_ADMIN_PASS': password,
               'BACKUP_DIR': str(tmp_path / 'backups'), 'RESTORE_TEST_DIR': compact}
        def run(kind, **changes):
            (bin_dir / 'scenario.json').write_text(json.dumps({**settings, **changes}))
            if kind == 'backup':
                argv = ['bash', str(backup_script)]
            else:
                archive = dest / 'graylog-mongo-20261122-0240.archive.gz'
                archive.write_bytes(gzip.compress(b'fixture'))
                argv = [sys.executable, str(ROOT / 'tools/mongo-restore-test.py'), str(archive)]
            return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=15)
        def calls():
            path = bin_dir / 'calls.jsonl'
            return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []
        yield run, calls, dest, env, password


def old(path):
    path.write_bytes(b'preserve')
    stamp = time.time() - 35 * 86400
    os.utime(path, (stamp, stamp))


def test_backup_purges_only_owned_archives_after_validated_success(lab):
    run, calls, dest, _, password = lab
    legacy = dest / 'graylog-mongo-20260814-0919.archive.gz'
    owned = dest / 'omni-mongo-20260814-091900-abcdef123456.archive.gz'
    unrelated = dest / 'omni-mongo-important.archive.gz'
    for path in (legacy, owned, unrelated):old(path)
    result = run('backup')
    assert result.returncode == 0, result.stderr
    assert legacy.read_bytes() == unrelated.read_bytes() == b'preserve'
    assert not owned.exists()
    archives = list(dest.glob('omni-mongo-*.archive.gz'))
    assert len(archives) == 2
    produced = next(p for p in archives if p != unrelated)
    assert produced.stat().st_mode & 0o777 == 0o600
    assert gzip.decompress(produced.read_bytes()) == b'fixture'
    dump = next(c for c in calls() if c['name'] == 'mongodump')
    assert dump['config_valid'] and dump['mode'] == 0o600
    assert password not in json.dumps(calls()) + result.stdout + result.stderr
    assert not [p for p in dest.glob('.omni-mongo-backup.*') if p.is_dir()]


@pytest.mark.parametrize('failure', ['dump_fail', 'restore_fail', 'corrupt'])
def test_failed_backup_never_purges_previous_archives(lab, failure):
    run, calls, dest, _, _ = lab
    existing = dest / 'omni-mongo-20260814-091900-abcdef123456.archive.gz'
    old(existing)
    result = run('backup', **{failure: True})
    assert result.returncode != 0
    assert any(c['name'] == 'mongodump' for c in calls())
    if failure == 'restore_fail':
        assert any(c['name'] == 'mongorestore' for c in calls())
    assert existing.read_bytes() == b'preserve'
    assert not [p for p in dest.glob('.omni-mongo-backup.*') if p.is_dir()]


def test_concurrent_backup_is_refused_without_dump(lab):
    run, calls, dest, _, _ = lab
    with (dest / '.omni-mongo-backup.lock').open('w') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = run('backup')
    assert result.returncode != 0
    assert not any(c['name'] == 'mongodump' for c in calls())


def test_restore_uses_private_unix_socket_and_stops_only_its_child(lab):
    run, calls, _, env, password = lab
    # An unrelated TCP listener on the old test port must remain untouched.
    with socket.socket() as unrelated:
        unrelated.bind(('127.0.0.1', 0)); unrelated.listen(1)
        result = run('restore')
        assert unrelated.getsockname()[1] > 0
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report['passed'] and report['comparison'] == 'collection_counts_only'
    assert report['private_unix_socket'] and not report['tcp_listener']
    server = next(c for c in calls() if c['name'] == 'mongod' and not c.get('stopped'))
    assert not server['secret_in_environment'] and '--fork' not in server['argv']
    assert any(c.get('stopped') and c['pid'] == server['pid'] for c in calls())
    restore = next(c for c in calls() if c['name'] == 'mongorestore')
    assert '--nsInclude=graylog.*' in restore['argv']
    assert restore['argv'][restore['argv'].index('--uri') + 1].startswith('mongodb://%2F')
    assert not any('shutdownServer' in ' '.join(c['argv']) for c in calls())
    assert not list(Path(env['RESTORE_TEST_DIR']).iterdir())
    assert password not in json.dumps(calls()) + result.stdout + result.stderr


@pytest.mark.parametrize('port', ['27017', '0', '65536', 'bad'])
def test_restore_rejects_production_or_invalid_target_before_start(lab, port):
    run, calls, _, env, _ = lab
    env['RESTORE_TEST_PORT'] = port
    result = run('restore')
    assert result.returncode != 0 and not calls()


@pytest.mark.parametrize('failure', ['start_fail', 'restore_fail'])
def test_restore_failure_never_reads_source_and_cleans_owned_workspace(lab, failure):
    run, calls, _, env, _ = lab
    result = run('restore', **{failure: True})
    assert result.returncode != 0
    assert not any(c['name'] == 'mongosh' for c in calls())
    assert not list(Path(env['RESTORE_TEST_DIR']).iterdir())


def test_restore_reports_count_drift_as_failure(lab):
    run, _, _, _, _ = lab
    result = run('restore', mismatch=True)
    assert result.returncode == 1
    assert json.loads(result.stdout)['differing_collections'] == ['streams']
