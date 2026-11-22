#!/usr/bin/env python3
"""Compare collection counts after restoring graylog.* into a private child.

The sole bind address is a Unix socket inside a mode-0700 directory. MongoDB
8 supports Unix socket paths in --bind_ip; no TCP listener is requested.
Only the child started here is stopped. Equal counts do not prove equal data.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from urllib.parse import quote

ARCHIVE = re.compile(r"(?:graylog-mongo-\d{8}-\d{4,6}|omni-mongo-\d{8}-\d{6}-[a-f0-9]{12})\.archive\.gz")
COUNTS = ('const d=db.getSiblingDB("graylog"); const o={}; '
          'd.getCollectionNames().filter(c=>!c.startsWith("system.")).sort()'
          '.forEach(c=>o[c]=d.getCollection(c).countDocuments()); print(JSON.stringify(o));')


def archive_path(value):
    if value:
        path = Path(value)
    else:
        directory = Path(os.environ.get("BACKUP_DIR", "/home/siem-backup")) / "mongo"
        candidates = [p for p in directory.iterdir() if ARCHIVE.fullmatch(p.name)
                      and p.is_file() and not p.is_symlink()]
        if not candidates:
            raise ValueError("Aucune archive MongoDB disponible")
        path = max(candidates, key=lambda p: p.stat().st_mtime_ns)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Archive ordinaire requise, sans lien symbolique")
    return path.resolve()


def invoke(argv, env, timeout=120):
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Commande MongoDB en échec : " + Path(argv[0]).name)
    return result.stdout


def parse_counts(text):
    result = json.loads(text)
    if not isinstance(result, dict) or any(not isinstance(k, str) or type(v) is not int or v < 0
                                          for k, v in result.items()):
        raise ValueError("Comptages MongoDB invalides")
    return result


def restore(archive, port, base):
    if not re.fullmatch(r"[1-9][0-9]{3,4}", str(port)) or not 1024 <= int(port) <= 65535 or int(port) == 27017:
        raise ValueError("Identifiant de socket invalide ; 27017 est réservé à la production")
    password = os.environ.get("MONGO_ADMIN_PASS")
    if not password:
        raise ValueError("MONGO_ADMIN_PASS absent")
    base = Path(base).resolve(strict=True)
    if not base.is_dir():
        raise ValueError("Répertoire temporaire invalide")
    for tool in ("mongod", "mongosh", "mongorestore"):
        if not shutil.which(tool):
            raise ValueError("Outil requis absent : " + tool)
    work = Path(tempfile.mkdtemp(prefix="omni-restore-test.", dir=base))
    work.chmod(0o700)
    child = None
    clean = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "HOME", "TMPDIR")}
    try:
        (work / "db").mkdir(mode=0o700)
        sock = work / "mongo.sock"
        if len(os.fsencode(sock)) > 100:
            raise ValueError("Chemin du socket Unix trop long")
        target = "mongodb://" + quote(str(sock), safe="") + "/?directConnection=true"
        started = time.monotonic()
        with (work / "process.log").open("wb") as log:
            child = subprocess.Popen([
                "mongod", "--dbpath", str(work / "db"), "--port", str(port),
                "--bind_ip", str(sock), "--unixSocketPrefix", str(work), "--filePermissions", "0700",
                "--wiredTigerCacheSizeGB", "0.5", "--logpath", str(work / "mongod.log"),
            ], env=clean, stdout=log, stderr=subprocess.STDOUT)
            for _ in range(120):
                if child.poll() is not None:
                    raise RuntimeError("Le mongod temporaire n'a pas démarré")
                if sock.exists() and stat.S_ISSOCK(sock.stat().st_mode):
                    break
                time.sleep(0.25)
            else:
                raise RuntimeError("Délai de démarrage du mongod temporaire dépassé")
            ready = time.monotonic()
            invoke(["mongorestore", "--quiet", "--uri", target, "--gzip", "--archive=" + str(archive),
                    "--nsInclude=graylog.*"], clean, timeout=600)
            restored_at = time.monotonic()
            restored = parse_counts(invoke(["mongosh", "--quiet", target, "--eval", COUNTS], clean))
            read_env = {**clean, "MONGO_ADMIN_PASS": password}
            auth = ('const a=db.getSiblingDB("admin").auth("admin",process.env.MONGO_ADMIN_PASS); '
                    'if(a!==1 && a.ok!==1) throw new Error("Authentication failed"); ')
            source = parse_counts(invoke([
                "mongosh", "--quiet", "mongodb://127.0.0.1:27017/?replicaSet=rs0&authSource=admin",
                "--eval", auth + COUNTS,
            ], read_env))
            return {"passed": restored == source, "comparison": "collection_counts_only",
                    "collections_restored": len(restored), "collections_source": len(source),
                    "documents_restored": sum(restored.values()), "documents_source": sum(source.values()),
                    "differing_collections": [k for k in sorted(restored.keys() | source.keys())
                                               if restored.get(k) != source.get(k)],
                    "startup_seconds": round(ready - started, 3),
                    "restore_seconds": round(restored_at - ready, 3),
                    "private_unix_socket": True, "tcp_listener": False}
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=60)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=15)
        # If stopping the child fails, leave the private workspace for inspection.
        shutil.rmtree(work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", nargs="?")
    args = parser.parse_args()
    os.umask(0o077)
    def interrupted(*_):
        raise KeyboardInterrupt
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, interrupted)
    try:
        result = restore(archive_path(args.archive), os.environ.get("RESTORE_TEST_PORT", "27018"),
                         os.environ.get("RESTORE_TEST_DIR", "/data"))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["passed"] else 1
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(json.dumps({"passed": False, "error": str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
