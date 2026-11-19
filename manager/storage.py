"""Private local state and one lock shared by configuration and operations."""
import contextlib
import json
import os
from pathlib import Path
import tempfile


@contextlib.contextmanager
def lock(state: Path):
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    if os.name == "posix" and state.stat().st_mode & 0o077:
        raise ValueError("Le répertoire d'état doit être privé (chmod 700).")
    path = state / "operation.lock"
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise ValueError("Une opération est en cours ou a été interrompue ; examiner operation.lock avant reprise.") from None
    try:
        os.write(descriptor, str(os.getpid()).encode())
        os.close(descriptor)
        yield
    finally:
        path.unlink(missing_ok=True)


def write_private(path: Path, data):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
        output.write((json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode())
        candidate = Path(output.name)
    try:
        candidate.chmod(0o600)
        os.replace(candidate, path)
    finally:
        candidate.unlink(missing_ok=True)
