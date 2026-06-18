"""Chargement de la configuration OMS-XDR."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_config(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Configuration introuvable : {path}")
    with p.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)
