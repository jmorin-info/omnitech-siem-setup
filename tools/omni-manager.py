#!/usr/bin/env python3
"""Launch the local SSH administration menus. No additional Python packages required."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from manager.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
