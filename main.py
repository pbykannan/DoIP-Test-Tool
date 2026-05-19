"""Entry point: run from project root (dev) or from PyInstaller exe (frozen)."""
import sys
from pathlib import Path

if not getattr(sys, "frozen", False):
    ROOT = Path(__file__).resolve().parent
    SRC = ROOT / "src"
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))

from doip_tester.gui.main import main

if __name__ == "__main__":
    main()
