"""Application root directory: repo root in development, exe directory when frozen (PyInstaller)."""

import os
import shutil
import sys
from pathlib import Path


def app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    # src/doip_tester/paths.py -> parents[2] = repo root
    return Path(__file__).resolve().parents[2]


def ensure_data_beside_exe() -> None:
    """
    One-file PyInstaller extracts bundles to _MEIPASS. Copy embedded ``project_configs/*.yaml``
    next to the exe on first run so users can edit them.

    Missing files are always copied from the bundle. Existing *.yaml are NOT overwritten
    (so user edits survive exe upgrades). To force-refresh templates from the embedded
    bundle once, set environment variable DOIP_REFRESH_PROJECT_YAML=1 before starting.
    """
    if not getattr(sys, "frozen", False):
        return
    me = getattr(sys, "_MEIPASS", None)
    if not me:
        return
    root = app_root()
    mep = Path(me)

    refresh = os.environ.get("DOIP_REFRESH_PROJECT_YAML", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )

    src_pc = mep / "project_configs"
    dst_pc = root / "project_configs"
    if src_pc.is_dir():
        dst_pc.mkdir(parents=True, exist_ok=True)
        for f in sorted(src_pc.glob("*.yaml")):
            dst_f = dst_pc / f.name
            if not dst_f.is_file() or refresh:
                shutil.copy2(f, dst_f)
