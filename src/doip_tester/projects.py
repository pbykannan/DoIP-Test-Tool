"""Project-specific YAML configs under project_configs/."""

import sys
from pathlib import Path
from typing import List, Optional


def project_configs_dir(repo_root: Path) -> Path:
    return repo_root / "project_configs"


def list_project_names(repo_root: Path) -> List[str]:
    d = project_configs_dir(repo_root)
    if not d.is_dir():
        return []
    names = sorted(p.stem for p in d.glob("*.yaml") if p.is_file())
    return names


def project_yaml_path(repo_root: Path, name: str) -> Path:
    return project_configs_dir(repo_root) / (name + ".yaml")


def read_first_project_yaml_text(repo_root: Path) -> Optional[str]:
    """Readable text of first sorted ``project_configs/*.yaml``, or ``None``."""
    names = list_project_names(repo_root)
    if not names:
        return None
    p = project_yaml_path(repo_root, names[0])
    if not p.is_file():
        return None
    return p.read_text(encoding="utf-8")


def read_first_bundled_project_yaml_text() -> Optional[str]:
    """Frozen exe: first ``*.yaml`` under PyInstaller ``_MEIPASS/project_configs``."""
    if not getattr(sys, "frozen", False):
        return None
    me = getattr(sys, "_MEIPASS", None)
    if not me:
        return None
    d = Path(me) / "project_configs"
    if not d.is_dir():
        return None
    ys = sorted(d.glob("*.yaml"))
    if not ys:
        return None
    return ys[0].read_text(encoding="utf-8")
