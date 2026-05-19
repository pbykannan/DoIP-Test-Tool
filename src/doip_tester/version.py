"""
应用版本：格式 yy.mm.dd.nn（nn 为 00～99 当日构建序号）。

- 开发运行：未设置 DOIP_APP_VERSION 时为当前日期的 yy.mm.dd.00。
- 打包（PyInstaller）：由 scripts/write_embedded_version.py 写入
  doip_tester/_embedded_version.txt 并打进 bundle，与构建日当天一致或可手动指定。
"""

from __future__ import annotations

import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

_VERSION_RE = re.compile(r"^\d{2}\.\d{2}\.\d{2}\.\d{2}$")


def default_version_for_today() -> str:
    """当天 yy.mm.dd.00（开发或未嵌入版本时使用）。"""
    return datetime.now().strftime("%y.%m.%d") + ".00"


def validate_app_version_string(s: str) -> bool:
    if not _VERSION_RE.match(s.strip()):
        return False
    try:
        n = int(s.strip().rsplit(".", 1)[-1])
    except ValueError:
        return False
    return 0 <= n <= 99


def _read_embedded_path() -> Optional[Path]:
    if not getattr(sys, "frozen", False):
        return None
    base = Path(getattr(sys, "_MEIPASS", ""))
    if not base or not base.is_dir():
        return None
    p = base / "doip_tester" / "_embedded_version.txt"
    return p if p.is_file() else None


def get_app_version() -> str:
    """
    冻结 exe：优先读取打包嵌入的版本文件。
    开发：环境变量 DOIP_APP_VERSION（合法则采用），否则为当天 yy.mm.dd.00。
    """
    p = _read_embedded_path()
    if p is not None:
        raw = p.read_text(encoding="utf-8").strip()
        if validate_app_version_string(raw):
            return raw
        return default_version_for_today()

    env = os.environ.get("DOIP_APP_VERSION", "").strip()
    if env and validate_app_version_string(env):
        return env
    return default_version_for_today()
