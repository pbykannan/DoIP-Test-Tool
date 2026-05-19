"""
写入 src/doip_tester/_embedded_version.txt，供 PyInstaller 打入 exe。

用法：
  python scripts/write_embedded_version.py              # 默认当天 yy.mm.dd.00
  python scripts/write_embedded_version.py 26.05.09.03  # 手动指定（同日 00～99）
  set DOIP_APP_VERSION=26.05.09.01 && python scripts/write_embedded_version.py

版本串须匹配 \\d{2}.\\d{2}.\\d{2}.\\d{2}，末两位为 00～99。
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "src" / "doip_tester" / "_embedded_version.txt"

sys.path.insert(0, str(ROOT / "src"))
from doip_tester.version import (  # noqa: E402
    default_version_for_today,
    validate_app_version_string,
)


def main() -> None:
    v = os.environ.get("DOIP_APP_VERSION", "").strip()
    if len(sys.argv) >= 2:
        v = sys.argv[1].strip()
    if not v:
        v = default_version_for_today()
    if not validate_app_version_string(v):
        print(
            "Invalid version %r — expected yy.mm.dd.nn (nn = 00..99), e.g. 26.05.09.00"
            % (v,),
            file=sys.stderr,
        )
        sys.exit(1)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(v + "\n", encoding="utf-8")
    print("Wrote", OUT, "->", v)


if __name__ == "__main__":
    main()
