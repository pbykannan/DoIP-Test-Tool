"""Run pip with Windows/registry proxies disabled (dead proxy breaks builds)."""
from __future__ import annotations

import os
import runpy
import sys
import urllib.request


def main(argv: list[str]) -> None:
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "ALL_PROXIES",
        "PIP_PROXY",
    ):
        os.environ.pop(key, None)
    os.environ["NO_PROXY"] = "*"
    urllib.request.getproxies = lambda: {}  # type: ignore[method-assign]
    sys.argv = ["pip", *argv]
    runpy.run_module("pip", run_name="__main__", alter_sys=True)


if __name__ == "__main__":
    main(sys.argv[1:])
