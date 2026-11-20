"""Small console helpers so every component prints clean, timestamped, colour-coded lines."""
from __future__ import annotations

import os
import sys
import time

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _wrap(code: str):
    def f(s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if _COLOR else s
    return f


class c:  # noqa: N801 - used like a namespace
    bold = staticmethod(_wrap("1"))
    dim = staticmethod(_wrap("2"))
    red = staticmethod(_wrap("1;31"))
    green = staticmethod(_wrap("32"))
    yellow = staticmethod(_wrap("33"))
    blue = staticmethod(_wrap("34"))
    cyan = staticmethod(_wrap("36"))


_TAGS = {"agent": c.cyan, "witness": c.green, "batcher": c.blue, "monitor": c.yellow, "chain": c.blue, "demo": c.dim}


def log(component: str, msg: str) -> None:
    tag = _TAGS.get(component, c.dim)(f"[{component:^7}]")
    print(f"{c.dim(time.strftime('%H:%M:%S'))} {tag} {msg}", flush=True)
