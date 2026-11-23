#!/usr/bin/env python3
"""Build SERA Antigravity Plugin into `dist/sera-<version>.zip` and `dist-latest/`."""

from __future__ import annotations

import json
import sys
from pathlib import Path

GIT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GIT_ROOT / "src"))

from sera.plugin_packager import build_plugin_release  # noqa: E402


def main() -> None:
    info = build_plugin_release(GIT_ROOT)
    print(json.dumps(info, indent=2))


if __name__ == "__main__":
    main()
