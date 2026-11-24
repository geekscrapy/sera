#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "cryptography>=42.0.0",
#     "google-cloud-bigquery>=3.20.0",
#     "httpx[socks]>=0.27.0",
#     "mcp>=1.2.0",
#     "msal>=1.28.0",
#     "pysocks>=1.7.1",
#     "requests[socks]>=2.31.0",
#     "rich>=13.7.0",
#     "typer>=0.12.0",
# ]
# ///
"""Self-contained local plugin MCP server entrypoint for SERA."""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True

_SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from sera.mcp_server.server import main

if __name__ == "__main__":
    main()
