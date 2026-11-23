"""SERA — Secure Extraction for Response Agents."""

from __future__ import annotations

__version__ = "0.1.0"
__app_name__ = "SERA — Secure Extraction for Response Agents"

# Upfront runtime dependency manifest installed into `.venv` during `sera init` via `uv`.
REQUIRED_UV_PACKAGES: tuple[str, ...] = (
    "cryptography>=42.0.0",
    "google-cloud-bigquery>=3.20.0",
    "httpx[socks]>=0.27.0",
    "mcp>=1.2.0",
    "msal>=1.28.0",
    "rich>=13.7.0",
    "typer>=0.12.0",
)
