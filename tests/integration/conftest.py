"""Shared schema & data-type assertion helpers for SERA external API diagnostic integration tests."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def assert_required_fields_and_types(
    payload: dict[str, Any],
    required_spec: dict[str, type | tuple[type, ...]],
    context: str,
) -> None:
    """Validate that `payload` contains every required field with the expected data type(s)."""
    assert isinstance(payload, dict), f"[{context}] Expected JSON object (dict), got {type(payload).__name__}"
    for key, expected_type in required_spec.items():
        assert key in payload, (
            f"[{context}] External API contract violation: missing required field '{key}'. "
            f"Present keys: {sorted(payload.keys())}"
        )
        val = payload[key]
        assert isinstance(val, expected_type), (
            f"[{context}] External API data-type change on field '{key}': "
            f"expected {expected_type}, got {type(val).__name__} ({val!r})"
        )


def live_workspace_path() -> Path | None:
    raw = os.environ.get("SERA_ITEST_WORKSPACE", "").strip()
    if not raw:
        return None
    p = Path(raw).expanduser().resolve()
    return p if (p / ".sera" / "config.toml").exists() else None
