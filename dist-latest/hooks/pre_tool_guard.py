#!/usr/bin/env python3
"""PreToolUse lifecycle hook guarding `<workspace>/.sera/` and binding active workspace path for MCP."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


DOT_SERA_PATTERN = re.compile(r"(^|[/\\\s'\"=])\.sera([/\\\s'\"]|$)")


def _contains_dot_sera_path(value: Any) -> bool:
    if isinstance(value, str):
        if DOT_SERA_PATTERN.search(value):
            return True
        try:
            parts = Path(value).parts
            if ".sera" in parts:
                return True
        except Exception:
            pass
        return False
    if isinstance(value, dict):
        return any(_contains_dot_sera_path(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_dot_sera_path(item) for item in value)
    return False


def _is_sera_mcp_tool(tool_name: str, args: dict[str, Any]) -> tuple[bool, bool]:
    """Return `(is_direct_sera_tool, is_lazy_call_mcp_tool)`."""
    lowered = tool_name.lower()
    if lowered.startswith("mcp_sera_") or lowered.startswith("mcp_sera-"):
        return True, False
    if lowered == "call_mcp_tool" and str(args.get("ServerName", "")).lower().startswith("sera"):
        return False, True
    return False, False


def evaluate_pre_tool_use(payload: dict[str, Any]) -> dict[str, Any]:
    """Evaluate an Antigravity `PreToolUse` stdin payload and return the hook decision JSON."""
    tool_call = payload.get("toolCall") or {}
    tool_name = str(tool_call.get("name", ""))
    args = tool_call.get("args") or {}
    if not isinstance(args, dict):
        args = {}

    is_direct_sera, is_lazy_sera = _is_sera_mcp_tool(tool_name, args)

    # 1. Bind host-verified engagement workspace directory onto SERA MCP tool calls so multi-client
    #    windows stay 100% isolated with zero `case_id` parameter required from the agent.
    if is_direct_sera or is_lazy_sera:
        workspace_paths = payload.get("workspacePaths") or []
        verified_ws = str(workspace_paths[0] if workspace_paths else payload.get("cwd", "")).strip()
        if verified_ws:
            if is_direct_sera:
                return {
                    "decision": "allow",
                    "overwrite": {"workspace_dir": verified_ws},
                }
            inner_args = dict(args.get("Arguments") or {})
            inner_args["workspace_dir"] = verified_ws
            return {
                "decision": "allow",
                "overwrite": {"Arguments": inner_args},
            }
        return {"decision": "allow"}

    # 2. Block any non-SERA tool (read_file, write_file, edit_file, run_command, grep, find, etc.)
    #    from reading, modifying, or deleting `<workspace>/.sera/`.
    if _contains_dot_sera_path(args):
        return {
            "decision": "deny",
            "reason": (
                "SERA Forensic Integrity Guard: Direct access to `.sera/` (credentials, SQLite ledger, "
                "and encrypted event spool) is prohibited. Use SERA's MCP tools or the `sera` CLI."
            ),
        }

    return {"decision": "allow"}


def main() -> int:
    raw_stdin = sys.stdin.read().strip()
    if not raw_stdin:
        sys.stdout.write(json.dumps({"decision": "allow"}) + "\n")
        return 0
    try:
        payload = json.loads(raw_stdin)
    except json.JSONDecodeError:
        sys.stdout.write(json.dumps({"decision": "allow"}) + "\n")
        return 0

    decision = evaluate_pre_tool_use(payload)
    sys.stdout.write(json.dumps(decision) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
