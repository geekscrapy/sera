"""Unit tests for the `PreToolUse` `.sera/` guard hook and `dist/` + `dist-latest/` plugin artifacts."""

from __future__ import annotations

import json
import subprocess
import sys
import zipfile
from pathlib import Path

from sera.hooks.guard_dot_sera import evaluate_pre_tool_use
from sera.plugin_packager import build_plugin_release


def test_hook_blocks_all_dot_sera_access_and_injects_verified_workspace_for_mcp() -> None:
    # Block read_file on .sera/creds
    deny_read = evaluate_pre_tool_use(
        {
            "workspacePaths": ["/cases/client_a"],
            "toolCall": {"name": "read_file", "args": {"Path": "/cases/client_a/.sera/creds/microsoft_default.json"}},
        }
    )
    assert deny_read["decision"] == "deny"

    # Block shell command referencing .sera
    deny_cmd = evaluate_pre_tool_use(
        {
            "workspacePaths": ["/cases/client_a"],
            "toolCall": {"name": "run_command", "args": {"CommandLine": "sqlite3 .sera/sera.sqlite 'DELETE FROM uploaded_events'"}},
        }
    )
    assert deny_cmd["decision"] == "deny"

    # Allow normal file access outside .sera
    allow_normal = evaluate_pre_tool_use(
        {
            "workspacePaths": ["/cases/client_a"],
            "toolCall": {"name": "read_file", "args": {"Path": "/cases/client_a/investigation_notes.md"}},
        }
    )
    assert allow_normal == {"decision": "allow"}

    # Inject verified workspacePaths[0] into direct SERA MCP tool call
    mcp_bound = evaluate_pre_tool_use(
        {
            "workspacePaths": ["/cases/client_alpha"],
            "toolCall": {"name": "mcp_sera_submit_job", "args": {"source": "microsoft", "workspace_dir": "/spoofed"}},
        }
    )
    assert mcp_bound == {"decision": "allow", "overwrite": {"workspace_dir": "/cases/client_alpha"}}


def test_plugin_packager_produces_valid_dist_zip_and_dist_latest(tmp_path: Path) -> None:
    fake_git = tmp_path / "git"
    (fake_git / "src").mkdir(parents=True)
    result = build_plugin_release(fake_git, version="0.1.0")

    dist_latest = Path(result["dist_latest_dir"])
    zip_path = Path(result["zip_path"])
    assert dist_latest.is_dir()
    assert zip_path.is_file()
    assert zip_path.name == "sera-0.1.0.zip"

    manifest = json.loads((dist_latest / "plugin.json").read_text(encoding="utf-8"))
    assert manifest["name"] == "sera"
    assert "Secure Extraction for Response Agents" in manifest["displayName"]

    mcp_cfg = json.loads((dist_latest / "mcp_config.json").read_text(encoding="utf-8"))
    assert mcp_cfg["mcpServers"]["sera"]["command"] == "uvx"
    assert mcp_cfg["mcpServers"]["sera"]["args"] == [
        "--from",
        "git+https://github.com/geekscrapy/sera.git",
        "sera-mcp",
    ]

    hooks_cfg = json.loads((dist_latest / "hooks.json").read_text(encoding="utf-8"))
    hook_cmd = hooks_cfg["sera-forensic-guard"]["PreToolUse"][0]["hooks"][0]["command"]
    assert hook_cmd == "python3 -B ./hooks/pre_tool_guard.py"

    assert (dist_latest / "rules" / "sera.md").is_file()
    skill_text = (dist_latest / "skills" / "sera" / "SKILL.md").read_text(encoding="utf-8")
    assert "Init Setup" in skill_text
    assert "Auth" in skill_text
    assert "Downloading" in skill_text
    assert "Uploading" in skill_text
    assert "Agent-Only Technical Reference" in skill_text

    # Execute standalone packaged hook script over subprocess stdin/stdout
    hook_script = dist_latest / "hooks" / "pre_tool_guard.py"
    proc = subprocess.run(
        [sys.executable, "-B", str(hook_script)],
        input=json.dumps({"toolCall": {"name": "write_file", "args": {"Path": "/tmp/ws/.sera/spool/x.enc"}}}),
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(proc.stdout)["decision"] == "deny"

    # Verify zip contents
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())
    assert "sera/plugin.json" in names
    assert "sera/mcp_config.json" in names
    assert "sera/hooks.json" in names
    assert "sera/hooks/pre_tool_guard.py" in names
    assert "sera/rules/sera.md" in names
    assert "sera/skills/sera/SKILL.md" in names
