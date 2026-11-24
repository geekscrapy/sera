"""End-to-end parity tests for `sera init` -> `sera source add` -> `sera dest add` -> `collect`/`jobs`/`status`."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import respx
from typer.testing import CliRunner

from sera.cli.app import app
from sera.mcp_server.server import create_mcp_server
from sera.service import resolve_target_venv_python


runner = CliRunner()


def _extract_mcp_json(tool_result: object) -> dict | list:
    assert not getattr(tool_result, "is_error", False), f"MCP tool returned error: {tool_result}"
    structured = getattr(tool_result, "structured_content", None)
    if isinstance(structured, dict):
        return structured["result"] if list(structured.keys()) == ["result"] else structured
    content_blocks = getattr(tool_result, "content", tool_result)
    texts = [getattr(b, "text", "") for b in content_blocks]  # type: ignore[union-attr]
    joined = "\n".join(t for t in texts if t)
    return json.loads(joined)


def test_resolve_target_venv_python_respects_active_virtual_env(tmp_path: Path, monkeypatch) -> None:
    fake_venv = tmp_path / "custom_venv"
    fake_py = fake_venv / "bin" / "python"
    fake_py.parent.mkdir(parents=True)
    fake_py.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("VIRTUAL_ENV", str(fake_venv))

    resolved = resolve_target_venv_python(tmp_path / "engagement_ws")
    assert resolved == str(fake_py)


async def test_cli_and_mcp_full_parity_and_multi_engagement_isolation(tmp_path: Path) -> None:
    case_alpha = tmp_path / "case_alpha"
    case_beta = tmp_path / "case_beta"
    sink_alpha = tmp_path / "sink_alpha"
    sink_beta = tmp_path / "sink_beta"

    # 1. Step 1: Bare `sera init` (zero source/dest flags required upfront)
    for ws in (case_alpha, case_beta):
        res = runner.invoke(
            app,
            [
                "init",
                "--workspace",
                str(ws),
                "--skip-uv",
                "--json",
            ],
        )
        assert res.exit_code == 0, res.output

    # 2. Step 2: `sera source add` (source-specific options like default_workspace_id/proxy + isolated auth credentials)
    src_alpha = runner.invoke(
        app,
        [
            "source",
            "add",
            "microsoft",
            "--auth-mode",
            "static-bearer",
            "--opt",
            "access_token=tok-alpha",
            "--opt",
            "tenant_id=tenant-alpha",
            "--opt",
            "default_workspace_id=ws-alpha-guid",
            "--workspace",
            str(case_alpha),
            "--json",
        ],
    )
    assert src_alpha.exit_code == 0, src_alpha.output
    # Ensure secret token is NOT stored in .sera/config.toml
    assert "tok-alpha" not in (case_alpha / ".sera" / "config.toml").read_text(encoding="utf-8")
    assert "ws-alpha-guid" in (case_alpha / ".sera" / "config.toml").read_text(encoding="utf-8")

    src_beta = runner.invoke(
        app,
        [
            "source",
            "add",
            "microsoft",
            "--auth-mode",
            "static-bearer",
            "--opt",
            "access_token=tok-beta",
            "--opt",
            "tenant_id=tenant-beta",
            "--workspace",
            str(case_beta),
            "--json",
        ],
    )
    assert src_beta.exit_code == 0, src_beta.output

    # 3. Step 3: `sera dest add` (destination-specific options like file paths + auth)
    for ws, sink in ((case_alpha, sink_alpha), (case_beta, sink_beta)):
        dst_res = runner.invoke(
            app,
            [
                "dest",
                "add",
                "jsonl",
                "--opt",
                f"output_dir={sink}",
                "--workspace",
                str(ws),
                "--json",
            ],
        )
        assert dst_res.exit_code == 0, dst_res.output

    # Also verify `sera dest add http` stores secret HEC token in `.sera/creds/dest_<name>.json` rather than config.toml
    http_dest_res = runner.invoke(
        app,
        [
            "dest",
            "add",
            "http",
            "--name",
            "siem_hec",
            "--auth-mode",
            "splunk-hec",
            "--opt",
            "url=https://siem.example.test/services/collector",
            "--opt",
            "format=splunk_hec",
            "--opt",
            "proxy_url=http://127.0.0.1:8080",
            "--opt",
            "hec_token=super-secret-hec",
            "--workspace",
            str(case_alpha),
            "--json",
        ],
    )
    assert http_dest_res.exit_code == 0, http_dest_res.output
    assert "super-secret-hec" not in (case_alpha / ".sera" / "config.toml").read_text(encoding="utf-8")
    assert (case_alpha / ".sera" / "creds" / "dest_siem_hec.json").is_file()

    mcp_server, pool = create_mcp_server()

    # Verify MCP tool names match CLI runtime commands 1-to-1
    registered_tools = sorted(t.name for t in await mcp_server.list_tools())
    assert registered_tools == [
        "collect",
        "destinations",
        "jobs",
        "resume",
        "sources",
        "status",
        "templates",
    ]

    cli_sources = json.loads(
        runner.invoke(app, ["sources", "--workspace", str(case_alpha), "--json"]).stdout
    )
    mcp_sources = _extract_mcp_json(
        await mcp_server.call_tool("sources", {"workspace_dir": str(case_alpha)})
    )
    assert cli_sources == mcp_sources
    assert mcp_sources["microsoft"]["profiles"][0]["tenant_id"] == "tenant-alpha"  # type: ignore[index]
    assert mcp_sources["microsoft"]["profiles"][0]["options"]["default_workspace_id"] == "ws-alpha-guid"  # type: ignore[index]

    cli_dests = json.loads(
        runner.invoke(app, ["destinations", "--workspace", str(case_alpha), "--json"]).stdout
    )
    mcp_dests = _extract_mcp_json(
        await mcp_server.call_tool("destinations", {"workspace_dir": str(case_alpha)})
    )
    assert cli_dests == mcp_dests
    assert mcp_dests["configured"]["siem_hec"]["has_auth"] is True  # type: ignore[index]
    assert mcp_dests["configured"]["siem_hec"]["has_proxy"] is True  # type: ignore[index]

    cli_templates = json.loads(
        runner.invoke(app, ["templates", "--sub-source", "entra", "--workspace", str(case_alpha), "--json"]).stdout
    )
    mcp_templates = _extract_mcp_json(
        await mcp_server.call_tool("templates", {"sub_source": "entra", "workspace_dir": str(case_alpha)})
    )
    assert cli_templates == mcp_templates

    with respx.mock(assert_all_called=True) as router:
        router.get("https://graph.microsoft.com/v1.0/auditLogs/signIns").mock(
            side_effect=[
                httpx.Response(
                    200,
                    json={"value": [{"id": "alpha-ev-1", "createdDateTime": "2026-11-20T01:00:00Z"}]},
                ),
                httpx.Response(
                    200,
                    json={"value": [{"id": "beta-ev-1", "createdDateTime": "2026-11-20T02:00:00Z"}]},
                ),
            ]
        )

        # Notice `--source` can even be omitted in CLI when `default_source` was set by `sera source add`!
        cli_collect = await asyncio.to_thread(
            runner.invoke,
            app,
            [
                "collect",
                "--sub-source",
                "entra",
                "--target",
                "signIns",
                "--start",
                "2026-11-20T00:00:00Z",
                "--end",
                "2026-11-21T00:00:00Z",
                "--workspace",
                str(case_alpha),
                "--json",
            ],
        )
        assert cli_collect.exit_code == 0, cli_collect.output
        assert json.loads(cli_collect.stdout)["events_uploaded"] == 1

        collect_res = _extract_mcp_json(
            await mcp_server.call_tool(
                "collect",
                {
                    "source": "microsoft",
                    "sub_source": "entra",
                    "target": "signIns",
                    "start": "2026-11-20T00:00:00Z",
                    "end": "2026-11-21T00:00:00Z",
                    "workspace_dir": str(case_beta),
                },
            )
        )
        assert isinstance(collect_res, dict)
        beta_job_id = collect_res["job_id"]
        await pool.get(case_beta).wait_all_background_tasks()

        beta_jobs = _extract_mcp_json(
            await mcp_server.call_tool(
                "jobs",
                {"workspace_dir": str(case_beta)},
            )
        )
        assert isinstance(beta_jobs, dict)
        assert beta_jobs["total_uploaded_events_in_workspace"] == 1
        assert beta_jobs["jobs"][0]["job_id"] == beta_job_id

        beta_status = _extract_mcp_json(
            await mcp_server.call_tool(
                "status",
                {"job_id": beta_job_id, "slices": True, "workspace_dir": str(case_beta)},
            )
        )
        assert isinstance(beta_status, dict)
        assert beta_status["status"] == "completed"
        assert beta_status["events_uploaded"] == 1
        assert len(beta_status["slice_details"]) == 1

    alpha_files = list((sink_alpha / "events").rglob("*.jsonl"))
    beta_files = list((sink_beta / "events").rglob("*.jsonl"))
    assert "alpha-ev-1" in alpha_files[0].read_text(encoding="utf-8")
    assert "beta-ev-1" not in alpha_files[0].read_text(encoding="utf-8")
    assert "beta-ev-1" in beta_files[0].read_text(encoding="utf-8")
