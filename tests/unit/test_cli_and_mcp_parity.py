"""End-to-end parity tests proving identical workflows across `sera` CLI and `MCPServer`, plus zero cross-case overlap."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import respx
from typer.testing import CliRunner

from sera.cli.app import app
from sera.mcp_server.server import create_mcp_server


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


async def test_cli_and_mcp_full_parity_and_multi_engagement_isolation(tmp_path: Path) -> None:
    case_alpha = tmp_path / "case_alpha"
    case_beta = tmp_path / "case_beta"
    sink_alpha = tmp_path / "sink_alpha"
    sink_beta = tmp_path / "sink_beta"

    # 1. Initialize TWO independent client engagement workspaces via plugin-driven CLI
    for ws, sink in ((case_alpha, sink_alpha), (case_beta, sink_beta)):
        res = runner.invoke(
            app,
            [
                "init",
                "--workspace",
                str(ws),
                "--dest-type",
                "jsonl",
                "--dest-opt",
                f"output_dir={sink}",
                "--skip-uv",
                "--json",
            ],
        )
        assert res.exit_code == 0, res.output

    # Configure isolated tokens in each engagement workspace via generic plugin CLI
    assert (
        runner.invoke(
            app,
            [
                "auth",
                "add",
                "microsoft",
                "--mode",
                "static-bearer",
                "--opt",
                "access_token=tok-alpha",
                "--opt",
                "tenant_id=tenant-alpha",
                "--workspace",
                str(case_alpha),
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app,
            [
                "auth",
                "add",
                "microsoft",
                "--mode",
                "static-bearer",
                "--opt",
                "access_token=tok-beta",
                "--opt",
                "tenant_id=tenant-beta",
                "--workspace",
                str(case_beta),
            ],
        ).exit_code
        == 0
    )

    mcp_server, pool = create_mcp_server()
    cli_sources = json.loads(
        runner.invoke(app, ["sources", "--workspace", str(case_alpha), "--json"]).stdout
    )
    mcp_sources = _extract_mcp_json(
        await mcp_server.call_tool("list_sources", {"workspace_dir": str(case_alpha)})
    )
    assert cli_sources == mcp_sources
    assert mcp_sources["microsoft"]["profiles"][0]["tenant_id"] == "tenant-alpha"  # type: ignore[index]

    cli_templates = json.loads(
        runner.invoke(app, ["templates", "--sub-source", "entra", "--workspace", str(case_alpha), "--json"]).stdout
    )
    mcp_templates = _extract_mcp_json(
        await mcp_server.call_tool("list_templates", {"sub_source": "entra", "workspace_dir": str(case_alpha)})
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

        cli_collect = await asyncio.to_thread(
            runner.invoke,
            app,
            [
                "collect",
                "--source",
                "microsoft",
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

        submit_res = _extract_mcp_json(
            await mcp_server.call_tool(
                "submit_job",
                {
                    "source": "microsoft",
                    "sub_source": "entra",
                    "table_or_endpoint": "signIns",
                    "start_time": "2026-11-20T00:00:00Z",
                    "end_time": "2026-11-21T00:00:00Z",
                    "workspace_dir": str(case_beta),
                },
            )
        )
        assert isinstance(submit_res, dict)
        beta_job_id = submit_res["job_id"]
        await pool.get(case_beta).wait_all_background_tasks()

        beta_status = _extract_mcp_json(
            await mcp_server.call_tool(
                "check_jobs",
                {"job_id": beta_job_id, "workspace_dir": str(case_beta)},
            )
        )
        assert isinstance(beta_status, dict)
        assert beta_status["status"] == "completed"
        assert beta_status["events_uploaded"] == 1

    alpha_files = list((sink_alpha / "events").rglob("*.jsonl"))
    beta_files = list((sink_beta / "events").rglob("*.jsonl"))
    assert "alpha-ev-1" in alpha_files[0].read_text(encoding="utf-8")
    assert "beta-ev-1" not in alpha_files[0].read_text(encoding="utf-8")
    assert "beta-ev-1" in beta_files[0].read_text(encoding="utf-8")
