"""SERA MCP Server — plugin-agnostic 1-to-1 parity adapter over `SeraService` matching `sera` CLI commands."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

try:
    from mcp.server import MCPServer
except ImportError:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP as MCPServer  # type: ignore[no-redef]

from sera import __app_name__, __version__
from sera.core.models import JobSpec
from sera.service import WorkspaceServicePool


def create_mcp_server(default_workspace: Path | None = None) -> tuple[MCPServer, WorkspaceServicePool]:
    """Create the SERA MCPServer and its workspace-isolated service pool."""
    pool = WorkspaceServicePool()

    server = MCPServer(
        name="sera",
        title=__app_name__,
        version=__version__,
        instructions=(
            "SERA (Secure Extraction for Response Agents) downloads full, unsummarized forensic telemetry "
            "from registered source plugins into configured destination sink plugins using canonical "
            "full-event templates and ephemeral AES-256-GCM spooling. Schema sampling is disabled. "
            "MCP tools map 1-to-1 to `sera` CLI commands: use `collect` (non-blocking) to obtain a `job_id`, "
            "and `jobs` or `status` to track upload completion."
        ),
    )

    def _svc(workspace_dir: str = ""):
        target_ws = Path(workspace_dir).resolve() if workspace_dir.strip() else (default_workspace or Path.cwd())
        return pool.get(target_ws)

    @server.tool(
        name="collect",
        description=(
            "Submit a non-blocking forensic log extraction job (mirrors `sera collect`). "
            "Returns `job_id` immediately (use `job_id` to look up uploaded logs in the destination target)."
        ),
    )
    async def collect(
        source: str,
        sub_source: str,
        target: str,
        start: str,
        end: str,
        params: dict[str, Any] | None = None,
        profile: str = "default",
        target_id: str = "",
        destination: str = "",
        chunk_hours: float | None = None,
        workspace_dir: str = "",
    ) -> dict[str, Any]:
        service = _svc(workspace_dir)
        spec = JobSpec(
            source=source.strip(),
            sub_source=sub_source.strip(),
            table_or_endpoint=target.strip(),
            start_time=start.strip(),
            end_time=end.strip(),
            template="canonical",
            params=dict(params or {}),
            profile=profile.strip() or "default",
            target_id=target_id.strip(),
            destination=destination.strip(),
            initial_chunk_hours=chunk_hours,
        )
        return service.submit_job_async(spec)

    @server.tool(
        name="jobs",
        description=(
            "List recent extraction jobs and workspace uploaded event totals (mirrors `sera jobs`). Non-blocking."
        ),
    )
    async def jobs(
        limit: int = 25,
        workspace_dir: str = "",
    ) -> dict[str, Any]:
        service = _svc(workspace_dir)
        return service.check_jobs(limit=limit)

    @server.tool(
        name="status",
        description=(
            "Inspect live slice progress or final completion summary for a single `job_id` "
            "(mirrors `sera status <job_id>`). Non-blocking."
        ),
    )
    async def status(
        job_id: str,
        slices: bool = False,
        workspace_dir: str = "",
    ) -> dict[str, Any]:
        service = _svc(workspace_dir)
        return service.check_jobs(job_id=job_id.strip(), include_slices=slices)

    @server.tool(
        name="resume",
        description=(
            "Resume an interrupted or failed job at the slice level, re-fetching only uncommitted slices "
            "while skipping events already recorded in `uploaded_events` (mirrors `sera resume <job_id>`). Non-blocking."
        ),
    )
    async def resume(
        job_id: str,
        workspace_dir: str = "",
    ) -> dict[str, Any]:
        service = _svc(workspace_dir)
        return service.resume_job_async(job_id=job_id.strip())

    @server.tool(
        name="sources",
        description=(
            "List discovered source plugins, supported `sub_source`s, auth modes, and profile readiness "
            "(mirrors `sera sources`). Never exposes secret values or customer schema samples."
        ),
    )
    async def sources(workspace_dir: str = "") -> dict[str, Any]:
        service = _svc(workspace_dir)
        return service.list_sources()

    @server.tool(
        name="destinations",
        description="List configured destination sinks and discovered destination plugin types (mirrors `sera destinations`).",
    )
    async def destinations(workspace_dir: str = "") -> dict[str, Any]:
        service = _svc(workspace_dir)
        return service.list_destinations()

    @server.tool(
        name="templates",
        description=(
            "List the canonical full-event query template and allowed filter `params` per source/sub_source "
            "(mirrors `sera templates`)."
        ),
    )
    async def templates(
        source: str = "",
        sub_source: str = "",
        workspace_dir: str = "",
    ) -> list[dict[str, Any]]:
        service = _svc(workspace_dir)
        return service.list_templates(source=source.strip(), sub_source=sub_source.strip())

    return server, pool


def main() -> None:
    parser = argparse.ArgumentParser(description="SERA MCP Server")
    parser.add_argument(
        "--workspace",
        default="",
        help="Optional default engagement workspace path (defaults to CWD / hook-bound workspace)",
    )
    args = parser.parse_args()
    ws = Path(args.workspace).resolve() if args.workspace else None
    server, _ = create_mcp_server(default_workspace=ws)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
