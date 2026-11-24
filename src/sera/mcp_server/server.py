"""SERA MCP Server — full parity adapter over `SeraService`."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

try:
    from mcp.server import MCPServer
except ImportError:  # pragma: no cover - fallback for older mcp 1.x environments
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
            "using allowlisted query templates, encrypts batches in an ephemeral spool, and uploads them "
            "to the engagement's configured destination. Schema sampling is disabled. Use `submit_job` "
            "(non-blocking) to get a `job_id`, and `check_jobs` to track upload completion."
        ),
    )

    def _svc(workspace_dir: str = ""):
        target = Path(workspace_dir).resolve() if workspace_dir.strip() else (default_workspace or Path.cwd())
        return pool.get(target)

    @server.tool(
        name="submit_job",
        description=(
            "Submit a non-blocking forensic log extraction job using an allowlisted query template. "
            "Returns `job_id` immediately (use `job_id` to look up uploaded logs in the destination target)."
        ),
    )
    async def submit_job(
        source: str,
        sub_source: str,
        table_or_endpoint: str,
        start_time: str,
        end_time: str,
        params: dict[str, Any] | None = None,
        profile: str = "default",
        target_id: str = "",
        destination: str = "",
        initial_chunk_hours: float | None = None,
        workspace_dir: str = "",
    ) -> dict[str, Any]:
        service = _svc(workspace_dir)
        spec = JobSpec(
            source=source.strip(),
            sub_source=sub_source.strip(),
            table_or_endpoint=table_or_endpoint.strip(),
            start_time=start_time.strip(),
            end_time=end_time.strip(),
            template="canonical",
            params=dict(params or {}),
            profile=profile.strip() or "default",
            target_id=target_id.strip(),
            destination=destination.strip(),
            initial_chunk_hours=initial_chunk_hours,
        )
        return service.submit_job_async(spec)

    @server.tool(
        name="check_jobs",
        description=(
            "Check live progress or final completion summary for a specific `job_id` (or list recent jobs "
            "when `job_id` is omitted). Non-blocking."
        ),
    )
    async def check_jobs(
        job_id: str = "",
        include_slices: bool = False,
        limit: int = 25,
        workspace_dir: str = "",
    ) -> dict[str, Any]:
        service = _svc(workspace_dir)
        return service.check_jobs(job_id=job_id, include_slices=include_slices, limit=limit)

    @server.tool(
        name="resume_job",
        description=(
            "Resume an interrupted or failed job at the slice level (re-fetching only uncommitted slices "
            "while skipping events already recorded in `uploaded_events`). Non-blocking."
        ),
    )
    async def resume_job(
        job_id: str,
        workspace_dir: str = "",
    ) -> dict[str, Any]:
        service = _svc(workspace_dir)
        return service.resume_job_async(job_id=job_id.strip())

    @server.tool(
        name="list_sources",
        description=(
            "List configured telemetry sources, supported `sub_source`s, and auth readiness status. "
            "Never exposes secret values or customer schema samples."
        ),
    )
    async def list_sources(workspace_dir: str = "") -> dict[str, Any]:
        service = _svc(workspace_dir)
        return service.list_sources()

    @server.tool(
        name="list_destinations",
        description="List configured customizable destinations and target coordinates for this engagement.",
    )
    async def list_destinations(workspace_dir: str = "") -> dict[str, Any]:
        service = _svc(workspace_dir)
        return service.list_destinations()

    @server.tool(
        name="list_templates",
        description="List allowlisted parameterized query templates and their typed parameter schemas.",
    )
    async def list_templates(
        sub_source: str = "",
        workspace_dir: str = "",
    ) -> list[dict[str, Any]]:
        service = _svc(workspace_dir)
        return service.list_templates(sub_source=sub_source.strip())

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
