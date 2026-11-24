"""Plugin-agnostic SERA orchestration service powering both the Rich CLI and the MCP server.

This module has zero hardcoded knowledge of concrete sources (e.g. `microsoft`) or concrete
destination sinks (e.g. `bigquery`). All source and destination plugins are discovered
dynamically via `SourceRegistry` and `DestinationRegistry`.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from sera import CORE_UV_PACKAGES
from sera.config import (
    DestinationConfig,
    NetworkConfig,
    WorkspaceConfig,
    load_workspace_config,
    save_workspace_config,
    sera_dir_for_workspace,
)
from sera.core.db import SeraDatabase
from sera.core.engine import CollectionEngine
from sera.core.models import JobRecord, JobSpec, JobStatus
from sera.core.registry import DestinationRegistry, SourceRegistry
from sera.core.spool import EphemeralSpoolManager
from sera.destinations.base import BaseDestinationSink
from sera.sources.base import BaseSourceConnector


def collect_required_uv_packages(
    sources: SourceRegistry | None = None,
    destinations: DestinationRegistry | None = None,
) -> list[str]:
    """Aggregate core framework packages plus `required_packages` declared by every discovered plugin."""
    src_reg = sources or SourceRegistry()
    dst_reg = destinations or DestinationRegistry()
    combined = set(CORE_UV_PACKAGES) | set(src_reg.required_packages()) | set(dst_reg.required_packages())
    return sorted(combined)


def ensure_uv_dependencies(
    workspace_dir: Path,
    sources: SourceRegistry | None = None,
    destinations: DestinationRegistry | None = None,
) -> dict[str, Any]:
    """Ensure all upfront core and plugin libraries are installed into `.venv` via `uv`."""
    uv_bin = shutil.which("uv")
    local_venv_py = workspace_dir / ".venv" / "bin" / "python"
    target_python = str(local_venv_py) if local_venv_py.exists() else sys.executable
    packages = collect_required_uv_packages(sources, destinations)

    if not uv_bin:
        return {
            "synced": False,
            "python": target_python,
            "packages": packages,
            "reason": "`uv` binary not found on PATH; using active environment packages.",
        }

    cmd = [uv_bin, "pip", "install", "--python", target_python, *packages]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"`uv pip install` failed (exit {proc.returncode}):\n{proc.stderr.strip() or proc.stdout.strip()}"
        )
    return {
        "synced": True,
        "python": target_python,
        "packages": packages,
    }


def initialize_workspace(
    workspace_dir: Path,
    *,
    destination_type: str,
    destination_name: str = "default",
    destination_options: dict[str, Any] | None = None,
    source_defaults: dict[str, dict[str, Any]] | None = None,
    batch_size: int = 5000,
    sync_uv_deps: bool = True,
    source_registry: SourceRegistry | None = None,
    destination_registry: DestinationRegistry | None = None,
) -> dict[str, Any]:
    """Initialize `<workspace>/.sera/` using plugin-supplied defaults and validate destination configuration."""
    ws = workspace_dir.resolve()
    sdir = sera_dir_for_workspace(ws)
    for sub in ("creds", "spool"):
        (sdir / sub).mkdir(parents=True, exist_ok=True)

    src_reg = source_registry or SourceRegistry()
    dst_reg = destination_registry or DestinationRegistry()
    sink_cls = dst_reg.get_class(destination_type)
    normalized_opts = sink_cls.apply_defaults(dict(destination_options or {}))

    dest_cfg = DestinationConfig(
        name=destination_name,
        type=destination_type,
        options=normalized_opts,
    )
    net_cfg = NetworkConfig()
    # Validate options via the destination plugin before persisting config.toml
    dst_reg.create(dest_cfg)

    cfg = WorkspaceConfig(
        default_destination=destination_name,
        batch_size=batch_size,
        network=net_cfg,
        destinations={destination_name: dest_cfg},
        source_defaults=dict(source_defaults or {}),
    )
    cfg_path = save_workspace_config(ws, cfg)
    db = SeraDatabase(sdir / "sera.sqlite")
    uv_info = (
        ensure_uv_dependencies(ws, src_reg, dst_reg)
        if sync_uv_deps
        else {"synced": False, "reason": "skipped"}
    )

    return {
        "workspace_dir": str(ws),
        "sera_dir": str(sdir),
        "config_path": str(cfg_path),
        "sqlite_path": str(db.db_path),
        "default_destination": destination_name,
        "destination_type": destination_type,
        "uv": uv_info,
    }


class SeraService:
    """Workspace-isolated SERA service shared 1:1 by the CLI and the MCP server."""

    def __init__(
        self,
        workspace_dir: Path,
        *,
        purge_orphan_spools_on_start: bool = False,
        source_registry: SourceRegistry | None = None,
        destination_registry: DestinationRegistry | None = None,
        sink_override: BaseDestinationSink | None = None,
        connector_override: BaseSourceConnector | None = None,
    ) -> None:
        self.workspace_dir = workspace_dir.resolve()
        self.sera_dir = sera_dir_for_workspace(self.workspace_dir)
        self.config = load_workspace_config(self.workspace_dir)
        self.db = SeraDatabase(self.sera_dir / "sera.sqlite")
        self.spool = EphemeralSpoolManager(self.sera_dir / "spool")

        self.sources = source_registry or SourceRegistry()
        self.destinations = destination_registry or DestinationRegistry()
        self._sink_override = sink_override
        self._connector_override = connector_override
        self._background_tasks: dict[str, asyncio.Task[Any]] = {}

        if purge_orphan_spools_on_start:
            self.spool.purge_orphans()
            self.db.reset_interrupted_slices()

    def reload_config(self) -> None:
        self.config = load_workspace_config(self.workspace_dir)

    def get_connector(self, source_name: str) -> BaseSourceConnector:
        if self._connector_override is not None:
            return self._connector_override
        return self.sources.create(source_name, self.workspace_dir, self.config)

    def get_sink(self, destination_name: str = "") -> BaseDestinationSink:
        if self._sink_override is not None:
            return self._sink_override
        dest_cfg = self.config.get_destination(destination_name)
        return self.destinations.create(dest_cfg)

    def configure_source_auth(
        self,
        source_name: str,
        profile: str,
        mode: str,
        values: dict[str, str],
        on_message: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Delegate credential onboarding to the target source plugin and record non-secret metadata."""
        self.reload_config()
        connector = self.get_connector(source_name)
        receipt = connector.configure_auth(
            profile=profile,
            mode=mode,
            values=values,
            on_message=on_message,
        )
        self.db.upsert_auth_profile(
            source=source_name,
            profile=profile,
            auth_mode=str(receipt.get("auth_mode", mode)),
            tenant_id=str(receipt.get("tenant_id", "")),
            client_id=str(receipt.get("client_id", "")),
        )
        return receipt

    def list_sources(self) -> dict[str, Any]:
        """List discovered source plugins, sub_sources, auth modes, and readiness (zero schema sampling)."""
        self.reload_config()
        stored_profiles = self.db.list_auth_profiles()
        result: dict[str, Any] = {}
        for sname in self.sources.names():
            conn = self.get_connector(sname)
            prof_names = [p["profile"] for p in stored_profiles if p["source"] == sname] or ["default"]
            profiles_status = [conn.check_auth_status(p) for p in prof_names]
            result[sname] = {
                "sub_sources": conn.supported_sub_sources(),
                "auth_modes": {
                    m: {"description": spec.description, "fields": [f.name for f in spec.fields]}
                    for m, spec in conn.auth_modes().items()
                },
                "profiles": profiles_status,
                "defaults": self.config.source_defaults.get(sname, {}),
            }
        return result

    def list_destinations(self) -> dict[str, Any]:
        """List configured destinations and all discovered destination sink plugins."""
        self.reload_config()
        configured: dict[str, Any] = {}
        for name, dcfg in self.config.destinations.items():
            sink = self.destinations.create(dcfg)
            configured[name] = sink.config_summary()
        return {
            "default_destination": self.config.default_destination,
            "registered_types": self.destinations.types(),
            "configured": configured,
        }

    def list_templates(self, source: str = "", sub_source: str = "") -> list[dict[str, Any]]:
        """Query discovered source plugins for their canonical full-event templates."""
        self.reload_config()
        target_sources = [source] if source else self.sources.names()
        items: list[dict[str, Any]] = []
        for sname in target_sources:
            conn = self.get_connector(sname)
            if sub_source and sub_source not in conn.supported_sub_sources():
                continue
            items.extend(conn.list_templates(sub_source=sub_source))
        return items

    def enqueue_job(self, spec: JobSpec) -> dict[str, Any]:
        """Validate and create a pending job in `sera.sqlite`, returning `job_id` and plugin lookup hint."""
        self.reload_config()
        connector = self.get_connector(spec.source)
        sink = self.get_sink(spec.destination)
        engine = CollectionEngine(
            config=self.config,
            db=self.db,
            spool=self.spool,
        )
        job_id = engine.enqueue_job(spec, connector, sink)
        return {
            "job_id": job_id,
            "status": JobStatus.PENDING.value,
            "destination_name": sink.dest_config.name,
            "destination_target": sink.describe_target(),
            "lookup_hint": sink.format_lookup_hint(job_id),
        }

    async def execute_enqueued_job(
        self,
        job_id: str,
        on_slice_progress: Callable[[JobRecord], None] | None = None,
    ) -> JobRecord:
        self.reload_config()
        job = self.db.get_job(job_id)
        connector = self.get_connector(job.source)
        sink = self.get_sink(job.destination_name)
        engine = CollectionEngine(
            config=self.config,
            db=self.db,
            spool=self.spool,
        )
        return await engine.execute_job(
            job_id=job_id,
            connector=connector,
            sink=sink,
            on_slice_progress=on_slice_progress,
        )

    def submit_job_async(self, spec: JobSpec) -> dict[str, Any]:
        """Non-blocking job submission for MCP: enqueues job, schedules background task, returns `job_id` immediately."""
        receipt = self.enqueue_job(spec)
        job_id = receipt["job_id"]
        task = asyncio.create_task(self._run_background_safe(job_id))
        self._background_tasks[job_id] = task
        task.add_done_callback(lambda _: self._background_tasks.pop(job_id, None))
        return receipt

    async def _run_background_safe(self, job_id: str) -> None:
        try:
            await self.execute_enqueued_job(job_id)
        except Exception:
            pass

    def check_jobs(self, job_id: str = "", include_slices: bool = False, limit: int = 25) -> dict[str, Any]:
        if job_id.strip():
            rec = self.db.get_job(job_id.strip())
            out = rec.to_summary_dict()
            if include_slices:
                out["slice_details"] = [
                    {
                        "slice_id": s.slice_id,
                        "parent_slice_id": s.parent_slice_id,
                        "start_time": s.start_time,
                        "end_time": s.end_time,
                        "status": s.status.value,
                        "events_fetched": s.events_fetched,
                        "events_uploaded": s.events_uploaded,
                        "attempt_count": s.attempt_count,
                        "last_error": s.last_error,
                    }
                    for s in self.db.list_slices(rec.job_id)
                ]
            return out

        jobs = [j.to_summary_dict() for j in self.db.list_jobs(limit=limit)]
        return {
            "total_returned": len(jobs),
            "total_uploaded_events_in_workspace": self.db.count_uploaded_events(),
            "jobs": jobs,
        }

    def prepare_resume(self, job_id: str) -> JobRecord:
        job = self.db.get_job(job_id)
        if job.status == JobStatus.COMPLETED:
            return job
        for orphan in self.spool.spool_dir.glob(f"{job_id}_*.enc"):
            orphan.unlink(missing_ok=True)
        self.db.reset_interrupted_slices(job_id=job_id)
        return self.db.get_job(job_id)

    def resume_job_async(self, job_id: str) -> dict[str, Any]:
        job = self.prepare_resume(job_id)
        if job.status == JobStatus.COMPLETED:
            return {"job_id": job_id, "status": "completed", "message": "Job is already completed."}
        task = asyncio.create_task(self._run_background_safe(job_id))
        self._background_tasks[job_id] = task
        task.add_done_callback(lambda _: self._background_tasks.pop(job_id, None))
        return {
            "job_id": job_id,
            "status": "resuming",
            "destination_target": job.destination_target,
        }

    async def wait_all_background_tasks(self) -> None:
        tasks = list(self._background_tasks.values())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


class WorkspaceServicePool:
    """Maintains strictly isolated `SeraService` instances keyed by engagement workspace path."""

    def __init__(self) -> None:
        self._pool: dict[Path, SeraService] = {}

    def get(self, workspace_dir: str | Path | None = None) -> SeraService:
        ws = Path(workspace_dir).resolve() if workspace_dir else Path.cwd().resolve()
        if ws not in self._pool:
            self._pool[ws] = SeraService(ws, purge_orphan_spools_on_start=True)
        return self._pool[ws]
