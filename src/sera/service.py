"""Unified SERA orchestration service powering both the Rich CLI and the MCP server."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from sera import REQUIRED_UV_PACKAGES
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
from sera.core.templates import TemplateRegistry
from sera.destinations.base import BaseDestinationSink
from sera.sources.base import BaseSourceConnector
from sera.sources.microsoft.connector import MicrosoftSourceConnector


def ensure_uv_dependencies(workspace_dir: Path) -> dict[str, Any]:
    """Ensure all upfront SERA libraries are installed into `.venv` via `uv`."""
    uv_bin = shutil.which("uv")
    local_venv_py = workspace_dir / ".venv" / "bin" / "python"
    target_python = str(local_venv_py) if local_venv_py.exists() else sys.executable

    if not uv_bin:
        return {
            "synced": False,
            "python": target_python,
            "reason": "`uv` binary not found on PATH; using active environment packages.",
        }

    cmd = [uv_bin, "pip", "install", "--python", target_python, *REQUIRED_UV_PACKAGES]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"`uv pip install` failed (exit {proc.returncode}):\n{proc.stderr.strip() or proc.stdout.strip()}"
        )
    return {
        "synced": True,
        "python": target_python,
        "packages": list(REQUIRED_UV_PACKAGES),
    }


def initialize_workspace(
    workspace_dir: Path,
    *,
    destination_name: str = "bigquery",
    destination_type: str = "bigquery",
    destination_options: dict[str, Any] | None = None,
    proxy_url: str = "",
    ca_bundle: str = "",
    verify_tls: bool = True,
    default_workspace_id: str = "",
    default_subscription_id: str = "",
    batch_size: int = 5000,
    sync_uv_deps: bool = True,
) -> dict[str, Any]:
    """Initialize `<workspace>/.sera/` (`config.toml`, `sera.sqlite`, `creds/`, `spool/`, `templates/`)."""
    ws = workspace_dir.resolve()
    sdir = sera_dir_for_workspace(ws)
    for sub in ("creds", "spool"):
        (sdir / sub).mkdir(parents=True, exist_ok=True)

    opts = dict(destination_options or {})
    if destination_type == "bigquery":
        opts.setdefault("dataset_id", "sera_raw")
        opts.setdefault("events_table", "events")
        opts.setdefault("jobs_table", "collection_jobs")
        opts.setdefault("location", "US")
        opts.setdefault("partition_field", "event_timestamp")
        opts.setdefault("cluster_fields", ["source", "sub_source", "table_or_endpoint"])

    source_defaults: dict[str, dict[str, Any]] = {}
    ms_defs: dict[str, Any] = {}
    if default_workspace_id.strip():
        ms_defs["default_workspace_id"] = default_workspace_id.strip()
    if default_subscription_id.strip():
        ms_defs["default_subscription_id"] = default_subscription_id.strip()
    if ms_defs:
        source_defaults["microsoft"] = ms_defs

    cfg = WorkspaceConfig(
        default_destination=destination_name,
        batch_size=batch_size,
        network=NetworkConfig(
            proxy_url=proxy_url.strip(),
            ca_bundle=ca_bundle.strip(),
            verify_tls=verify_tls,
        ),
        destinations={
            destination_name: DestinationConfig(
                name=destination_name,
                type=destination_type,
                options=opts,
            )
        },
        source_defaults=source_defaults,
    )
    cfg_path = save_workspace_config(ws, cfg)
    db = SeraDatabase(sdir / "sera.sqlite")
    uv_info = ensure_uv_dependencies(ws) if sync_uv_deps else {"synced": False, "reason": "skipped"}

    return {
        "workspace_dir": str(ws),
        "sera_dir": str(sdir),
        "config_path": str(cfg_path),
        "sqlite_path": str(db.db_path),
        "default_destination": destination_name,
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
        self.templates = TemplateRegistry()

        self.sources = source_registry or SourceRegistry()
        if "microsoft" not in self.sources.names():
            self.sources.register(MicrosoftSourceConnector)

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
        return self.destinations.create(dest_cfg, self.config.network)

    def list_sources(self) -> dict[str, Any]:
        """List registered sources, sub_sources, and auth readiness (zero schema sampling)."""
        self.reload_config()
        stored_profiles = self.db.list_auth_profiles()
        result: dict[str, Any] = {}
        for sname in self.sources.names():
            conn = self.get_connector(sname)
            prof_names = [p["profile"] for p in stored_profiles if p["source"] == sname] or ["default"]
            profiles_status = [conn.check_auth_status(p) for p in prof_names]
            result[sname] = {
                "sub_sources": conn.supported_sub_sources(),
                "profiles": profiles_status,
                "defaults": self.config.source_defaults.get(sname, {}),
            }
        return result

    def list_destinations(self) -> dict[str, Any]:
        """List configured destinations and registered sink types."""
        self.reload_config()
        configured: dict[str, Any] = {}
        for name, dcfg in self.config.destinations.items():
            sink = self.destinations.create(dcfg, self.config.network)
            configured[name] = sink.config_summary()
        return {
            "default_destination": self.config.default_destination,
            "registered_types": self.destinations.types(),
            "configured": configured,
        }

    def list_templates(self, sub_source: str = "") -> list[dict[str, Any]]:
        self.reload_config()
        return self.templates.list_templates(sub_source=sub_source)

    def enqueue_job(self, spec: JobSpec) -> dict[str, Any]:
        """Validate and create a pending job in `sera.sqlite`, returning its `job_id` and lookup metadata."""
        self.reload_config()
        connector = self.get_connector(spec.source)
        sink = self.get_sink(spec.destination)
        engine = CollectionEngine(
            config=self.config,
            db=self.db,
            spool=self.spool,
            templates=self.templates,
        )
        job_id = engine.enqueue_job(spec, connector, sink)
        target = sink.describe_target()
        lookup_hint = (
            f"SELECT * FROM `{target}` WHERE job_id = '{job_id}'"
            if sink.sink_type == "bigquery"
            else f"job_id={job_id} in {target}"
        )
        return {
            "job_id": job_id,
            "status": JobStatus.PENDING.value,
            "destination_name": sink.dest_config.name,
            "destination_target": target,
            "lookup_hint": lookup_hint,
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
            templates=self.templates,
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
            # Error is already persisted on `jobs.error_message` and `job_slices.last_error` in sera.sqlite
            pass

    def check_jobs(self, job_id: str = "", include_slices: bool = False, limit: int = 25) -> dict[str, Any]:
        """Non-blocking progress & completion summary lookup used by both CLI and MCP."""
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
        """Reset uncommitted (`in_progress`/`failed`) slices to `pending` while keeping uploaded slices intact."""
        job = self.db.get_job(job_id)
        if job.status == JobStatus.COMPLETED:
            return job
        # Purge any unreadable `.enc` spool leftovers for this job before re-fetching uncommitted slices
        for orphan in self.spool.spool_dir.glob(f"{job_id}_*.enc"):
            orphan.unlink(missing_ok=True)
        self.db.reset_interrupted_slices(job_id=job_id)
        return self.db.get_job(job_id)

    def resume_job_async(self, job_id: str) -> dict[str, Any]:
        """Non-blocking resume for MCP: resets uncommitted slices and schedules background execution."""
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
        """Await any active background tasks (useful in tests and graceful shutdown)."""
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
