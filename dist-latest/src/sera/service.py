"""Plugin-agnostic SERA orchestration service powering both the Rich CLI and the MCP server.

This module has zero hardcoded knowledge of concrete sources (e.g. `microsoft`) or concrete
destination sinks (e.g. `bigquery`). All source and destination plugins are discovered
dynamically via `SourceRegistry` and `DestinationRegistry`.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from sera import CORE_UV_PACKAGES
from sera.config import (
    DestinationConfig,
    NetworkConfig,
    SourceProfileConfig,
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


def resolve_target_venv_python(workspace_dir: Path) -> str:
    """Resolve the Python interpreter of the currently defined `.venv` (never requiring global install)."""
    active_venv = os.environ.get("VIRTUAL_ENV", "").strip()
    if active_venv:
        active_py = Path(active_venv).expanduser() / "bin" / "python"
        if active_py.exists():
            return str(active_py)
    for candidate_root in (workspace_dir, workspace_dir.parent):
        candidate_py = candidate_root / ".venv" / "bin" / "python"
        if candidate_py.exists():
            return str(candidate_py)
    return sys.executable


def ensure_uv_dependencies(
    workspace_dir: Path,
    sources: SourceRegistry | None = None,
    destinations: DestinationRegistry | None = None,
) -> dict[str, Any]:
    """Ensure all upfront core and plugin libraries are installed into the active `.venv` via `uv`."""
    uv_bin = shutil.which("uv")
    target_python = resolve_target_venv_python(workspace_dir)
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
    destination_type: str = "",
    destination_name: str = "default",
    destination_options: dict[str, Any] | None = None,
    source_defaults: dict[str, dict[str, Any]] | None = None,
    batch_size: int = 5000,
    sync_uv_deps: bool = True,
    source_registry: SourceRegistry | None = None,
    destination_registry: DestinationRegistry | None = None,
) -> dict[str, Any]:
    """Initialize `<workspace>/.sera/` (`config.toml`, `sera.sqlite`, `creds/`, `spool/`) and sync `.venv` deps."""
    ws = workspace_dir.resolve()
    sdir = sera_dir_for_workspace(ws)
    for sub in ("creds", "spool"):
        (sdir / sub).mkdir(parents=True, exist_ok=True)
    db = SeraDatabase(sdir / "sera.sqlite")

    src_reg = source_registry or SourceRegistry()
    dst_reg = destination_registry or DestinationRegistry()

    try:
        cfg_path = sdir / "config.toml"
        if cfg_path.exists():
            cfg = load_workspace_config(ws)
            cfg.batch_size = batch_size
            if source_defaults:
                cfg.source_defaults.update(source_defaults)
        else:
            cfg = WorkspaceConfig(
                batch_size=batch_size,
                network=NetworkConfig(),
                source_defaults=dict(source_defaults or {}),
            )

        if destination_type.strip():
            dtype = destination_type.strip()
            dname = destination_name.strip() or "default"
            sink_cls = dst_reg.get_class(dtype)
            normalized_opts = sink_cls.apply_defaults(dict(destination_options or {}))
            dest_cfg = DestinationConfig(name=dname, type=dtype, options=normalized_opts)
            dst_reg.create(dest_cfg, workspace_dir=ws)
            cfg.destinations[dname] = dest_cfg
            if not cfg.default_destination:
                cfg.default_destination = dname

        saved_cfg_path = save_workspace_config(ws, cfg)
        uv_info = (
            ensure_uv_dependencies(ws, src_reg, dst_reg)
            if sync_uv_deps
            else {"synced": False, "reason": "skipped"}
        )
    except Exception as exc:
        db.log_activity(
            "init",
            "failed",
            f"Workspace initialization failed in '{ws}'",
            details={"batch_size": batch_size, "destination_type": destination_type},
            error_message=str(exc),
        )
        raise

    next_hint = (
        "Workspace initialized. Next step: configure a telemetry source and authentication "
        "via `sera source add <type>` (inspect options with `sera source types`)."
    )
    db.log_activity(
        "init",
        "completed",
        "Initialized SERA workspace",
        details={
            "batch_size": batch_size,
            "uv_synced": bool(uv_info.get("synced")),
            "default_destination": cfg.default_destination,
        },
        next_step_hint=next_hint,
    )

    return {
        "workspace_dir": str(ws),
        "sera_dir": str(sdir),
        "config_path": str(saved_cfg_path),
        "sqlite_path": str(db.db_path),
        "default_source": cfg.default_source,
        "default_destination": cfg.default_destination,
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

    def resolve_source_and_profile(self, source_or_profile: str, profile: str = "default") -> tuple[str, str]:
        """Resolve `(source_plugin_type, profile_name)` from either plugin name or configured profile name."""
        key = source_or_profile.strip()
        prof = profile.strip() or "default"
        if not key and self.config.default_source and self.config.default_source in self.config.sources:
            sp = self.config.sources[self.config.default_source]
            return sp.type, sp.name
        if key in self.sources.names():
            return key, prof
        if key in self.config.sources:
            sp = self.config.sources[key]
            return sp.type, sp.name
        return key, prof

    def get_connector(self, source_name: str) -> BaseSourceConnector:
        if self._connector_override is not None:
            return self._connector_override
        resolved_type, _ = self.resolve_source_and_profile(source_name)
        return self.sources.create(resolved_type, self.workspace_dir, self.config)

    def get_sink(self, destination_name: str = "") -> BaseDestinationSink:
        if self._sink_override is not None:
            return self._sink_override
        dest_cfg = self.config.get_destination(destination_name)
        return self.destinations.create(dest_cfg, workspace_dir=self.workspace_dir)

    def add_source(
        self,
        source_type: str,
        *,
        profile: str = "default",
        auth_mode: str,
        source_options: dict[str, Any] | None = None,
        auth_values: dict[str, str] | None = None,
        set_default: bool = False,
        on_message: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Configure a source profile (source-specific options like proxy + isolated auth credentials)."""
        self.reload_config()
        stype = source_type.strip()
        pname = profile.strip() or "default"
        try:
            src_cls = self.sources.get_class(stype)

            existing_opts = (
                dict(self.config.sources[pname].options)
                if pname in self.config.sources and self.config.sources[pname].type == stype
                else {}
            )
            existing_opts.update(source_options or {})
            normalized_opts = src_cls.apply_defaults(existing_opts)

            self.config.sources[pname] = SourceProfileConfig(
                name=pname,
                type=stype,
                options=normalized_opts,
            )
            if set_default or not self.config.default_source:
                self.config.default_source = pname
            save_workspace_config(self.workspace_dir, self.config)

            connector = self.get_connector(stype)
            auth_inputs = dict(auth_values or {})
            # Also pass source proxy_url / ca_bundle if present so initial interactive login (device-code/browser) uses it
            for net_key in ("proxy_url", "ca_bundle"):
                if normalized_opts.get(net_key) and net_key not in auth_inputs:
                    auth_inputs[net_key] = str(normalized_opts[net_key])

            self.db.log_activity(
                "source.add",
                "started",
                f"Starting authentication for source '{pname}' ({stype}, mode={auth_mode.strip()})",
                details={"source_type": stype, "profile": pname, "auth_mode": auth_mode.strip(), "options": normalized_opts},
            )
            receipt = connector.configure_auth(
                profile=pname,
                mode=auth_mode.strip(),
                values=auth_inputs,
                on_message=on_message,
            )
            self.db.upsert_auth_profile(
                source=stype,
                profile=pname,
                auth_mode=str(receipt.get("auth_mode", auth_mode)),
                tenant_id=str(receipt.get("tenant_id", "")),
                client_id=str(receipt.get("client_id", "")),
            )
        except Exception as exc:
            self.db.log_activity(
                "source.add",
                "failed",
                f"Failed to configure source '{pname}' ({stype}, mode={auth_mode.strip()})",
                details={"source_type": stype, "profile": pname, "auth_mode": auth_mode.strip(), "options": source_options or {}},
                error_message=str(exc),
            )
            raise

        next_hint = (
            "Source configured and authenticated. Next step: configure a destination sink via `sera dest add <type>`."
            if not self.config.destinations
            else "Source and destination are both configured. Ready to submit extraction jobs via MCP `collect` or `sera collect`."
        )
        self.db.log_activity(
            "source.add",
            "completed",
            f"Configured source '{pname}' ({stype}, auth={receipt.get('auth_mode', auth_mode.strip())})",
            details={
                "source_type": stype,
                "profile": pname,
                "auth_mode": str(receipt.get("auth_mode", auth_mode.strip())),
                "options": normalized_opts,
            },
            next_step_hint=next_hint,
        )
        return {
            **receipt,
            "source_type": stype,
            "profile": pname,
            "default_source": self.config.default_source == pname,
            "options": normalized_opts,
        }

    def configure_source_auth(
        self,
        source_name: str,
        profile: str,
        mode: str,
        values: dict[str, str],
        on_message: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Delegate credential onboarding and split any source options cleanly into `[sources.<profile>]`."""
        src_cls = self.sources.get_class(source_name.strip())
        opt_names = {s.name for s in src_cls.option_specs()}
        src_opts = {k: v for k, v in values.items() if k in opt_names and str(v).strip() != ""}
        auth_vals = {k: v for k, v in values.items() if k not in opt_names or k in {"proxy_url", "ca_bundle"}}
        return self.add_source(
            source_type=source_name,
            profile=profile,
            auth_mode=mode,
            source_options=src_opts,
            auth_values=auth_vals,
            on_message=on_message,
        )

    def add_destination(
        self,
        dest_type: str,
        *,
        name: str = "default",
        auth_mode: str = "",
        dest_options: dict[str, Any] | None = None,
        auth_values: dict[str, str] | None = None,
        set_default: bool = False,
    ) -> dict[str, Any]:
        """Configure a destination profile (sink-specific options like file paths / HTTP proxy + isolated auth)."""
        self.reload_config()
        dtype = dest_type.strip()
        dname = name.strip() or "default"
        try:
            sink_cls = self.destinations.get_class(dtype)
            modes = sink_cls.auth_modes()
            resolved_mode = auth_mode.strip() or next(iter(modes))
            if resolved_mode not in modes:
                raise ValueError(
                    f"Unsupported auth mode '{resolved_mode}' for destination '{dtype}'. Valid: {', '.join(sorted(modes))}"
                )

            normalized_opts = sink_cls.apply_defaults(dict(dest_options or {}))
            dest_cfg = DestinationConfig(name=dname, type=dtype, options=normalized_opts)
            sink = self.destinations.create(dest_cfg, workspace_dir=self.workspace_dir)
            auth_receipt = sink.configure_auth(
                self.workspace_dir,
                mode=resolved_mode,
                values=dict(auth_values or {}),
            )

            self.config.destinations[dname] = dest_cfg
            if set_default or not self.config.default_destination:
                self.config.default_destination = dname
            save_workspace_config(self.workspace_dir, self.config)
            target_desc = sink.describe_target()
        except Exception as exc:
            self.db.log_activity(
                "dest.add",
                "failed",
                f"Failed to configure destination '{dname}' ({dtype})",
                details={"name": dname, "type": dtype, "auth_mode": auth_mode.strip(), "options": dest_options or {}},
                error_message=str(exc),
            )
            raise

        has_source = bool(self.db.list_auth_profiles())
        next_hint = (
            "Destination and source are both configured. Ready to submit extraction jobs via MCP `collect` or `sera collect`."
            if has_source
            else "Destination configured. Next step: configure a telemetry source and authentication via `sera source add <type>`."
        )
        self.db.log_activity(
            "dest.add",
            "completed",
            f"Configured destination '{dname}' ({dtype}) -> {target_desc}",
            details={
                "name": dname,
                "type": dtype,
                "auth_mode": auth_receipt["auth_mode"],
                "target": target_desc,
                "options": normalized_opts,
            },
            next_step_hint=next_hint,
        )

        return {
            "name": dname,
            "type": dtype,
            "auth_mode": auth_receipt["auth_mode"],
            "target": target_desc,
            "default_destination": self.config.default_destination == dname,
            "summary": sink.config_summary(),
        }

    def list_sources(self) -> dict[str, Any]:
        """List discovered source plugins, configured profiles, options, auth modes, and readiness."""
        self.reload_config()
        stored_profiles = self.db.list_auth_profiles()
        result: dict[str, Any] = {}
        for sname in self.sources.names():
            conn = self.get_connector(sname)
            cfg_prof_names = [p.name for p in self.config.sources.values() if p.type == sname]
            db_prof_names = [p["profile"] for p in stored_profiles if p["source"] == sname]
            prof_names = list(dict.fromkeys([*cfg_prof_names, *db_prof_names])) or ["default"]
            profiles_status = []
            for p in prof_names:
                st = conn.check_auth_status(p)
                if p in self.config.sources and self.config.sources[p].type == sname:
                    st["options"] = self.config.sources[p].options
                profiles_status.append(st)

            result[sname] = {
                "sub_sources": conn.supported_sub_sources(),
                "options": [
                    {"name": o.name, "required": o.required, "default": o.default, "description": o.description}
                    for o in conn.option_specs()
                ],
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
            sink = self.destinations.create(dcfg, workspace_dir=self.workspace_dir)
            configured[name] = sink.config_summary()
        return {
            "default_destination": self.config.default_destination,
            "registered_types": self.destinations.types(),
            "configured": configured,
        }

    def list_templates(self, source: str = "", sub_source: str = "") -> list[dict[str, Any]]:
        """Query discovered source plugins for their canonical full-event templates."""
        self.reload_config()
        if source.strip():
            resolved_type, _ = self.resolve_source_and_profile(source.strip())
            target_sources = [resolved_type]
        else:
            target_sources = self.sources.names()
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
        resolved_type, resolved_prof = self.resolve_source_and_profile(spec.source, spec.profile)
        normalized_spec = JobSpec(
            source=resolved_type,
            sub_source=spec.sub_source,
            table_or_endpoint=spec.table_or_endpoint,
            start_time=spec.start_time,
            end_time=spec.end_time,
            template=spec.template,
            params=spec.params,
            profile=resolved_prof,
            target_id=spec.target_id,
            destination=spec.destination,
            initial_chunk_hours=spec.initial_chunk_hours,
        )
        connector = self.get_connector(resolved_type)
        sink = self.get_sink(normalized_spec.destination)
        engine = CollectionEngine(
            config=self.config,
            db=self.db,
            spool=self.spool,
        )
        job_id = engine.enqueue_job(normalized_spec, connector, sink)
        lookup_hint = sink.format_lookup_hint(job_id)
        self.db.log_activity(
            "job.queued",
            "started",
            f"Queued extraction job '{job_id}' ({resolved_type}/{spec.sub_source}:{spec.table_or_endpoint})",
            details={
                "job_id": job_id,
                "source": resolved_type,
                "sub_source": spec.sub_source,
                "target": spec.table_or_endpoint,
                "destination_target": sink.describe_target(),
                "lookup_hint": lookup_hint,
            },
        )
        return {
            "job_id": job_id,
            "status": JobStatus.PENDING.value,
            "destination_name": sink.dest_config.name,
            "destination_target": sink.describe_target(),
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
        )
        try:
            final_rec = await engine.execute_job(
                job_id=job_id,
                connector=connector,
                sink=sink,
                on_slice_progress=on_slice_progress,
            )
        except Exception as exc:
            self.db.log_activity(
                "job.failed",
                "failed",
                f"Extraction job '{job_id}' failed",
                details={
                    "job_id": job_id,
                    "source": job.source,
                    "sub_source": job.sub_source,
                    "target": job.table_or_endpoint,
                },
                error_message=str(exc),
            )
            raise

        lookup_hint = sink.format_lookup_hint(job_id)
        self.db.log_activity(
            "job.completed",
            "completed",
            f"Completed job '{job_id}' ({final_rec.events_uploaded} events uploaded)",
            details={
                "job_id": job_id,
                "source": final_rec.source,
                "sub_source": final_rec.sub_source,
                "target": final_rec.table_or_endpoint,
                "events_uploaded": final_rec.events_uploaded,
                "events_skipped_uploaded": final_rec.events_skipped_uploaded,
                "destination_target": final_rec.destination_target,
                "lookup_hint": lookup_hint,
            },
            next_step_hint=f"Job `{job_id}` finished uploading ({final_rec.events_uploaded} events). Query via: `{lookup_hint}`",
        )
        return final_rec

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
