"""LLM-oriented operational event monitor (`sera monitor`) for reactive next-step & error guidance.

Allows an LLM agent to watch for out-of-band terminal completions or failures (`init`, `source add`,
`auth`, `dest add`, and background jobs) without accessing `.sera/` secrets directly.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Callable

from sera.config import load_workspace_config, sera_dir_for_workspace
from sera.core.db import SeraDatabase
from sera.core.models import JobStatus
from sera.core.registry import DestinationRegistry, SourceRegistry


def inspect_workspace_readiness(workspace_dir: Path) -> dict[str, Any]:
    """Return a non-secret snapshot of current workspace setup stage and readiness."""
    ws = workspace_dir.resolve()
    sdir = sera_dir_for_workspace(ws)
    cfg_path = sdir / "config.toml"
    db_path = sdir / "sera.sqlite"

    if not cfg_path.exists() or not db_path.exists():
        return {
            "initialized": False,
            "stage": "uninitialized",
            "default_source": "",
            "sources_ready": [],
            "default_destination": "",
            "destinations_configured": [],
            "active_jobs": 0,
            "failed_jobs": 0,
            "recommended_next_step": "Run `sera init` in the engagement workspace.",
        }

    cfg = load_workspace_config(ws)
    db = SeraDatabase(db_path)
    src_reg = SourceRegistry()
    dst_reg = DestinationRegistry()

    sources_ready: list[dict[str, Any]] = []
    stored_auth = db.list_auth_profiles()
    seen_pairs: set[tuple[str, str]] = set()
    for sp in cfg.sources.values():
        seen_pairs.add((sp.type, sp.name))
    for ap in stored_auth:
        seen_pairs.add((str(ap["source"]), str(ap["profile"])))

    for stype, prof in sorted(seen_pairs):
        if stype not in src_reg.names():
            continue
        conn = src_reg.create(stype, ws, cfg)
        st = conn.check_auth_status(prof)
        if st.get("configured"):
            sources_ready.append(
                {
                    "source_type": stype,
                    "profile": prof,
                    "auth_mode": st.get("auth_mode"),
                    "has_proxy": bool(conn.source_network(prof).proxy_url),
                }
            )

    destinations_configured: list[dict[str, Any]] = []
    for dname, dcfg in sorted(cfg.destinations.items()):
        if dcfg.type not in dst_reg.types():
            continue
        sink = dst_reg.create(dcfg, workspace_dir=ws)
        destinations_configured.append(
            {
                "name": dname,
                "type": dcfg.type,
                "target": sink.describe_target(),
            }
        )

    recent_jobs = db.list_jobs(limit=50)
    active_jobs = sum(1 for j in recent_jobs if j.status in (JobStatus.PENDING, JobStatus.RUNNING))
    failed_jobs = sum(1 for j in recent_jobs if j.status == JobStatus.FAILED)

    if not sources_ready:
        stage = "needs_source"
        rec_next = (
            "Configure a telemetry source and authentication via `sera source add <type>` "
            "(inspect options & auth modes with `sera source types`)."
        )
    elif not destinations_configured:
        stage = "needs_destination"
        rec_next = (
            "Configure a destination sink via `sera dest add <type>` "
            "(inspect options & auth modes with `sera dest types`)."
        )
    else:
        stage = "ready"
        rec_next = (
            "Workspace is fully configured and ready. Submit extraction jobs via MCP `collect` "
            "or CLI `sera collect`, and track progress via `jobs` / `status` or `sera watch --bell`."
        )

    return {
        "initialized": True,
        "stage": stage,
        "default_source": cfg.default_source,
        "sources_ready": sources_ready,
        "default_destination": cfg.default_destination,
        "destinations_configured": destinations_configured,
        "active_jobs": active_jobs,
        "failed_jobs": failed_jobs,
        "recommended_next_step": rec_next,
    }


def derive_action_recommendation(event: dict[str, Any], workspace_state: dict[str, Any]) -> str:
    """Produce a concrete remediation hint on failure or next-step recommendation on completion."""
    ev_type = event.get("event_type", "")
    status = event.get("status", "")
    err = event.get("error_message", "")
    lowered_err = err.lower()

    if status == "failed":
        if "socks" in lowered_err or "proxy" in lowered_err or "connection refused" in lowered_err:
            return (
                f"Proxy/network connection failed ({err}). Verify the proxy listener/SSH tunnel is active, "
                "confirm `proxy_url` scheme/port (e.g. `socks5h://127.0.0.1:1080`), and re-run the command."
            )
        if "aadsts" in lowered_err or "device code" in lowered_err or "client_secret" in lowered_err or "unauthorized" in lowered_err:
            return (
                f"Authentication failed ({err}). Verify `tenant_id`, `client_id`, credentials/consent, "
                "or Conditional Access egress IP, then re-run `sera source add ...`."
            )
        if "default credentials" in lowered_err or "adc" in lowered_err or "project" in lowered_err and ev_type.startswith("dest"):
            return (
                f"Destination credential/project check failed ({err}). Ensure GCP Application Default Credentials "
                "(`gcloud auth application-default login`) and project env vars (`GOOGLE_CLOUD_PROJECT`) are set."
            )
        if ev_type == "job.failed":
            job_id = event.get("details", {}).get("job_id", "<job_id>")
            return (
                f"Extraction job `{job_id}` failed ({err}). Diagnose the upstream error (expired session/token, "
                f"missing API permission, or network drop) and resume uncommitted slices with `resume(job_id='{job_id}')` "
                f"or `sera resume {job_id}`."
            )
        return f"Operation `{ev_type}` failed ({err}). Propose a targeted fix and guide the user to retry."

    if event.get("next_step_hint"):
        return str(event["next_step_hint"])
    return str(workspace_state.get("recommended_next_step", ""))


def get_recent_activity_snapshot(workspace_dir: Path, limit: int = 20) -> dict[str, Any]:
    """Return non-blocking recent activity events, `last_seq` cursor, and `workspace_state`."""
    ws = workspace_dir.resolve()
    db_path = sera_dir_for_workspace(ws) / "sera.sqlite"
    ws_state = inspect_workspace_readiness(ws)
    if not db_path.exists():
        return {
            "last_seq": 0,
            "events": [],
            "workspace_state": ws_state,
        }
    db = SeraDatabase(db_path)
    events = db.list_activity_events(limit=limit, actionable_only=False)
    for ev in events:
        ev["recommendation"] = derive_action_recommendation(ev, ws_state)
    return {
        "last_seq": db.latest_activity_seq(),
        "events": events,
        "workspace_state": ws_state,
    }


def wait_for_next_activity_event(
    workspace_dir: Path,
    *,
    since_seq: int | None = None,
    timeout_seconds: float = 600.0,
    poll_interval: float = 0.5,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Block until the next `completed` or `failed` event > `since_seq` arrives, then return structured JSON."""
    ws = workspace_dir.resolve()
    db_path = sera_dir_for_workspace(ws) / "sera.sqlite"

    if since_seq is not None:
        baseline_seq = since_seq
    elif db_path.exists():
        baseline_seq = SeraDatabase(db_path).latest_activity_seq()
    else:
        baseline_seq = 0

    deadline = time.monotonic() + max(0.1, timeout_seconds)
    interval = max(0.05, poll_interval)

    while True:
        if db_path.exists():
            db = SeraDatabase(db_path)
            new_events = db.list_activity_events(
                since_seq=baseline_seq,
                limit=10,
                actionable_only=True,
            )
            if new_events:
                ws_state = inspect_workspace_readiness(ws)
                for ev in new_events:
                    ev["recommendation"] = derive_action_recommendation(ev, ws_state)
                latest_ev = new_events[-1]
                return {
                    "matched": True,
                    "last_seq": int(latest_ev["seq"]),
                    "event": latest_ev,
                    "events": new_events,
                    "workspace_state": ws_state,
                }

        if time.monotonic() >= deadline:
            ws_state = inspect_workspace_readiness(ws)
            curr_seq = SeraDatabase(db_path).latest_activity_seq() if db_path.exists() else baseline_seq
            return {
                "matched": False,
                "reason": "timeout",
                "last_seq": curr_seq,
                "event": None,
                "events": [],
                "workspace_state": ws_state,
            }

        sleep_fn(interval)


def follow_activity_stream(
    workspace_dir: Path,
    *,
    since_seq: int | None = None,
    poll_interval: float = 0.5,
    max_events: int | None = None,
    stream: Any = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    """Continuously stream activity events as JSON lines (`--follow`)."""
    out = stream if stream is not None else sys.stdout
    ws = workspace_dir.resolve()
    db_path = sera_dir_for_workspace(ws) / "sera.sqlite"

    if since_seq is not None:
        cursor = since_seq
    elif db_path.exists():
        cursor = SeraDatabase(db_path).latest_activity_seq()
    else:
        cursor = 0

    emitted_count = 0
    interval = max(0.05, poll_interval)
    try:
        while True:
            if db_path.exists():
                db = SeraDatabase(db_path)
                batch = db.list_activity_events(since_seq=cursor, limit=50, actionable_only=False)
                if batch:
                    ws_state = inspect_workspace_readiness(ws)
                    for ev in batch:
                        cursor = int(ev["seq"])
                        ev["recommendation"] = derive_action_recommendation(ev, ws_state)
                        out.write(json.dumps({"event": ev, "workspace_state": ws_state}) + "\n")
                        out.flush()
                        emitted_count += 1
                        if max_events is not None and emitted_count >= max_events:
                            return
            sleep_fn(interval)
    except KeyboardInterrupt:
        return
