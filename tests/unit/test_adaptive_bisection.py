"""Unit tests verifying adaptive per-interval tree bisection."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from sera.config import DestinationConfig, NetworkConfig, WorkspaceConfig
from sera.core.db import SeraDatabase
from sera.core.engine import CollectionEngine
from sera.core.http_client import SeraHttpClient
from sera.core.models import JobSpec, RawEventEnvelope, SliceResult, canonical_raw_json, format_utc_iso, sha256_hex, utc_now_iso
from sera.core.spool import EphemeralSpoolManager
from sera.core.templates import TemplateRegistry
from sera.destinations.jsonl import JsonlDirectoryDestination
from sera.sources.base import BaseSourceConnector


class _TuesdaySpikeConnector(BaseSourceConnector):
    """Simulates a 7-day pull where ONLY Tuesday (2026-11-17) exceeds row caps unless split <= 6 hours."""

    source_name = "microsoft"

    def __init__(self, workspace_dir: Path, config: WorkspaceConfig) -> None:
        super().__init__(workspace_dir, config)
        self.calls: list[tuple[str, str, float]] = []

    def supported_sub_sources(self) -> dict:
        return {"log_analytics": {}}

    def default_chunk_duration(self, sub_source: str) -> timedelta:
        return timedelta(hours=24)

    def validate_job_spec(self, spec: JobSpec, templates: TemplateRegistry) -> None:
        return None

    def check_auth_status(self, profile: str = "default") -> dict:
        return {"configured": True}

    async def fetch_slice(
        self,
        job_id: str,
        spec: JobSpec,
        slice_start: datetime,
        slice_end: datetime,
        http: SeraHttpClient,
        templates: TemplateRegistry,
    ) -> SliceResult:
        hours = (slice_end - slice_start).total_seconds() / 3600.0
        self.calls.append((format_utc_iso(slice_start), format_utc_iso(slice_end), hours))

        # Tuesday 2026-11-17 between 12:00 and 24:00 is high-volume (> 6h slices truncate!)
        tue_noon = datetime(2026, 11, 17, 12, 0, tzinfo=slice_start.tzinfo)
        wed_midnight = datetime(2026, 11, 18, 0, 0, tzinfo=slice_start.tzinfo)
        overlaps_spike = slice_start < wed_midnight and slice_end > tue_noon
        if overlaps_spike and hours > 6.0:
            return SliceResult(events=[], truncated=True, truncation_reason="PartialError: >500k rows")

        body = {"TimeGenerated": format_utc_iso(slice_start), "window_hours": hours}
        raw_payload, raw_sha256 = canonical_raw_json(body)
        ev = RawEventEnvelope(
            event_id=sha256_hex(f"slice|{format_utc_iso(slice_start)}|{format_utc_iso(slice_end)}"),
            job_id=job_id,
            ingested_at=utc_now_iso(),
            event_timestamp=format_utc_iso(slice_start),
            source="microsoft",
            sub_source="log_analytics",
            table_or_endpoint="SigninLogs",
            raw_sha256=raw_sha256,
            raw_payload=raw_payload,
            event_data=body,
        )
        return SliceResult(events=[ev], truncated=False)


async def test_only_high_volume_day_splits_while_other_six_days_stay_24h(tmp_path: Path) -> None:
    out_dir = tmp_path / "external_sink"
    dest_cfg = DestinationConfig(name="local_jsonl", type="jsonl", options={"output_dir": str(out_dir)})
    cfg = WorkspaceConfig(default_destination="local_jsonl", destinations={"local_jsonl": dest_cfg})
    db = SeraDatabase(tmp_path / "ws" / ".sera" / "sera.sqlite")
    spool = EphemeralSpoolManager(tmp_path / "ws" / ".sera" / "spool")
    templates = TemplateRegistry()
    conn = _TuesdaySpikeConnector(tmp_path / "ws", cfg)
    sink = JsonlDirectoryDestination(dest_cfg, cfg.network)

    engine = CollectionEngine(cfg, db, spool, templates)
    spec = JobSpec(
        source="microsoft",
        sub_source="log_analytics",
        table_or_endpoint="SigninLogs",
        start_time="2026-11-16T00:00:00Z",  # Monday
        end_time="2026-11-23T00:00:00Z",    # Next Monday (7 days)
    )
    job_id = engine.enqueue_job(spec, conn, sink)
    final = await engine.execute_job(job_id, conn, sink)

    # Verify the 6 quiet days ran as single 24.0h slices (zero unnecessary chunking!)
    # Tuesday (24h) truncated -> split into [00:00-12:00] (12h, quiet -> succeeded!) and [12:00-24:00] (12h, spike -> split into two 6h slices -> both succeeded!)
    assert final.slices_split == 2
    assert final.slices_completed == 6 + 1 + 2  # 6 full days + Tue morning (12h) + 2 Tue afternoon (6h) = 9 leaf slices!
    assert final.events_uploaded == 9

    twenty_four_hour_calls = [c for c in conn.calls if c[2] == 24.0]
    assert len(twenty_four_hour_calls) == 7  # Initial 7 days attempted at 24h; 6 succeeded immediately!
