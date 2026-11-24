"""Unit tests for ephemeral RAM AES-256-GCM spooling, tamper detection, and slice-level restart resume."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

import pytest

from sera.config import DestinationConfig, NetworkConfig, WorkspaceConfig
from sera.core.db import SeraDatabase
from sera.core.engine import CollectionEngine
from sera.core.http_client import SeraHttpClient
from sera.core.models import (
    JobRecord,
    JobSpec,
    JobStatus,
    RawEventEnvelope,
    SliceResult,
    canonical_raw_json,
    format_utc_iso,
    sha256_hex,
    utc_now_iso,
)
from sera.core.spool import EphemeralSpoolManager, SpoolTamperError
from sera.destinations.base import BaseDestinationSink, SinkOptionSpec
from sera.sources.base import AuthModeSpec, BaseSourceConnector


def _make_event(idx: int, job_id: str = "job_1", ts: str = "2026-11-20T01:00:00Z") -> RawEventEnvelope:
    body = {"id": f"ev-{idx}", "createdDateTime": ts, "detail": f"full-fidelity-payload-{idx}"}
    raw_payload, raw_sha256 = canonical_raw_json(body)
    return RawEventEnvelope(
        event_id=sha256_hex(f"test|{idx}"),
        job_id=job_id,
        ingested_at=utc_now_iso(),
        event_timestamp=ts,
        source="microsoft",
        sub_source="entra",
        table_or_endpoint="signIns",
        raw_sha256=raw_sha256,
        raw_payload=raw_payload,
        event_data=body,
    )


def test_spool_encrypts_verifies_and_rejects_single_bit_tamper(tmp_path: Path) -> None:
    spool = EphemeralSpoolManager(tmp_path / "spool")
    events = [_make_event(1), _make_event(2)]
    handle = spool.write_batch("job_abc", "slice_01", 0, events)

    disk_bytes = handle.file_path.read_bytes()
    assert b"full-fidelity-payload" not in disk_bytes

    decrypted = spool.read_and_verify(handle)
    assert b"full-fidelity-payload-1" in decrypted
    assert b"full-fidelity-payload-2" in decrypted

    corrupted = bytearray(disk_bytes)
    corrupted[-5] ^= 0x01
    handle.file_path.write_bytes(bytes(corrupted))
    with pytest.raises(SpoolTamperError):
        spool.read_and_verify(handle)


def test_spool_cannot_decrypt_across_new_process_key_and_purges_orphans(tmp_path: Path) -> None:
    spool_dir = tmp_path / "spool"
    process_1 = EphemeralSpoolManager(spool_dir)
    handle = process_1.write_batch("job_old", "slice_01", 0, [_make_event(99)])
    assert handle.file_path.exists()

    process_2 = EphemeralSpoolManager(spool_dir)
    with pytest.raises(SpoolTamperError):
        process_2.read_and_verify(handle)

    removed = process_2.purge_orphans()
    assert removed == 1
    assert list(spool_dir.glob("*.enc")) == []


class _FlakySink(BaseDestinationSink):
    sink_type = "memory_flaky"

    @classmethod
    def option_specs(cls) -> tuple[SinkOptionSpec, ...]:
        return ()

    def __init__(self, fail_on_call: int | None = None) -> None:
        super().__init__(DestinationConfig(name="mem", type="memory_flaky"), NetworkConfig(max_retries=0))
        self.fail_on_call = fail_on_call
        self.calls = 0
        self.uploaded_lines: list[str] = []

    def describe_target(self) -> str:
        return "mem://events"

    def config_summary(self) -> dict:
        return {"type": "memory_flaky"}

    async def ensure_ready(self) -> None:
        return None

    async def upload_ndjson_batch(self, ndjson_bytes: bytes, event_count: int, job: JobRecord, slice_id: str) -> None:
        self.calls += 1
        if self.fail_on_call is not None and self.calls == self.fail_on_call:
            raise RuntimeError("Simulated crash mid-job on slice 2")
        self.uploaded_lines.extend(ndjson_bytes.decode("utf-8").strip().splitlines())

    async def record_job_summary(self, job: JobRecord) -> None:
        return None


class _TwoDayConnector(BaseSourceConnector):
    source_name = "microsoft"

    @classmethod
    def auth_modes(cls) -> dict[str, AuthModeSpec]:
        return {}

    def configure_auth(self, profile: str, mode: str, values: dict[str, str], on_message: Callable[[str], None] | None = None) -> dict[str, Any]:
        return {}

    def supported_sub_sources(self) -> dict:
        return {"entra": {}}

    def list_templates(self, sub_source: str = "") -> list[dict[str, Any]]:
        return []

    def default_chunk_duration(self, sub_source: str) -> timedelta:
        return timedelta(hours=24)

    def validate_job_spec(self, spec: JobSpec) -> None:
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
    ) -> SliceResult:
        day_num = slice_start.day
        ev_shared = _make_event(0, job_id=job_id, ts=format_utc_iso(slice_start))
        ev_unique = _make_event(day_num, job_id=job_id, ts=format_utc_iso(slice_start))
        return SliceResult(events=[ev_shared, ev_unique], truncated=False)


async def test_slice_level_resume_across_restart_keeps_uploaded_slices_and_skips_uploaded_events(tmp_path: Path) -> None:
    cfg = WorkspaceConfig(default_destination="mem", batch_size=10, network=NetworkConfig(max_retries=0))
    db = SeraDatabase(tmp_path / "sera.sqlite")
    conn = _TwoDayConnector(tmp_path, cfg)

    spool_proc1 = EphemeralSpoolManager(tmp_path / "spool")
    sink_proc1 = _FlakySink(fail_on_call=2)
    engine_1 = CollectionEngine(cfg, db, spool_proc1)

    spec = JobSpec(
        source="microsoft",
        sub_source="entra",
        table_or_endpoint="signIns",
        start_time="2026-11-01T00:00:00Z",
        end_time="2026-11-03T00:00:00Z",
    )
    job_id = engine_1.enqueue_job(spec, conn, sink_proc1)

    with pytest.raises(RuntimeError, match="Simulated crash mid-job"):
        await engine_1.execute_job(job_id, conn, sink_proc1)

    failed_view = db.get_job(job_id)
    assert failed_view.status == JobStatus.FAILED
    assert failed_view.slices_completed == 1
    assert failed_view.events_uploaded == 2

    (tmp_path / "spool" / f"{job_id}_orphan.enc").write_bytes(b"dead-process-ciphertext")

    spool_proc2 = EphemeralSpoolManager(tmp_path / "spool")
    assert spool_proc2.purge_orphans() == 1
    db.reset_interrupted_slices(job_id=job_id)

    sink_proc2 = _FlakySink(fail_on_call=None)
    engine_2 = CollectionEngine(cfg, db, spool_proc2)
    completed = await engine_2.execute_job(job_id, conn, sink_proc2)

    assert completed.status == JobStatus.COMPLETED
    assert completed.slices_completed == 2
    assert completed.events_uploaded == 3
    assert completed.events_skipped_uploaded == 1
    assert len(sink_proc2.uploaded_lines) == 1
