"""Unit tests for the single `sera.sqlite` database and customizable destinations (`bigquery`, `jsonl`, `http`)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import httpx
import respx

from sera.config import DestinationConfig, NetworkConfig
from sera.core.db import SeraDatabase
from sera.core.models import JobRecord, JobStatus, RawEventEnvelope, canonical_raw_json, sha256_hex, utc_now_iso
from sera.destinations.bigquery import BigQueryDestination
from sera.destinations.http import HttpIngestDestination
from sera.destinations.jsonl import JsonlDirectoryDestination


def _sample_event(ev_id: str) -> RawEventEnvelope:
    payload = {"id": ev_id, "userPrincipalName": "analyst@contoso.com", "nested": {"x": 42}}
    raw_str, raw_hash = canonical_raw_json(payload)
    return RawEventEnvelope(
        event_id=sha256_hex(ev_id),
        job_id="job_test1",
        ingested_at="2026-11-23T12:00:00Z",
        event_timestamp="2026-11-23T11:55:00Z",
        source="microsoft",
        sub_source="entra",
        table_or_endpoint="signIns",
        raw_sha256=raw_hash,
        raw_payload=raw_str,
        event_data=payload,
    )


def _sample_job_record() -> JobRecord:
    return JobRecord(
        job_id="job_test1",
        source="microsoft",
        sub_source="entra",
        table_or_endpoint="signIns",
        template="all",
        params={},
        profile="default",
        target_id="",
        destination_name="custom_bq",
        destination_target="case-alpha.forensics.raw_events",
        start_time="2026-11-23T00:00:00Z",
        end_time="2026-11-24T00:00:00Z",
        status=JobStatus.COMPLETED,
        events_fetched=2,
        events_skipped_uploaded=0,
        events_uploaded=2,
        slices_total=1,
        slices_completed=1,
        slices_split=0,
        created_at=utc_now_iso(),
        started_at=utc_now_iso(),
        completed_at=utc_now_iso(),
    )


def test_single_sqlite_file_contains_all_tables(tmp_path: Path) -> None:
    db_file = tmp_path / "sera.sqlite"
    SeraDatabase(db_file)
    conn = sqlite3.connect(str(db_file))
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert {"jobs", "job_slices", "uploaded_events", "auth_profiles"}.issubset(tables)


class _FakeLoadJob:
    errors = None

    def result(self) -> None:
        return None


class _FakeBQClient:
    project = "adc-env-project"

    def __init__(self) -> None:
        self.created_datasets: list[Any] = []
        self.created_tables: list[Any] = []
        self.loads: list[tuple[str, bytes]] = []

    def create_dataset(self, ds: Any, exists_ok: bool = True) -> None:
        self.created_datasets.append(ds)

    def create_table(self, tbl: Any, exists_ok: bool = True) -> None:
        self.created_tables.append(tbl)

    def load_table_from_file(self, file_obj: Any, destination: str, job_config: Any = None, location: Any = None) -> _FakeLoadJob:
        self.loads.append((destination, file_obj.read()))
        return _FakeLoadJob()


async def test_customizable_bigquery_jsonl_and_http_destinations(tmp_path: Path) -> None:
    ev = _sample_event("e-100")
    ndjson_bytes = (json.dumps(ev.to_destination_row()) + "\n").encode("utf-8")
    job = _sample_job_record()

    # 1. BigQuery destination (auto-selects project & auth via ADC/env; customizable dataset/table/clustering)
    fake_bq = _FakeBQClient()
    bq_cfg = DestinationConfig(
        name="custom_bq",
        type="bigquery",
        options={
            "dataset_id": "forensics",
            "events_table": "raw_events",
            "jobs_table": "audit_runs",
            "location": "EU",
            "cluster_fields": ["source", "sub_source"],
        },
    )
    bq_sink = BigQueryDestination(bq_cfg, NetworkConfig(), client_factory=lambda: fake_bq)
    assert bq_sink.describe_target() == "adc-env-project.forensics.raw_events"
    await bq_sink.upload_ndjson_batch(ndjson_bytes, 1, job, "slice_1")
    await bq_sink.record_job_summary(job)
    assert len(fake_bq.created_tables) == 2
    assert fake_bq.loads[0][0] == "adc-env-project.forensics.raw_events"
    assert fake_bq.loads[1][0] == "adc-env-project.forensics.audit_runs"

    # 2. Customizable JSONL directory destination
    jsonl_dir = tmp_path / "mounted_case_share"
    j_cfg = DestinationConfig(name="share", type="jsonl", options={"output_dir": str(jsonl_dir)})
    j_sink = JsonlDirectoryDestination(j_cfg, NetworkConfig())
    await j_sink.upload_ndjson_batch(ndjson_bytes, 1, job, "slice_1")
    await j_sink.record_job_summary(job)
    written_files = list((jsonl_dir / "events").rglob("*.jsonl"))
    assert len(written_files) == 1
    assert "analyst@contoso.com" in written_files[0].read_text(encoding="utf-8")
    assert (jsonl_dir / "collection_jobs.jsonl").exists()

    # 3. Customizable HTTP/HEC destination
    with respx.mock(assert_all_called=True) as router:
        hec_route = router.post("https://siem.example.test/services/collector/event").mock(
            return_value=httpx.Response(200, json={"text": "Success", "code": 0})
        )
        h_cfg = DestinationConfig(
            name="hec",
            type="http",
            options={
                "url": "https://siem.example.test/services/collector/event",
                "format": "splunk_hec",
                "hec_token": "tok-123",
            },
        )
        h_sink = HttpIngestDestination(h_cfg, NetworkConfig())
        await h_sink.upload_ndjson_batch(ndjson_bytes, 1, job, "slice_1")
        assert hec_route.called
        sent_auth = hec_route.calls[0].request.headers["Authorization"]
        assert sent_auth == "Splunk tok-123"
