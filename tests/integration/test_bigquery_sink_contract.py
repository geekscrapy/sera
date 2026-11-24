"""Integration & contract diagnostic tests for Google Cloud BigQuery SDK & Batch Load API (ADC + env project)."""

from __future__ import annotations

import json
import os

import pytest
from google.cloud import bigquery

from sera.config import DestinationConfig
from sera.core.models import JobRecord, JobStatus, RawEventEnvelope, canonical_raw_json, sha256_hex, utc_now_iso
from sera.destinations.bigquery import BigQueryDestination, EVENTS_SCHEMA, JOBS_SCHEMA


def test_bigquery_sdk_schema_and_adc_option_specs_contract() -> None:
    """Validate BigQuery schema types and confirm zero project/credential options are required."""
    spec_names = {s.name: s.required for s in BigQueryDestination.option_specs()}
    assert "project_id" not in spec_names
    assert "credentials_file" not in spec_names
    assert all(req is False for req in spec_names.values())

    field_map = {f.name: (f.field_type, f.mode) for f in EVENTS_SCHEMA}
    assert field_map["event_id"] == ("STRING", "REQUIRED")
    assert field_map["job_id"] == ("STRING", "REQUIRED")
    assert field_map["event_timestamp"] == ("TIMESTAMP", "REQUIRED")
    assert field_map["raw_payload"] == ("STRING", "REQUIRED")
    assert field_map["event_data"] == ("JSON", "REQUIRED")

    jobs_map = {f.name: (f.field_type, f.mode) for f in JOBS_SCHEMA}
    assert jobs_map["events_uploaded"] == ("INT64", "REQUIRED")

    table = bigquery.Table("adc-proj.sera.events", schema=list(EVENTS_SCHEMA))
    table.time_partitioning = bigquery.TimePartitioning(
        type_=bigquery.TimePartitioningType.DAY,
        field="event_timestamp",
    )
    table.clustering_fields = ["source", "sub_source", "table_or_endpoint"]
    api_repr = table.to_api_repr()

    assert api_repr["timePartitioning"]["type"] == "DAY"
    assert api_repr["timePartitioning"]["field"] == "event_timestamp"
    assert api_repr["clustering"]["fields"] == ["source", "sub_source", "table_or_endpoint"]


@pytest.mark.skipif(
    os.environ.get("SERA_ITEST_ENABLE_BQ") != "1",
    reason="Set SERA_ITEST_ENABLE_BQ=1 (with ambient ADC + GCP project env vars) to run live BigQuery diagnostic",
)
async def test_live_bigquery_batch_load_roundtrip_contract() -> None:
    dataset_id = os.environ.get("SERA_ITEST_BQ_DATASET", "sera_itest_diag").strip()

    sink = BigQueryDestination(
        DestinationConfig(
            name="itest_bq",
            type="bigquery",
            options={"dataset_id": dataset_id},
        ),
    )
    payload = {"id": "itest-1", "diagnostic": True}
    raw_str, raw_hash = canonical_raw_json(payload)
    ev = RawEventEnvelope(
        event_id=sha256_hex(f"itest|{utc_now_iso()}"),
        job_id="job_itest_diag",
        ingested_at=utc_now_iso(),
        event_timestamp=utc_now_iso(),
        source="microsoft",
        sub_source="entra",
        table_or_endpoint="signIns",
        raw_sha256=raw_hash,
        raw_payload=raw_str,
        event_data=payload,
    )
    job = JobRecord(
        job_id="job_itest_diag",
        source="microsoft",
        sub_source="entra",
        table_or_endpoint="signIns",
        template="canonical",
        params={},
        profile="default",
        target_id="",
        destination_name="itest_bq",
        destination_target=sink.describe_target(),
        start_time=utc_now_iso(),
        end_time=utc_now_iso(),
        status=JobStatus.COMPLETED,
        events_fetched=1,
        events_skipped_uploaded=0,
        events_uploaded=1,
        slices_total=1,
        slices_completed=1,
        slices_split=0,
        created_at=utc_now_iso(),
        started_at=utc_now_iso(),
        completed_at=utc_now_iso(),
    )
    ndjson = (json.dumps(ev.to_destination_row()) + "\n").encode("utf-8")
    await sink.upload_ndjson_batch(ndjson, 1, job, "slice_diag")
    await sink.record_job_summary(job)
