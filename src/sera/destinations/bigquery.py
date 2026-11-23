"""Customizable Google BigQuery destination sink using atomic Batch Load jobs."""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path
from typing import Any, Callable

from google.cloud import bigquery
from google.oauth2 import service_account

from sera.config import DestinationConfig, NetworkConfig
from sera.core.models import JobRecord, utc_now_iso
from sera.destinations.base import BaseDestinationSink


EVENTS_SCHEMA: tuple[bigquery.SchemaField, ...] = (
    bigquery.SchemaField("event_id", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("job_id", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("ingested_at", "TIMESTAMP", mode="REQUIRED"),
    bigquery.SchemaField("event_timestamp", "TIMESTAMP", mode="REQUIRED"),
    bigquery.SchemaField("source", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("sub_source", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("table_or_endpoint", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("raw_sha256", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("raw_payload", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("event_data", "JSON", mode="REQUIRED"),
)

JOBS_SCHEMA: tuple[bigquery.SchemaField, ...] = (
    bigquery.SchemaField("job_id", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("recorded_at", "TIMESTAMP", mode="REQUIRED"),
    bigquery.SchemaField("status", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("source", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("sub_source", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("table_or_endpoint", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("template", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("params_json", "STRING", mode="REQUIRED"),
    bigquery.SchemaField("start_time", "TIMESTAMP", mode="REQUIRED"),
    bigquery.SchemaField("end_time", "TIMESTAMP", mode="REQUIRED"),
    bigquery.SchemaField("events_fetched", "INT64", mode="REQUIRED"),
    bigquery.SchemaField("events_skipped_uploaded", "INT64", mode="REQUIRED"),
    bigquery.SchemaField("events_uploaded", "INT64", mode="REQUIRED"),
    bigquery.SchemaField("slices_total", "INT64", mode="REQUIRED"),
    bigquery.SchemaField("slices_completed", "INT64", mode="REQUIRED"),
    bigquery.SchemaField("slices_split", "INT64", mode="REQUIRED"),
    bigquery.SchemaField("started_at", "TIMESTAMP", mode="NULLABLE"),
    bigquery.SchemaField("completed_at", "TIMESTAMP", mode="NULLABLE"),
    bigquery.SchemaField("error_message", "STRING", mode="NULLABLE"),
)


class BigQueryDestination(BaseDestinationSink):
    """Customizable BigQuery destination (`project_id`, `dataset_id`, table names, clustering, location)."""

    sink_type = "bigquery"

    def __init__(
        self,
        dest_config: DestinationConfig,
        network: NetworkConfig,
        client_factory: Callable[[], bigquery.Client] | None = None,
    ) -> None:
        super().__init__(dest_config, network)
        opts = dest_config.options
        self.project_id = str(opts.get("project_id", "")).strip()
        self.dataset_id = str(opts.get("dataset_id", "sera_raw")).strip()
        self.events_table = str(opts.get("events_table", "events")).strip()
        self.jobs_table = str(opts.get("jobs_table", "collection_jobs")).strip()
        self.location = str(opts.get("location", "US")).strip()
        self.partition_field = str(opts.get("partition_field", "event_timestamp")).strip()
        raw_clusters = opts.get("cluster_fields", ["source", "sub_source", "table_or_endpoint"])
        self.cluster_fields = [str(c) for c in raw_clusters] if isinstance(raw_clusters, list) else []
        self.credentials_file = str(opts.get("credentials_file", "")).strip()
        self._client_factory = client_factory
        self._client: bigquery.Client | None = None
        self._ready = False

        if not self.project_id:
            raise ValueError(
                f"BigQuery destination '{dest_config.name}' requires a non-empty 'project_id' in .sera/config.toml"
            )

    def _get_client(self) -> bigquery.Client:
        if self._client is not None:
            return self._client
        if self._client_factory is not None:
            self._client = self._client_factory()
            return self._client
        creds = None
        if self.credentials_file:
            cred_path = Path(self.credentials_file).expanduser()
            creds = service_account.Credentials.from_service_account_file(str(cred_path))
        self._client = bigquery.Client(
            project=self.project_id,
            credentials=creds,
            location=self.location or None,
        )
        return self._client

    @property
    def events_table_fqn(self) -> str:
        return f"{self.project_id}.{self.dataset_id}.{self.events_table}"

    @property
    def jobs_table_fqn(self) -> str:
        return f"{self.project_id}.{self.dataset_id}.{self.jobs_table}"

    def describe_target(self) -> str:
        return self.events_table_fqn

    def config_summary(self) -> dict[str, Any]:
        return {
            "name": self.dest_config.name,
            "type": self.sink_type,
            "project_id": self.project_id,
            "dataset_id": self.dataset_id,
            "events_table": self.events_table,
            "jobs_table": self.jobs_table,
            "location": self.location,
            "partition_field": self.partition_field,
            "cluster_fields": self.cluster_fields,
            "uses_credentials_file": bool(self.credentials_file),
            "lookup_example": f"SELECT * FROM `{self.events_table_fqn}` WHERE job_id = '<job_id>'",
        }

    def _ensure_ready_sync(self) -> None:
        if self._ready:
            return
        client = self._get_client()
        dataset_ref = bigquery.Dataset(f"{self.project_id}.{self.dataset_id}")
        if self.location:
            dataset_ref.location = self.location
        client.create_dataset(dataset_ref, exists_ok=True)

        ev_table = bigquery.Table(self.events_table_fqn, schema=list(EVENTS_SCHEMA))
        if self.partition_field:
            ev_table.time_partitioning = bigquery.TimePartitioning(
                type_=bigquery.TimePartitioningType.DAY,
                field=self.partition_field,
            )
        if self.cluster_fields:
            ev_table.clustering_fields = self.cluster_fields[:4]
        client.create_table(ev_table, exists_ok=True)

        jb_table = bigquery.Table(self.jobs_table_fqn, schema=list(JOBS_SCHEMA))
        client.create_table(jb_table, exists_ok=True)
        self._ready = True

    async def ensure_ready(self) -> None:
        await asyncio.to_thread(self._ensure_ready_sync)

    def _upload_sync(self, ndjson_bytes: bytes) -> None:
        client = self._get_client()
        job_cfg = bigquery.LoadJobConfig(
            schema=list(EVENTS_SCHEMA),
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
        )
        load_job = client.load_table_from_file(
            io.BytesIO(ndjson_bytes),
            self.events_table_fqn,
            job_config=job_cfg,
            location=self.location or None,
        )
        load_job.result()
        if load_job.errors:
            raise RuntimeError(f"BigQuery LoadJob reported errors: {load_job.errors}")

    async def upload_ndjson_batch(
        self,
        ndjson_bytes: bytes,
        event_count: int,
        job: JobRecord,
        slice_id: str,
    ) -> None:
        if not ndjson_bytes or event_count <= 0:
            return
        await self.ensure_ready()
        await asyncio.to_thread(self._upload_sync, ndjson_bytes)

    def _record_job_sync(self, job: JobRecord) -> None:
        client = self._get_client()
        row = {
            "job_id": job.job_id,
            "recorded_at": utc_now_iso(),
            "status": job.status.value,
            "source": job.source,
            "sub_source": job.sub_source,
            "table_or_endpoint": job.table_or_endpoint,
            "template": job.template,
            "params_json": json.dumps(job.params, sort_keys=True),
            "start_time": job.start_time,
            "end_time": job.end_time,
            "events_fetched": job.events_fetched,
            "events_skipped_uploaded": job.events_skipped_uploaded,
            "events_uploaded": job.events_uploaded,
            "slices_total": job.slices_total,
            "slices_completed": job.slices_completed,
            "slices_split": job.slices_split,
            "started_at": job.started_at,
            "completed_at": job.completed_at,
            "error_message": job.error_message or None,
        }
        payload = (json.dumps(row, separators=(",", ":")) + "\n").encode("utf-8")
        job_cfg = bigquery.LoadJobConfig(
            schema=list(JOBS_SCHEMA),
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
        )
        load_job = client.load_table_from_file(
            io.BytesIO(payload),
            self.jobs_table_fqn,
            job_config=job_cfg,
            location=self.location or None,
        )
        load_job.result()

    async def record_job_summary(self, job: JobRecord) -> None:
        await self.ensure_ready()
        await asyncio.to_thread(self._record_job_sync, job)
