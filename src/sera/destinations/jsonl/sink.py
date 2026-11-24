"""Self-contained external NDJSON directory destination sink plugin."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from sera.config import DestinationConfig, NetworkConfig
from sera.core.models import JobRecord, utc_now_iso
from sera.destinations.base import BaseDestinationSink, SinkOptionSpec


class JsonlDirectoryDestination(BaseDestinationSink):
    """Writes verified NDJSON batches atomically to an external forensic mount or archive directory."""

    sink_type = "jsonl"
    required_packages = ()

    @classmethod
    def option_specs(cls) -> tuple[SinkOptionSpec, ...]:
        return (
            SinkOptionSpec("output_dir", "External target directory for NDJSON files", required=True),
            SinkOptionSpec("events_subdir", "Subdirectory for event batch files", required=False, default="events"),
            SinkOptionSpec(
                "jobs_filename",
                "JSONL filename for recorded job summaries",
                required=False,
                default="collection_jobs.jsonl",
            ),
        )

    def __init__(self, dest_config: DestinationConfig, network: NetworkConfig) -> None:
        super().__init__(dest_config, network)
        opts = self.apply_defaults(dest_config.options)
        raw_dir = str(opts.get("output_dir", "")).strip()
        if not raw_dir:
            raise ValueError(f"JSONL destination '{dest_config.name}' requires 'output_dir'")
        self.output_dir = Path(raw_dir).expanduser().resolve()
        self.events_subdir = str(opts.get("events_subdir", "events")).strip()
        self.jobs_filename = str(opts.get("jobs_filename", "collection_jobs.jsonl")).strip()

    def describe_target(self) -> str:
        return str(self.output_dir / self.events_subdir)

    def format_lookup_hint(self, job_id: str) -> str:
        return f"{self.describe_target()}/**/{job_id}_*.jsonl"

    def config_summary(self) -> dict[str, Any]:
        return {
            "name": self.dest_config.name,
            "type": self.sink_type,
            "output_dir": str(self.output_dir),
            "events_subdir": self.events_subdir,
            "jobs_filename": self.jobs_filename,
        }

    async def ensure_ready(self) -> None:
        (self.output_dir / self.events_subdir).mkdir(parents=True, exist_ok=True)

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
        target_dir = self.output_dir / self.events_subdir / job.source / job.sub_source
        target_dir.mkdir(parents=True, exist_ok=True)
        uid = uuid.uuid4().hex[:8]
        tmp_path = target_dir / f".{job.job_id}_{slice_id}_{uid}.tmp"
        final_path = target_dir / f"{job.job_id}_{slice_id}_{uid}.jsonl"
        tmp_path.write_bytes(ndjson_bytes)
        tmp_path.replace(final_path)

    async def record_job_summary(self, job: JobRecord) -> None:
        await self.ensure_ready()
        manifest_path = self.output_dir / self.jobs_filename
        record = {"recorded_at": utc_now_iso(), **job.to_summary_dict()}
        with manifest_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
