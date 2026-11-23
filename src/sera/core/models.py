"""Core data models and UTC timestamp helpers for SERA."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SliceStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SPLIT = "split"
    FAILED = "failed"


def utc_now_iso() -> str:
    """Return current UTC time in canonical ISO-8601 Z format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_utc_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp string and normalize to timezone-aware UTC."""
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Timestamp string cannot be empty")
    if cleaned.endswith("Z") or cleaned.endswith("z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_utc_iso(dt: datetime) -> str:
    """Format a datetime as canonical ISO-8601 UTC with Z suffix."""
    utc_dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    if utc_dt.microsecond:
        return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_raw_json(event_dict: dict[str, Any]) -> tuple[str, str]:
    """Serialize raw wire JSON object deterministically and return (raw_payload, sha256_hex)."""
    raw_payload = json.dumps(event_dict, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
    raw_sha256 = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()
    return raw_payload, raw_sha256


def sha256_hex(text: str) -> str:
    """Compute SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class JobSpec:
    """Validated collection job specification shared by CLI and MCP."""

    source: str
    sub_source: str
    table_or_endpoint: str
    start_time: str
    end_time: str
    template: str = "all"
    params: dict[str, Any] = field(default_factory=dict)
    profile: str = "default"
    target_id: str = ""
    destination: str = ""
    initial_chunk_hours: float | None = None

    def normalized_window(self) -> tuple[datetime, datetime]:
        start_dt = parse_utc_iso(self.start_time)
        end_dt = parse_utc_iso(self.end_time)
        if end_dt <= start_dt:
            raise ValueError(f"end_time ({self.end_time}) must be strictly after start_time ({self.start_time})")
        return start_dt, end_dt


@dataclass(frozen=True)
class RawEventEnvelope:
    """Canonical forensic envelope preserving 100% of the upstream wire event."""

    event_id: str
    job_id: str
    ingested_at: str
    event_timestamp: str
    source: str
    sub_source: str
    table_or_endpoint: str
    raw_sha256: str
    raw_payload: str
    event_data: dict[str, Any]

    def to_destination_row(self) -> dict[str, Any]:
        """Convert to NDJSON-serializable destination record."""
        return {
            "event_id": self.event_id,
            "job_id": self.job_id,
            "ingested_at": self.ingested_at,
            "event_timestamp": self.event_timestamp,
            "source": self.source,
            "sub_source": self.sub_source,
            "table_or_endpoint": self.table_or_endpoint,
            "raw_sha256": self.raw_sha256,
            "raw_payload": self.raw_payload,
            # BigQuery JSON column accepts either JSON object or JSON string in NEWLINE_DELIMITED_JSON;
            # passing the JSON object directly works seamlessly in BigQuery JSON columns, JSONL sinks, and HTTP sinks.
            "event_data": self.event_data,
        }


@dataclass
class SliceResult:
    """Result returned by a source connector for a single [start_time, end_time) slice."""

    events: list[RawEventEnvelope]
    truncated: bool = False
    truncation_reason: str = ""


@dataclass
class SliceRecord:
    """Database row representation for an adaptive interval slice."""

    slice_id: str
    job_id: str
    parent_slice_id: str | None
    start_time: str
    end_time: str
    status: SliceStatus
    events_fetched: int = 0
    events_uploaded: int = 0
    attempt_count: int = 0
    last_error: str = ""


@dataclass
class JobRecord:
    """Database row representation for a collection job."""

    job_id: str
    source: str
    sub_source: str
    table_or_endpoint: str
    template: str
    params: dict[str, Any]
    profile: str
    target_id: str
    destination_name: str
    destination_target: str
    start_time: str
    end_time: str
    status: JobStatus
    events_fetched: int
    events_skipped_uploaded: int
    events_uploaded: int
    slices_total: int
    slices_completed: int
    slices_split: int
    created_at: str
    started_at: str | None
    completed_at: str | None
    error_message: str = ""

    def to_summary_dict(self) -> dict[str, Any]:
        duration_seconds: float | None = None
        if self.started_at and self.completed_at:
            try:
                duration_seconds = round(
                    (parse_utc_iso(self.completed_at) - parse_utc_iso(self.started_at)).total_seconds(),
                    3,
                )
            except ValueError:
                duration_seconds = None
        return {
            "job_id": self.job_id,
            "status": self.status.value,
            "source": self.source,
            "sub_source": self.sub_source,
            "table_or_endpoint": self.table_or_endpoint,
            "template": self.template,
            "params": self.params,
            "profile": self.profile,
            "target_id": self.target_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "destination_name": self.destination_name,
            "destination_target": self.destination_target,
            "events_fetched": self.events_fetched,
            "events_already_uploaded_skipped": self.events_skipped_uploaded,
            "events_uploaded": self.events_uploaded,
            "slices": {
                "total_leaves_and_splits": self.slices_total,
                "completed": self.slices_completed,
                "split": self.slices_split,
            },
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": duration_seconds,
            "error_message": self.error_message,
        }
