"""Single SQLite database (`<workspace>/.sera/sera.sqlite`) managing jobs, slices, uploaded_events, and auth_profiles."""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from sera.core.models import (
    JobRecord,
    JobSpec,
    JobStatus,
    RawEventEnvelope,
    SliceRecord,
    SliceStatus,
    format_utc_iso,
    utc_now_iso,
)

SQLITE_CHUNK_LIMIT = 800


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    sub_source TEXT NOT NULL,
    table_or_endpoint TEXT NOT NULL,
    template TEXT NOT NULL,
    params_json TEXT NOT NULL,
    profile TEXT NOT NULL,
    target_id TEXT NOT NULL,
    destination_name TEXT NOT NULL,
    destination_target TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    status TEXT NOT NULL,
    events_fetched INTEGER NOT NULL DEFAULT 0,
    events_skipped_uploaded INTEGER NOT NULL DEFAULT 0,
    events_uploaded INTEGER NOT NULL DEFAULT 0,
    slices_total INTEGER NOT NULL DEFAULT 0,
    slices_completed INTEGER NOT NULL DEFAULT 0,
    slices_split INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    error_message TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS job_slices (
    slice_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
    parent_slice_id TEXT,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    status TEXT NOT NULL,
    events_fetched INTEGER NOT NULL DEFAULT 0,
    events_uploaded INTEGER NOT NULL DEFAULT 0,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_job_slices_job_status
    ON job_slices(job_id, status, start_time);

CREATE TABLE IF NOT EXISTS uploaded_events (
    event_id TEXT NOT NULL,
    destination_name TEXT NOT NULL,
    job_id TEXT NOT NULL,
    source TEXT NOT NULL,
    sub_source TEXT NOT NULL,
    table_or_endpoint TEXT NOT NULL,
    event_timestamp TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    PRIMARY KEY (destination_name, event_id)
);

CREATE INDEX IF NOT EXISTS idx_uploaded_events_job
    ON uploaded_events(job_id);

CREATE TABLE IF NOT EXISTS auth_profiles (
    source TEXT NOT NULL,
    profile TEXT NOT NULL,
    auth_mode TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT '',
    client_id TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (source, profile)
);
"""


class SeraDatabase:
    """Thread/process-safe WAL SQLite store for all SERA workspace metadata."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA_SQL)

    def upsert_auth_profile(
        self,
        source: str,
        profile: str,
        auth_mode: str,
        tenant_id: str = "",
        client_id: str = "",
    ) -> None:
        now = utc_now_iso()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO auth_profiles (source, profile, auth_mode, tenant_id, client_id, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(source, profile) DO UPDATE SET
                    auth_mode = excluded.auth_mode,
                    tenant_id = excluded.tenant_id,
                    client_id = excluded.client_id,
                    updated_at = excluded.updated_at
                """,
                (source, profile, auth_mode, tenant_id, client_id, now),
            )

    def list_auth_profiles(self, source: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as conn:
            if source:
                rows = conn.execute(
                    "SELECT * FROM auth_profiles WHERE source = ? ORDER BY profile",
                    (source,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM auth_profiles ORDER BY source, profile"
                ).fetchall()
        return [dict(r) for r in rows]

    def create_job(
        self,
        spec: JobSpec,
        destination_name: str,
        destination_target: str,
        initial_intervals: list[tuple[datetime, datetime]],
    ) -> str:
        job_id = f"job_{uuid.uuid4().hex[:16]}"
        now = utc_now_iso()
        start_dt, end_dt = spec.normalized_window()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO jobs (
                    job_id, source, sub_source, table_or_endpoint, template, params_json,
                    profile, target_id, destination_name, destination_target,
                    start_time, end_time, status, slices_total, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    spec.source,
                    spec.sub_source,
                    spec.table_or_endpoint,
                    spec.template,
                    json.dumps(spec.params, sort_keys=True),
                    spec.profile,
                    spec.target_id,
                    destination_name,
                    destination_target,
                    format_utc_iso(start_dt),
                    format_utc_iso(end_dt),
                    JobStatus.PENDING.value,
                    len(initial_intervals),
                    now,
                ),
            )
            for idx, (s_dt, e_dt) in enumerate(initial_intervals):
                slice_id = f"{job_id}_s{idx:04d}_{uuid.uuid4().hex[:6]}"
                conn.execute(
                    """
                    INSERT INTO job_slices (
                        slice_id, job_id, parent_slice_id, start_time, end_time,
                        status, created_at, updated_at
                    ) VALUES (?, ?, NULL, ?, ?, ?, ?, ?)
                    """,
                    (
                        slice_id,
                        job_id,
                        format_utc_iso(s_dt),
                        format_utc_iso(e_dt),
                        SliceStatus.PENDING.value,
                        now,
                        now,
                    ),
                )
        return job_id

    def mark_job_running(self, job_id: str) -> None:
        now = utc_now_iso()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = ?,
                    started_at = COALESCE(started_at, ?),
                    completed_at = NULL,
                    error_message = ''
                WHERE job_id = ?
                """,
                (JobStatus.RUNNING.value, now, job_id),
            )

    def reset_interrupted_slices(self, job_id: str | None = None) -> int:
        """Reset any `in_progress` or `failed` slices back to `pending` for resume/startup recovery."""
        now = utc_now_iso()
        with self.connect() as conn:
            if job_id:
                cur = conn.execute(
                    """
                    UPDATE job_slices
                    SET status = ?, updated_at = ?
                    WHERE job_id = ? AND status IN (?, ?)
                    """,
                    (
                        SliceStatus.PENDING.value,
                        now,
                        job_id,
                        SliceStatus.IN_PROGRESS.value,
                        SliceStatus.FAILED.value,
                    ),
                )
            else:
                cur = conn.execute(
                    """
                    UPDATE job_slices
                    SET status = ?, updated_at = ?
                    WHERE status = ?
                    """,
                    (SliceStatus.PENDING.value, now, SliceStatus.IN_PROGRESS.value),
                )
            return cur.rowcount

    def claim_next_pending_slice(self, job_id: str) -> SliceRecord | None:
        now = utc_now_iso()
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM job_slices
                WHERE job_id = ? AND status = ?
                ORDER BY start_time ASC, created_at ASC
                LIMIT 1
                """,
                (job_id, SliceStatus.PENDING.value),
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                """
                UPDATE job_slices
                SET status = ?, attempt_count = attempt_count + 1, updated_at = ?
                WHERE slice_id = ?
                """,
                (SliceStatus.IN_PROGRESS.value, now, row["slice_id"]),
            )
            return self._row_to_slice(row, status_override=SliceStatus.IN_PROGRESS, bump_attempt=True)

    def split_slice(
        self,
        job_id: str,
        parent_slice_id: str,
        start_iso: str,
        mid_iso: str,
        end_iso: str,
        reason: str = "",
    ) -> tuple[str, str]:
        """Mark parent slice as `split` and insert two child intervals `[start, mid)` and `[mid, end)`."""
        now = utc_now_iso()
        left_id = f"{job_id}_sp_{uuid.uuid4().hex[:8]}"
        right_id = f"{job_id}_sp_{uuid.uuid4().hex[:8]}"
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE job_slices
                SET status = ?, last_error = ?, updated_at = ?
                WHERE slice_id = ?
                """,
                (SliceStatus.SPLIT.value, reason, now, parent_slice_id),
            )
            for sid, s_iso, e_iso in ((left_id, start_iso, mid_iso), (right_id, mid_iso, end_iso)):
                conn.execute(
                    """
                    INSERT INTO job_slices (
                        slice_id, job_id, parent_slice_id, start_time, end_time,
                        status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (sid, job_id, parent_slice_id, s_iso, e_iso, SliceStatus.PENDING.value, now, now),
                )
            conn.execute(
                """
                UPDATE jobs
                SET slices_total = slices_total + 2,
                    slices_split = slices_split + 1
                WHERE job_id = ?
                """,
                (job_id,),
            )
        return left_id, right_id

    def filter_unuploaded_events(
        self,
        events: list[RawEventEnvelope],
        destination_name: str,
    ) -> tuple[list[RawEventEnvelope], int]:
        """Filter out events already recorded in `uploaded_events` (or duplicated within this batch)."""
        if not events:
            return [], 0

        unique_in_batch: list[RawEventEnvelope] = []
        seen_ids: set[str] = set()
        skipped = 0
        for ev in events:
            if ev.event_id in seen_ids:
                skipped += 1
            else:
                seen_ids.add(ev.event_id)
                unique_in_batch.append(ev)

        already_in_db: set[str] = set()
        all_ids = [ev.event_id for ev in unique_in_batch]
        with self.connect() as conn:
            for i in range(0, len(all_ids), SQLITE_CHUNK_LIMIT):
                chunk = all_ids[i : i + SQLITE_CHUNK_LIMIT]
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"""
                    SELECT event_id FROM uploaded_events
                    WHERE destination_name = ? AND event_id IN ({placeholders})
                    """,
                    [destination_name, *chunk],
                ).fetchall()
                already_in_db.update(r["event_id"] for r in rows)

        to_upload: list[RawEventEnvelope] = []
        for ev in unique_in_batch:
            if ev.event_id in already_in_db:
                skipped += 1
            else:
                to_upload.append(ev)
        return to_upload, skipped

    def record_fetched_and_skipped(
        self,
        job_id: str,
        slice_id: str,
        fetched_count: int,
        skipped_count: int,
    ) -> None:
        now = utc_now_iso()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE job_slices
                SET events_fetched = events_fetched + ?, updated_at = ?
                WHERE slice_id = ?
                """,
                (fetched_count, now, slice_id),
            )
            conn.execute(
                """
                UPDATE jobs
                SET events_fetched = events_fetched + ?,
                    events_skipped_uploaded = events_skipped_uploaded + ?
                WHERE job_id = ?
                """,
                (fetched_count, skipped_count, job_id),
            )

    def commit_uploaded_batch(
        self,
        job_id: str,
        slice_id: str,
        destination_name: str,
        uploaded_events: list[RawEventEnvelope],
    ) -> int:
        """Atomically record uploaded event_ids in `uploaded_events` AFTER destination upload succeeds."""
        if not uploaded_events:
            return 0
        now = utc_now_iso()
        with self.connect() as conn:
            inserted = 0
            for ev in uploaded_events:
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO uploaded_events (
                        event_id, destination_name, job_id, source, sub_source,
                        table_or_endpoint, event_timestamp, raw_sha256, uploaded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ev.event_id,
                        destination_name,
                        job_id,
                        ev.source,
                        ev.sub_source,
                        ev.table_or_endpoint,
                        ev.event_timestamp,
                        ev.raw_sha256,
                        now,
                    ),
                )
                inserted += cur.rowcount

            conn.execute(
                """
                UPDATE job_slices
                SET events_uploaded = events_uploaded + ?, updated_at = ?
                WHERE slice_id = ?
                """,
                (inserted, now, slice_id),
            )
            conn.execute(
                """
                UPDATE jobs
                SET events_uploaded = events_uploaded + ?
                WHERE job_id = ?
                """,
                (inserted, job_id),
            )
            return inserted

    def mark_slice_completed(self, job_id: str, slice_id: str) -> None:
        now = utc_now_iso()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE job_slices
                SET status = ?, last_error = '', updated_at = ?
                WHERE slice_id = ?
                """,
                (SliceStatus.COMPLETED.value, now, slice_id),
            )
            conn.execute(
                """
                UPDATE jobs
                SET slices_completed = slices_completed + 1
                WHERE job_id = ?
                """,
                (job_id,),
            )

    def mark_slice_failed(self, job_id: str, slice_id: str, error_message: str) -> None:
        now = utc_now_iso()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE job_slices
                SET status = ?, last_error = ?, updated_at = ?
                WHERE slice_id = ?
                """,
                (SliceStatus.FAILED.value, error_message, now, slice_id),
            )
            conn.execute(
                """
                UPDATE jobs
                SET status = ?, completed_at = ?, error_message = ?
                WHERE job_id = ?
                """,
                (JobStatus.FAILED.value, now, error_message, job_id),
            )

    def mark_job_completed(self, job_id: str) -> None:
        now = utc_now_iso()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = ?, completed_at = ?, error_message = ''
                WHERE job_id = ?
                """,
                (JobStatus.COMPLETED.value, now, job_id),
            )

    def mark_job_failed(self, job_id: str, error_message: str) -> None:
        now = utc_now_iso()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE jobs
                SET status = ?, completed_at = ?, error_message = ?
                WHERE job_id = ?
                """,
                (JobStatus.FAILED.value, now, error_message, job_id),
            )

    def get_job(self, job_id: str) -> JobRecord:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(f"Job '{job_id}' not found in sera.sqlite")
        return self._row_to_job(row)

    def list_jobs(self, limit: int = 50) -> list[JobRecord]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_job(r) for r in rows]

    def list_slices(self, job_id: str) -> list[SliceRecord]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM job_slices WHERE job_id = ? ORDER BY start_time ASC, created_at ASC",
                (job_id,),
            ).fetchall()
        return [self._row_to_slice(r) for r in rows]

    def count_uploaded_events(self, destination_name: str | None = None) -> int:
        with self.connect() as conn:
            if destination_name:
                row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM uploaded_events WHERE destination_name = ?",
                    (destination_name,),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) AS cnt FROM uploaded_events").fetchone()
        return int(row["cnt"]) if row else 0

    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> JobRecord:
        return JobRecord(
            job_id=row["job_id"],
            source=row["source"],
            sub_source=row["sub_source"],
            table_or_endpoint=row["table_or_endpoint"],
            template=row["template"],
            params=json.loads(row["params_json"] or "{}"),
            profile=row["profile"],
            target_id=row["target_id"],
            destination_name=row["destination_name"],
            destination_target=row["destination_target"],
            start_time=row["start_time"],
            end_time=row["end_time"],
            status=JobStatus(row["status"]),
            events_fetched=int(row["events_fetched"]),
            events_skipped_uploaded=int(row["events_skipped_uploaded"]),
            events_uploaded=int(row["events_uploaded"]),
            slices_total=int(row["slices_total"]),
            slices_completed=int(row["slices_completed"]),
            slices_split=int(row["slices_split"]),
            created_at=row["created_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            error_message=row["error_message"] or "",
        )

    @staticmethod
    def _row_to_slice(
        row: sqlite3.Row,
        status_override: SliceStatus | None = None,
        bump_attempt: bool = False,
    ) -> SliceRecord:
        return SliceRecord(
            slice_id=row["slice_id"],
            job_id=row["job_id"],
            parent_slice_id=row["parent_slice_id"],
            start_time=row["start_time"],
            end_time=row["end_time"],
            status=status_override or SliceStatus(row["status"]),
            events_fetched=int(row["events_fetched"]),
            events_uploaded=int(row["events_uploaded"]),
            attempt_count=int(row["attempt_count"]) + (1 if bump_attempt else 0),
            last_error=row["last_error"] or "",
        )
