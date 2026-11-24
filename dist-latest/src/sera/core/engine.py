"""Vendor- and sink-agnostic adaptive collection engine with ephemeral AES-GCM spooling."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Awaitable, Callable

from sera.config import WorkspaceConfig
from sera.core.db import SeraDatabase
from sera.core.http_client import SeraHttpClient
from sera.core.models import JobRecord, JobSpec, format_utc_iso, parse_utc_iso
from sera.core.spool import EphemeralSpoolManager, SpoolBatchHandle, SpoolTamperError
from sera.destinations.base import BaseDestinationSink
from sera.sources.base import BaseSourceConnector


MIN_BISECTION_SECONDS = 1.0


def build_initial_intervals(
    start_dt: datetime,
    end_dt: datetime,
    chunk_duration: timedelta,
) -> list[tuple[datetime, datetime]]:
    """Partition `[start_dt, end_dt)` into initial coarse slices."""
    if end_dt <= start_dt:
        raise ValueError("end_dt must be strictly greater than start_dt")
    if chunk_duration.total_seconds() <= 0:
        return [(start_dt, end_dt)]

    intervals: list[tuple[datetime, datetime]] = []
    cursor = start_dt
    while cursor < end_dt:
        nxt = min(end_dt, cursor + chunk_duration)
        intervals.append((cursor, nxt))
        cursor = nxt
    return intervals


class CollectionEngine:
    """Executes SERA collection jobs across any registered source and destination plugins."""

    def __init__(
        self,
        config: WorkspaceConfig,
        db: SeraDatabase,
        spool: EphemeralSpoolManager,
        sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.config = config
        self.db = db
        self.spool = spool
        self._sleep = sleep_fn

    def enqueue_job(
        self,
        spec: JobSpec,
        connector: BaseSourceConnector,
        sink: BaseDestinationSink,
    ) -> str:
        """Validate `spec` via the source plugin, create coarse root intervals, and persist in `sera.sqlite`."""
        connector.validate_job_spec(spec)
        start_dt, end_dt = spec.normalized_window()
        chunk_td = (
            timedelta(hours=spec.initial_chunk_hours)
            if spec.initial_chunk_hours and spec.initial_chunk_hours > 0
            else connector.default_chunk_duration(spec.sub_source)
        )
        intervals = build_initial_intervals(start_dt, end_dt, chunk_td)
        return self.db.create_job(
            spec=spec,
            destination_name=sink.dest_config.name,
            destination_target=sink.describe_target(),
            initial_intervals=intervals,
        )

    async def execute_job(
        self,
        job_id: str,
        connector: BaseSourceConnector,
        sink: BaseDestinationSink,
        on_slice_progress: Callable[[JobRecord], None] | None = None,
    ) -> JobRecord:
        """Run all pending slices for `job_id`, bisecting ONLY individual intervals that hit caps."""
        job = self.db.get_job(job_id)
        spec = JobSpec(
            source=job.source,
            sub_source=job.sub_source,
            table_or_endpoint=job.table_or_endpoint,
            start_time=job.start_time,
            end_time=job.end_time,
            template=job.template,
            params=job.params,
            profile=job.profile,
            target_id=job.target_id,
            destination=job.destination_name,
        )
        self.db.mark_job_running(job_id)
        await sink.ensure_ready()

        batch_size = max(1, self.config.batch_size)
        active_handles: list[SpoolBatchHandle] = []

        try:
            async with SeraHttpClient(connector.source_network(spec.profile), sleep_fn=self._sleep) as http:
                while (slice_rec := self.db.claim_next_pending_slice(job_id)) is not None:
                    s_dt = parse_utc_iso(slice_rec.start_time)
                    e_dt = parse_utc_iso(slice_rec.end_time)
                    active_handles.clear()

                    try:
                        result = await connector.fetch_slice(
                            job_id=job_id,
                            spec=spec,
                            slice_start=s_dt,
                            slice_end=e_dt,
                            http=http,
                        )
                    except Exception as exc:
                        self.db.mark_slice_failed(job_id, slice_rec.slice_id, str(exc))
                        raise

                    span_seconds = (e_dt - s_dt).total_seconds()
                    if result.truncated and span_seconds > MIN_BISECTION_SECONDS:
                        mid_dt = s_dt + timedelta(seconds=span_seconds / 2.0)
                        self.db.split_slice(
                            job_id=job_id,
                            parent_slice_id=slice_rec.slice_id,
                            start_iso=format_utc_iso(s_dt),
                            mid_iso=format_utc_iso(mid_dt),
                            end_iso=format_utc_iso(e_dt),
                            reason=result.truncation_reason or "Upstream row/size cap reached",
                        )
                        if on_slice_progress:
                            on_slice_progress(self.db.get_job(job_id))
                        continue

                    to_upload, skipped = self.db.filter_unuploaded_events(
                        result.events,
                        destination_name=sink.dest_config.name,
                    )

                    staged_pairs: list[tuple[SpoolBatchHandle, list]] = []
                    for seq, idx in enumerate(range(0, len(to_upload), batch_size)):
                        batch = to_upload[idx : idx + batch_size]
                        handle = self.spool.write_batch(
                            job_id=job_id,
                            slice_id=slice_rec.slice_id,
                            sequence=seq,
                            events=batch,
                        )
                        active_handles.append(handle)
                        staged_pairs.append((handle, batch))

                    current_job_view = self.db.get_job(job_id)
                    for handle, batch in staged_pairs:
                        await self._upload_from_spool_with_retry(
                            sink=sink,
                            handle=handle,
                            job=current_job_view,
                            slice_id=slice_rec.slice_id,
                        )
                        self.db.commit_uploaded_batch(
                            job_id=job_id,
                            slice_id=slice_rec.slice_id,
                            destination_name=sink.dest_config.name,
                            uploaded_events=batch,
                        )
                        self.spool.remove(handle)

                    self.db.record_fetched_and_skipped(
                        job_id=job_id,
                        slice_id=slice_rec.slice_id,
                        fetched_count=len(result.events),
                        skipped_count=skipped,
                    )
                    self.db.mark_slice_completed(job_id, slice_rec.slice_id)
                    if on_slice_progress:
                        on_slice_progress(self.db.get_job(job_id))

            self.db.mark_job_completed(job_id)
            final_job = self.db.get_job(job_id)
            await sink.record_job_summary(final_job)
            return final_job

        except Exception as exc:
            for h in active_handles:
                self.spool.remove(h)
            self.db.mark_job_failed(job_id, str(exc))
            failed_job = self.db.get_job(job_id)
            try:
                await sink.record_job_summary(failed_job)
            except Exception:
                pass
            raise

    async def _upload_from_spool_with_retry(
        self,
        sink: BaseDestinationSink,
        handle: SpoolBatchHandle,
        job: JobRecord,
        slice_id: str,
    ) -> None:
        max_attempts = max(1, self.config.network.max_retries + 1)
        for attempt in range(max_attempts):
            ndjson_bytes = self.spool.read_and_verify(handle)
            try:
                await sink.upload_ndjson_batch(
                    ndjson_bytes=ndjson_bytes,
                    event_count=handle.event_count,
                    job=job,
                    slice_id=slice_id,
                )
                return
            except SpoolTamperError:
                raise
            except Exception:
                if attempt + 1 >= max_attempts:
                    raise
                await self._sleep(min(15.0, 0.5 * (2**attempt)))
