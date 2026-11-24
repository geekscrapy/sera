"""Unit tests for the Rich live job & slice progress watcher (`sera watch [--bell]`)."""

from __future__ import annotations

import io
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from sera.cli.app import app
from sera.cli.watch import (
    DING_JOB_COMPLETED,
    DING_JOB_FAILED,
    DING_NEW_JOB,
    JobWatchTracker,
    build_watch_renderable,
    ring_terminal_bell,
)
from sera.core.models import JobRecord, JobStatus, SliceRecord, SliceStatus


runner = CliRunner()


def _make_job(
    job_id: str,
    status: JobStatus,
    *,
    created_at: str = "2026-11-24T10:00:00Z",
    uploaded: int = 0,
    splits: int = 0,
    error: str = "",
) -> JobRecord:
    return JobRecord(
        job_id=job_id,
        source="microsoft",
        sub_source="entra",
        table_or_endpoint="signIns",
        template="canonical",
        params={},
        profile="default",
        target_id="",
        destination_name="default",
        destination_target="proj.sera.events",
        start_time="2026-11-20T00:00:00Z",
        end_time="2026-11-23T00:00:00Z",
        status=status,
        events_fetched=uploaded,
        events_skipped_uploaded=0,
        events_uploaded=uploaded,
        slices_total=3,
        slices_completed=1,
        slices_split=splits,
        created_at=created_at,
        started_at=created_at,
        completed_at=None,
        error_message=error,
    )


def test_watch_tracker_emits_1_ding_on_new_job_2_on_complete_and_3_on_fail() -> None:
    dings: list[int] = []
    sleeps: list[float] = []

    tracker = JobWatchTracker(
        bell=True,
        on_ding=dings.append,
        between_events_gap_seconds=0.25,
        sleep_fn=sleeps.append,
    )

    # Historical job before watch session started -> 0 dings
    old_done = _make_job("job_old", JobStatus.COMPLETED, created_at="2026-11-24T09:00:00Z")
    tracker.seed([old_done])
    assert dings == []

    # Tick 1: New job arrives (`running`) -> 1 ding
    j1_running = _make_job("job_1", JobStatus.RUNNING, created_at="2026-11-24T10:01:00Z")
    assert tracker.poll([old_done, j1_running]) == [DING_NEW_JOB]
    assert dings == [1]

    # Tick 2: Still running -> 0 dings
    assert tracker.poll([old_done, j1_running]) == []
    assert dings == [1]

    # Tick 3: `job_1` completes -> 2 dings
    j1_done = _make_job("job_1", JobStatus.COMPLETED, created_at="2026-11-24T10:01:00Z", uploaded=450)
    assert tracker.poll([old_done, j1_done]) == [DING_JOB_COMPLETED]
    assert dings == [1, 2]

    # Tick 4: `job_2` arrives (`pending`) -> 1 ding
    j2_pending = _make_job("job_2", JobStatus.PENDING, created_at="2026-11-24T10:02:00Z")
    assert tracker.poll([old_done, j1_done, j2_pending]) == [DING_NEW_JOB]
    assert dings == [1, 2, 1]

    # Tick 5: `job_2` fails -> 3 dings
    j2_failed = _make_job("job_2", JobStatus.FAILED, created_at="2026-11-24T10:02:00Z", error="403 Forbidden")
    assert tracker.poll([old_done, j1_done, j2_failed]) == [DING_JOB_FAILED]
    assert dings == [1, 2, 1, 3]

    # Verify `ring_terminal_bell` writes exact ASCII BEL bytes (`\a`) with spacing
    buf = io.StringIO()
    bell_gaps: list[float] = []
    ring_terminal_bell(3, stream=buf, ding_gap_seconds=0.18, sleep_fn=bell_gaps.append)
    assert buf.getvalue() == "\a\a\a"
    assert bell_gaps == [0.18, 0.18]


def test_watch_tracker_silent_when_bell_disabled() -> None:
    dings: list[int] = []
    tracker = JobWatchTracker(bell=False, on_ding=dings.append)
    tracker.seed([])
    j = _make_job("job_silent", JobStatus.RUNNING)
    tracker.poll([j])
    tracker.poll([_make_job("job_silent", JobStatus.COMPLETED)])
    assert dings == []


def test_watch_renderable_shows_job_progress_bar_and_slice_subtasks() -> None:
    job = _make_job("job_live_1", JobStatus.RUNNING, uploaded=125, splits=1)
    slices = [
        # Parent split slice should be excluded from leaf task bars so progress math stays exact
        SliceRecord(
            slice_id="job_live_1_0000",
            job_id="job_live_1",
            parent_slice_id=None,
            start_time="2026-11-20T00:00:00Z",
            end_time="2026-11-21T00:00:00Z",
            status=SliceStatus.SPLIT,
        ),
        SliceRecord(
            slice_id="job_live_1_sp_left",
            job_id="job_live_1",
            parent_slice_id="job_live_1_0000",
            start_time="2026-11-20T00:00:00Z",
            end_time="2026-11-20T12:00:00Z",
            status=SliceStatus.COMPLETED,
            events_fetched=125,
            events_uploaded=125,
        ),
        SliceRecord(
            slice_id="job_live_1_sp_right",
            job_id="job_live_1",
            parent_slice_id="job_live_1_0000",
            start_time="2026-11-20T12:00:00Z",
            end_time="2026-11-21T00:00:00Z",
            status=SliceStatus.IN_PROGRESS,
        ),
        SliceRecord(
            slice_id="job_live_1_0001",
            job_id="job_live_1",
            parent_slice_id=None,
            start_time="2026-11-21T00:00:00Z",
            end_time="2026-11-22T00:00:00Z",
            status=SliceStatus.PENDING,
        ),
    ]

    renderable = build_watch_renderable(
        [job],
        {"job_live_1": slices},
        session_job_ids={"job_live_1"},
        bell=True,
        total_workspace_uploaded=125,
    )
    rec_console = Console(record=True, width=130, force_terminal=True)
    rec_console.print(renderable)
    text = rec_console.export_text()

    assert "SERA Live Job Monitor" in text
    assert "job_live_1" in text
    assert "microsoft/entra:signIns" in text
    assert "1/3" in text
    assert "33%" in text
    assert "├─ sp_left" in text
    assert "├─ sp_right" in text
    assert "└─ 0001" in text
    assert "running" in text
    assert "pending" in text


def test_cli_sera_watch_exit_when_idle(tmp_path: Path) -> None:
    ws = tmp_path / "watch_ws"
    init_res = runner.invoke(app, ["init", "--workspace", str(ws), "--skip-uv"])
    assert init_res.exit_code == 0, init_res.output

    watch_res = runner.invoke(
        app,
        ["watch", "--workspace", str(ws), "--bell", "--interval", "0.1", "--exit-when-idle"],
    )
    assert watch_res.exit_code == 0, watch_res.output
    assert "SERA Live Job Monitor" in watch_res.output
