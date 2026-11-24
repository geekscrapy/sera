"""Rich live job & slice progress monitor (`sera watch [--bell]`)."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Callable

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TaskProgressColumn, TextColumn
from rich.text import Text

from sera.config import sera_dir_for_workspace
from sera.core.db import SeraDatabase
from sera.core.models import JobRecord, JobStatus, SliceRecord, SliceStatus


DING_NEW_JOB = 1
DING_JOB_COMPLETED = 2
DING_JOB_FAILED = 3


def ring_terminal_bell(
    count: int,
    *,
    stream: Any = None,
    ding_gap_seconds: float = 0.18,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    """Emit `count` distinct terminal BEL (`\\a`) dings with a short gap so terminals don't coalesce them."""
    if count <= 0:
        return
    out = stream if stream is not None else sys.stdout
    for idx in range(count):
        if idx > 0 and ding_gap_seconds > 0:
            sleep_fn(ding_gap_seconds)
        out.write("\a")
        out.flush()


class JobWatchTracker:
    """Tracks job lifecycle transitions across poll ticks and triggers 1 / 2 / 3 `--bell` dings."""

    def __init__(
        self,
        *,
        bell: bool = False,
        on_ding: Callable[[int], None] | None = None,
        between_events_gap_seconds: float = 0.35,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.bell = bell
        self._on_ding = on_ding or (lambda n: ring_terminal_bell(n, sleep_fn=sleep_fn))
        self._between_events_gap = between_events_gap_seconds
        self._sleep = sleep_fn
        self.known_statuses: dict[str, JobStatus] = {}
        self.session_job_ids: set[str] = set()
        self._seeded = False

    def seed(self, jobs: list[JobRecord]) -> None:
        """Record initial jobs at startup without ringing for pre-existing historical jobs."""
        for job in jobs:
            self.known_statuses[job.job_id] = job.status
            if job.status in (JobStatus.PENDING, JobStatus.RUNNING):
                self.session_job_ids.add(job.job_id)
        self._seeded = True

    def poll(self, jobs: list[JobRecord]) -> list[int]:
        """Process a fresh snapshot of jobs and return the sequence of ding counts emitted on this tick."""
        if not self._seeded:
            self.seed(jobs)
            return []

        emitted: list[int] = []
        # Process oldest-to-newest so arrival & completion order stays chronological
        chronological = sorted(jobs, key=lambda j: (j.created_at, j.job_id))

        for job in chronological:
            prev = self.known_statuses.get(job.job_id)
            curr = job.status

            if prev is None:
                self.known_statuses[job.job_id] = curr
                self.session_job_ids.add(job.job_id)
                if curr in (JobStatus.PENDING, JobStatus.RUNNING):
                    emitted.append(DING_NEW_JOB)
                elif curr == JobStatus.COMPLETED:
                    # Sub-poll-interval job both arrived and completed
                    emitted.append(DING_NEW_JOB)
                    emitted.append(DING_JOB_COMPLETED)
                elif curr == JobStatus.FAILED:
                    emitted.append(DING_NEW_JOB)
                    emitted.append(DING_JOB_FAILED)
                continue

            if curr != prev:
                self.known_statuses[job.job_id] = curr
                self.session_job_ids.add(job.job_id)
                if curr == JobStatus.COMPLETED:
                    emitted.append(DING_JOB_COMPLETED)
                elif curr == JobStatus.FAILED:
                    emitted.append(DING_JOB_FAILED)
                elif curr in (JobStatus.PENDING, JobStatus.RUNNING) and prev in (
                    JobStatus.COMPLETED,
                    JobStatus.FAILED,
                ):
                    emitted.append(DING_NEW_JOB)

        if self.bell:
            for idx, ding_count in enumerate(emitted):
                if idx > 0 and self._between_events_gap > 0:
                    self._sleep(self._between_events_gap)
                self._on_ding(ding_count)

        return emitted


def _short_iso(ts: str) -> str:
    """Format `2026-11-20T00:00:00Z` compactly as `11-20 00:00` (with seconds if non-zero)."""
    clean = ts.strip().rstrip("Z")
    if len(clean) >= 19 and "T" in clean:
        date_part, time_part = clean.split("T", 1)
        mm_dd = date_part[5:10] if len(date_part) >= 10 else date_part
        hh_mm_ss = time_part[:8]
        if hh_mm_ss.endswith(":00"):
            return f"{mm_dd} {hh_mm_ss[:5]}"
        return f"{mm_dd} {hh_mm_ss}"
    return ts


def _short_slice_label(job_id: str, slice_id: str) -> str:
    prefix = f"{job_id}_"
    if slice_id.startswith(prefix):
        return slice_id[len(prefix) :]
    return slice_id[-12:]


def _select_visible_slices(leaf_slices: list[SliceRecord], max_slices: int) -> tuple[list[SliceRecord], int]:
    """Return `(visible_leaf_slices, hidden_count)` keeping active/failed slices visible when capped."""
    if max_slices <= 0 or len(leaf_slices) <= max_slices:
        return leaf_slices, 0

    priority = [
        idx
        for idx, s in enumerate(leaf_slices)
        if s.status in (SliceStatus.IN_PROGRESS, SliceStatus.FAILED)
    ]
    chosen: set[int] = set(priority[:max_slices])
    # Fill remaining slots with recent completed + upcoming pending slices around active work
    anchor = priority[0] if priority else 0
    radius = 0
    while len(chosen) < max_slices and (anchor - radius >= 0 or anchor + radius < len(leaf_slices)):
        if anchor - radius >= 0:
            chosen.add(anchor - radius)
        if len(chosen) < max_slices and anchor + radius < len(leaf_slices):
            chosen.add(anchor + radius)
        radius += 1

    ordered = [leaf_slices[i] for i in sorted(chosen)]
    return ordered, len(leaf_slices) - len(ordered)


def build_watch_renderable(
    jobs: list[JobRecord],
    slices_by_job: dict[str, list[SliceRecord]],
    *,
    session_job_ids: set[str] | None = None,
    show_all: bool = False,
    bell: bool = False,
    max_slices_per_job: int = 20,
    total_workspace_uploaded: int = 0,
) -> RenderableType:
    """Build a Rich Panel displaying each tracked job's progress bar and its slice tasks underneath."""
    tracked_ids = session_job_ids or set()
    visible_jobs = [
        j
        for j in jobs
        if show_all
        or j.status in (JobStatus.PENDING, JobStatus.RUNNING)
        or j.job_id in tracked_ids
    ]
    # Show oldest active/session job at top so progress bars don't jump around as new jobs arrive
    visible_jobs.sort(key=lambda j: (j.created_at, j.job_id))

    bell_label = "[bold green]ON[/bold green] (1=new, 2=done, 3=fail)" if bell else "[dim]off[/dim]"
    n_active = sum(1 for j in visible_jobs if j.status in (JobStatus.PENDING, JobStatus.RUNNING))
    n_done = sum(1 for j in visible_jobs if j.status == JobStatus.COMPLETED)
    n_failed = sum(1 for j in visible_jobs if j.status == JobStatus.FAILED)

    subtitle = (
        f"Active: [yellow]{n_active}[/yellow] │ "
        f"Completed: [green]{n_done}[/green] │ "
        f"Failed: [red]{n_failed}[/red] │ "
        f"Workspace Uploaded: [bold green]{total_workspace_uploaded:,}[/bold green] │ "
        f"[dim]Ctrl+C to exit[/dim]"
    )

    if not visible_jobs:
        empty_msg = Text.from_markup(
            "  [dim]Waiting for active SERA extraction jobs...[/dim]\n"
            "  [dim]Submit a job via MCP `collect` or CLI `sera collect --background` to watch live progress.[/dim]"
        )
        return Panel(
            empty_msg,
            title=f"[bold cyan]SERA Live Job Monitor[/bold cyan]  │  Bell: {bell_label}",
            subtitle=subtitle,
            border_style="cyan",
        )

    progress = Progress(
        TextColumn("{task.description}"),
        BarColumn(bar_width=26),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        expand=True,
    )

    extra_notes: list[RenderableType] = []

    for job in visible_jobs:
        all_slices = slices_by_job.get(job.job_id, [])
        leaf_slices = [s for s in all_slices if s.status != SliceStatus.SPLIT]

        total_units = max(1, len(leaf_slices))
        if leaf_slices:
            done_units = float(sum(1 for s in leaf_slices if s.status == SliceStatus.COMPLETED))
        else:
            done_units = 1.0 if job.status == JobStatus.COMPLETED else 0.0

        status_badge = {
            JobStatus.PENDING: "[cyan]PENDING[/cyan]",
            JobStatus.RUNNING: "[bold yellow]RUNNING[/bold yellow]",
            JobStatus.COMPLETED: "[bold green]DONE   [/bold green]",
            JobStatus.FAILED: "[bold red]FAILED [/bold red]",
        }[job.status]

        split_note = f" [magenta]splits={job.slices_split}[/magenta]" if job.slices_split else ""
        job_desc = (
            f"{status_badge} [bold cyan]{job.job_id}[/bold cyan]  "
            f"[bold]{job.source}/{job.sub_source}[/bold]:{job.table_or_endpoint}  "
            f"[green]{job.events_uploaded:,} up[/green]{split_note}"
        )
        progress.add_task(job_desc, total=total_units, completed=done_units)

        if leaf_slices:
            shown_slices, hidden_count = _select_visible_slices(leaf_slices, max_slices_per_job)
            for idx, slc in enumerate(shown_slices):
                is_last = idx == len(shown_slices) - 1 and hidden_count == 0
                branch = "  └─ " if is_last else "  ├─ "
                s_label = _short_slice_label(job.job_id, slc.slice_id)
                window = f"{_short_iso(slc.start_time)}→{_short_iso(slc.end_time)}"

                if slc.status == SliceStatus.COMPLETED:
                    s_state = "[green]done[/green]"
                    s_done = 1.0
                elif slc.status == SliceStatus.IN_PROGRESS:
                    s_state = "[bold yellow]running[/bold yellow]"
                    s_done = 0.5
                elif slc.status == SliceStatus.FAILED:
                    s_state = "[bold red]failed[/bold red]"
                    s_done = 0.0
                else:
                    s_state = "[dim]pending[/dim]"
                    s_done = 0.0

                slice_desc = (
                    f"{branch}[dim]{s_label}[/dim]  {window}  {s_state}  [dim]({slc.events_uploaded:,} ev)[/dim]"
                )
                progress.add_task(slice_desc, total=1, completed=s_done)

            if hidden_count > 0:
                progress.add_task(
                    f"  └─ [dim]... +{hidden_count} additional slices[/dim]",
                    total=len(leaf_slices),
                    completed=done_units,
                )

        if job.status == JobStatus.FAILED and job.error_message:
            extra_notes.append(
                Text.from_markup(f"  [red]✗ {job.job_id}: {job.error_message[:140]}[/red]")
            )

    body: RenderableType = Group(progress, *extra_notes) if extra_notes else progress
    return Panel(
        body,
        title=f"[bold cyan]SERA Live Job Monitor[/bold cyan]  │  Bell: {bell_label}",
        subtitle=subtitle,
        border_style="cyan",
    )


def _snapshot_workspace(
    workspace_dir: Path,
    limit: int = 100,
) -> tuple[bool, list[JobRecord], dict[str, list[SliceRecord]], int]:
    """Read `(initialized, jobs, slices_by_job, total_uploaded)` from `<workspace>/.sera/sera.sqlite`."""
    db_path = sera_dir_for_workspace(workspace_dir) / "sera.sqlite"
    if not db_path.exists():
        return False, [], {}, 0
    db = SeraDatabase(db_path)
    jobs = db.list_jobs(limit=limit)
    slices_map: dict[str, list[SliceRecord]] = {j.job_id: db.list_slices(j.job_id) for j in jobs}
    total_up = db.count_uploaded_events()
    return True, jobs, slices_map, total_up


def run_job_watcher(
    workspace_dir: Path,
    *,
    bell: bool = False,
    interval: float = 0.5,
    show_all: bool = False,
    max_slices_per_job: int = 20,
    exit_when_idle: bool = False,
    max_iterations: int | None = None,
    console: Console | None = None,
    on_ding: Callable[[int], None] | None = None,
) -> None:
    """Run the interactive Rich live job & slice progress monitor until Ctrl+C (or idle exit)."""
    ws = workspace_dir.resolve()
    ui_console = console or Console()
    poll_interval = max(0.1, interval)
    tracker = JobWatchTracker(bell=bell, on_ding=on_ding)

    initialized, init_jobs, init_slices, init_total = _snapshot_workspace(ws)
    tracker.seed(init_jobs if initialized else [])

    def _current_view(
        is_init: bool,
        jobs: list[JobRecord],
        slices_map: dict[str, list[SliceRecord]],
        total_up: int,
    ) -> RenderableType:
        if not is_init:
            bell_label = "[bold green]ON[/bold green]" if bell else "[dim]off[/dim]"
            return Panel(
                Text.from_markup(
                    f"  [yellow]Workspace `{ws}` is not initialized yet.[/yellow]\n"
                    "  [dim]Waiting for `sera init` and incoming extraction jobs... (Ctrl+C to exit)[/dim]"
                ),
                title=f"[bold cyan]SERA Live Job Monitor[/bold cyan]  │  Bell: {bell_label}",
                border_style="yellow",
            )
        return build_watch_renderable(
            jobs,
            slices_map,
            session_job_ids=tracker.session_job_ids,
            show_all=show_all,
            bell=bell,
            max_slices_per_job=max_slices_per_job,
            total_workspace_uploaded=total_up,
        )

    iteration = 0
    try:
        with Live(
            _current_view(initialized, init_jobs, init_slices, init_total),
            console=ui_console,
            refresh_per_second=4,
            transient=False,
        ) as live:
            while True:
                iteration += 1
                if max_iterations is not None and iteration > max_iterations:
                    break
                time.sleep(poll_interval)
                is_init, jobs, slices_map, total_up = _snapshot_workspace(ws)
                if is_init:
                    tracker.poll(jobs)
                live.update(_current_view(is_init, jobs, slices_map, total_up), refresh=True)

                if exit_when_idle and is_init:
                    has_active = any(j.status in (JobStatus.PENDING, JobStatus.RUNNING) for j in jobs)
                    if not has_active:
                        break
    except KeyboardInterrupt:
        ui_console.print("\n[dim]Stopped SERA job monitor.[/dim]")
