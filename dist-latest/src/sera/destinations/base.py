"""Self-contained destination sink plugin contract (`BaseDestinationSink`).

Every destination sink (e.g. `bigquery`, `jsonl`, `http`, `s3`, `gcs`) lives in its own
package under `sera/destinations/<name>/` (or registers via entry point `sera.destinations`)
and encapsulates all sink options, defaults, client libraries, and upload logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import inspect
from pathlib import Path
from typing import Any

from sera.config import DestinationConfig
from sera.core.models import JobRecord


@dataclass(frozen=True)
class SinkOptionSpec:
    """Declarative configuration option owned by a destination sink plugin."""

    name: str
    description: str
    required: bool = False
    default: Any = None
    secret: bool = False


class BaseDestinationSink(ABC):
    """Self-contained destination sink plugin interface."""

    sink_type: str = ""
    required_packages: tuple[str, ...] = ()

    def __init__(self, dest_config: DestinationConfig) -> None:
        self.dest_config = dest_config

    @classmethod
    def skill_resource_markdown(cls) -> str:
        """Return sink-specific Markdown reference packaged into `skills/sera/resources/destinations/`."""
        res_file = Path(inspect.getfile(cls)).resolve().parent / "SKILL_RESOURCE.md"
        if res_file.is_file():
            return res_file.read_text(encoding="utf-8")
        return f"# Destination Plugin: `{cls.sink_type}`\n"

    @classmethod
    @abstractmethod
    def option_specs(cls) -> tuple[SinkOptionSpec, ...]:
        """Declare configurable options and defaults owned by this sink plugin."""

    @classmethod
    def apply_defaults(cls, raw_options: dict[str, Any]) -> dict[str, Any]:
        """Apply plugin-defined default option values without core knowing sink internals."""
        merged = dict(raw_options)
        for spec in cls.option_specs():
            if spec.name not in merged and spec.default is not None:
                # Copy mutable defaults safely
                merged[spec.name] = list(spec.default) if isinstance(spec.default, (list, tuple)) else spec.default
        return merged

    @abstractmethod
    def describe_target(self) -> str:
        """Human-readable target coordinate (e.g. `case-proj.sera_raw.events` or `/mnt/case/events`)."""

    def format_lookup_hint(self, job_id: str) -> str:
        """Return a sink-appropriate hint showing how to look up events uploaded by `job_id`."""
        return f"job_id={job_id} in {self.describe_target()}"

    @abstractmethod
    def config_summary(self) -> dict[str, Any]:
        """Return safe non-secret destination configuration summary."""

    @abstractmethod
    async def ensure_ready(self) -> None:
        """Provision destination tables/directories or verify connectivity prior to upload."""

    @abstractmethod
    async def upload_ndjson_batch(
        self,
        ndjson_bytes: bytes,
        event_count: int,
        job: JobRecord,
        slice_id: str,
    ) -> None:
        """Atomically upload a verified NDJSON batch of `RawEventEnvelope` rows."""

    @abstractmethod
    async def record_job_summary(self, job: JobRecord) -> None:
        """Write or append the final `JobRecord` audit summary to the destination."""
