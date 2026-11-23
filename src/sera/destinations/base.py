"""Abstract base sink interface for customizable SERA destinations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from sera.config import DestinationConfig, NetworkConfig
from sera.core.models import JobRecord


class BaseDestinationSink(ABC):
    """Pluggable destination sink accepting verified NDJSON forensic batches."""

    sink_type: str = ""

    def __init__(self, dest_config: DestinationConfig, network: NetworkConfig) -> None:
        self.dest_config = dest_config
        self.network = network

    @abstractmethod
    def describe_target(self) -> str:
        """Human- and SQL-readable target identifier (e.g. `case-proj.raw_logs.events`)."""

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
