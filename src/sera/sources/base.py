"""Abstract base connector protocol for pluggable SERA log sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sera.config import WorkspaceConfig
from sera.core.http_client import SeraHttpClient
from sera.core.models import JobSpec, SliceResult
from sera.core.templates import TemplateRegistry


class BaseSourceConnector(ABC):
    """Base interface for all SERA telemetry source connectors."""

    source_name: str = ""

    def __init__(self, workspace_dir: Path, config: WorkspaceConfig) -> None:
        self.workspace_dir = workspace_dir
        self.config = config

    @abstractmethod
    def supported_sub_sources(self) -> dict[str, dict[str, Any]]:
        """Return metadata map of supported `sub_source` names and their rules (zero schema sampling)."""

    @abstractmethod
    def default_chunk_duration(self, sub_source: str) -> timedelta:
        """Return default initial slice interval size for `sub_source`."""

    @abstractmethod
    def validate_job_spec(self, spec: JobSpec, templates: TemplateRegistry) -> None:
        """Validate `sub_source`, `table_or_endpoint`, time bounds, and allowlisted template parameters."""

    @abstractmethod
    def check_auth_status(self, profile: str = "default") -> dict[str, Any]:
        """Inspect local profile readiness without exposing secret values."""

    @abstractmethod
    async def fetch_slice(
        self,
        job_id: str,
        spec: JobSpec,
        slice_start: datetime,
        slice_end: datetime,
        http: SeraHttpClient,
        templates: TemplateRegistry,
    ) -> SliceResult:
        """Fetch raw full events for `[slice_start, slice_end)` or report `SliceResult(truncated=True)`."""
