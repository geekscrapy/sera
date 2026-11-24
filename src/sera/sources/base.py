"""Self-contained source plugin contract (`BaseSourceConnector`).

Every telemetry source (e.g. `microsoft`, `splunk`, `crowdstrike`, `wiz`) lives in its
own package under `sera/sources/<name>/` (or registers via entry point `sera.sources`)
and encapsulates all vendor auth, query templates, pagination, and runtime dependencies.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
import inspect
from pathlib import Path
from typing import Any, Callable

from sera.config import NetworkConfig, WorkspaceConfig
from sera.core.http_client import SeraHttpClient
from sera.core.models import JobSpec, SliceResult


@dataclass(frozen=True)
class AuthFieldSpec:
    """Declarative specification for an authentication input field owned by a source plugin."""

    name: str
    description: str
    required: bool = True
    secret: bool = False
    default: str = ""


@dataclass(frozen=True)
class AuthModeSpec:
    """Declarative specification for an authentication mode supported by a source plugin."""

    mode: str
    description: str
    fields: tuple[AuthFieldSpec, ...] = ()


class BaseSourceConnector(ABC):
    """Self-contained source evidence plugin interface."""

    source_name: str = ""
    required_packages: tuple[str, ...] = ()

    def __init__(self, workspace_dir: Path, config: WorkspaceConfig) -> None:
        self.workspace_dir = workspace_dir
        self.config = config

    def source_network(self, profile: str = "default") -> NetworkConfig:
        """Return HTTP client network settings for this source plugin (proxy is source-scoped, never destination-scoped)."""
        return self.config.network

    @classmethod
    def skill_resource_markdown(cls) -> str:
        """Return source-specific Markdown reference packaged into `skills/sera/resources/sources/`."""
        res_file = Path(inspect.getfile(cls)).resolve().parent / "SKILL_RESOURCE.md"
        if res_file.is_file():
            return res_file.read_text(encoding="utf-8")
        return f"# Source Plugin: `{cls.source_name}`\n"

    @classmethod
    @abstractmethod
    def auth_modes(cls) -> dict[str, AuthModeSpec]:
        """Declare supported authentication modes and their input fields for the CLI."""

    @abstractmethod
    def configure_auth(
        self,
        profile: str,
        mode: str,
        values: dict[str, str],
        on_message: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Configure and persist isolated credentials in `<workspace>/.sera/creds/`."""

    @abstractmethod
    def supported_sub_sources(self) -> dict[str, dict[str, Any]]:
        """Return metadata map of supported `sub_source`s and their rules (zero schema sampling)."""

    @abstractmethod
    def list_templates(self, sub_source: str = "") -> list[dict[str, Any]]:
        """Return canonical full-event template metadata owned by this source plugin."""

    @abstractmethod
    def default_chunk_duration(self, sub_source: str) -> timedelta:
        """Return default initial slice interval size for `sub_source`."""

    @abstractmethod
    def validate_job_spec(self, spec: JobSpec) -> None:
        """Validate `sub_source`, `table_or_endpoint`, time bounds, and plugin filter `params`."""

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
    ) -> SliceResult:
        """Fetch raw full events for `[slice_start, slice_end)` or report `SliceResult(truncated=True)`."""
