"""Self-contained destination sink plugin contract (`BaseDestinationSink`).

Every destination sink (e.g. `bigquery`, `jsonl`, `http`, `s3`, `gcs`) lives in its own
package under `sera/destinations/<name>/` (or registers via entry point `sera.destinations`)
and encapsulates all sink options (file paths, dataset names, HTTP proxies), auth modes,
defaults, client libraries, and upload logic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import inspect
import json
from pathlib import Path
from typing import Any

from sera.config import DestinationConfig, sera_dir_for_workspace
from sera.core.models import JobRecord
from sera.sources.base import AuthFieldSpec, AuthModeSpec


@dataclass(frozen=True)
class SinkOptionSpec:
    """Declarative configuration option owned by a destination sink plugin (stored in `.sera/config.toml`)."""

    name: str
    description: str
    required: bool = False
    default: Any = None
    secret: bool = False


def dest_creds_path(workspace_dir: Path, dest_name: str) -> Path:
    safe_name = "".join(c for c in dest_name if c.isalnum() or c in ("-", "_")) or "default"
    return sera_dir_for_workspace(workspace_dir) / "creds" / f"dest_{safe_name}.json"


class BaseDestinationSink(ABC):
    """Self-contained destination sink plugin interface."""

    sink_type: str = ""
    required_packages: tuple[str, ...] = ()

    def __init__(self, dest_config: DestinationConfig, workspace_dir: Path | None = None) -> None:
        self.dest_config = dest_config
        self.workspace_dir = workspace_dir

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
    def auth_modes(cls) -> dict[str, AuthModeSpec]:
        """Declare supported authentication modes and secret fields for `sera dest add`."""
        return {
            "none": AuthModeSpec(
                mode="none",
                description="No separate destination credentials required",
                fields=(),
            )
        }

    def configure_auth(
        self,
        workspace_dir: Path,
        mode: str,
        values: dict[str, str],
    ) -> dict[str, Any]:
        """Persist isolated destination credentials in `<workspace>/.sera/creds/dest_<name>.json`."""
        modes = self.auth_modes()
        if mode not in modes:
            raise ValueError(
                f"Unsupported auth mode '{mode}' for destination '{self.sink_type}'. Valid: {', '.join(sorted(modes))}"
            )
        payload: dict[str, Any] = {"auth_mode": mode}
        for fspec in modes[mode].fields:
            val = values.get(fspec.name, fspec.default).strip()
            if fspec.required and not val:
                raise ValueError(f"Destination '{self.sink_type}' auth mode '{mode}' requires '{fspec.name}'")
            if val:
                payload[fspec.name] = val
        path = dest_creds_path(workspace_dir, self.dest_config.name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return {"destination": self.dest_config.name, "type": self.sink_type, "auth_mode": mode}

    def load_auth_data(self) -> dict[str, Any]:
        """Load stored destination credentials from `<workspace>/.sera/creds/dest_<name>.json` if present."""
        if self.workspace_dir is None:
            return {}
        path = dest_creds_path(self.workspace_dir, self.dest_config.name)
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def check_auth_status(self) -> dict[str, Any]:
        """Inspect non-secret destination authentication readiness."""
        modes = self.auth_modes()
        default_mode = next(iter(modes))
        data = self.load_auth_data()
        active_mode = str(data.get("auth_mode") or default_mode)
        return {"auth_mode": active_mode, "configured": True}

    @classmethod
    def apply_defaults(cls, raw_options: dict[str, Any]) -> dict[str, Any]:
        """Apply plugin-defined default option values without core knowing sink internals."""
        merged = dict(raw_options)
        for spec in cls.option_specs():
            if spec.name not in merged and spec.default is not None:
                merged[spec.name] = list(spec.default) if isinstance(spec.default, (list, tuple)) else spec.default
        return merged

    @abstractmethod
    def describe_target(self) -> str:
        """Human-readable target coordinate (e.g. `case-proj.sera.events` or `/mnt/case/events`)."""

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
