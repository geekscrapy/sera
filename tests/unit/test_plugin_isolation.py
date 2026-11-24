"""AST & runtime architecture tests enforcing that concrete sources and sinks stay self-contained plugins."""

from __future__ import annotations

import ast
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from sera.config import DestinationConfig, NetworkConfig, WorkspaceConfig
from sera.core.http_client import SeraHttpClient
from sera.core.models import JobRecord, JobSpec, RawEventEnvelope, SliceResult, canonical_raw_json, format_utc_iso, sha256_hex, utc_now_iso
from sera.core.registry import DestinationRegistry, SourceRegistry
from sera.destinations.base import BaseDestinationSink, SinkOptionSpec
from sera.service import SeraService, collect_required_uv_packages, initialize_workspace
from sera.sources.base import AuthFieldSpec, AuthModeSpec, BaseSourceConnector


FORBIDDEN_CORE_IMPORT_PREFIXES = (
    "sera.sources.microsoft",
    "sera.destinations.bigquery",
    "sera.destinations.jsonl",
    "sera.destinations.http",
    "msal",
    "google.cloud",
    "google.oauth2",
)


def test_core_cli_mcp_and_service_contain_zero_concrete_plugin_imports() -> None:
    src_sera = Path(__file__).resolve().parents[2] / "src" / "sera"
    non_plugin_files: list[Path] = []
    for py_file in src_sera.rglob("*.py"):
        rel = py_file.relative_to(src_sera).parts
        # Concrete plugin directories are strictly `sources/<plugin>/...` and `destinations/<plugin>/...`
        if len(rel) >= 2 and rel[0] in {"sources", "destinations"} and rel[1] not in {"__init__.py", "base.py"}:
            continue
        non_plugin_files.append(py_file)

    assert non_plugin_files, "Expected core/service/cli/mcp files to scan"

    for py_file in non_plugin_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            imported_names: list[str] = []
            if isinstance(node, ast.Import):
                imported_names.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_names.append(node.module)
            for mod in imported_names:
                for forbidden in FORBIDDEN_CORE_IMPORT_PREFIXES:
                    assert not mod.startswith(forbidden), (
                        f"Plugin isolation violation in {py_file}: imported concrete plugin dependency '{mod}'"
                    )


class _CustomDummySource(BaseSourceConnector):
    source_name = "custom_siem"
    required_packages = ("example-siem-lib>=1.0",)

    @classmethod
    def auth_modes(cls) -> dict[str, AuthModeSpec]:
        return {"api-key": AuthModeSpec("api-key", "API Key", (AuthFieldSpec("key", "Key", secret=True),))}

    def configure_auth(self, profile: str, mode: str, values: dict[str, str], on_message: Callable[[str], None] | None = None) -> dict[str, Any]:
        return {"profile": profile, "auth_mode": mode}

    def supported_sub_sources(self) -> dict[str, dict[str, Any]]:
        return {"alerts": {"description": "Custom alerts", "default_chunk_hours": 12, "auth": "api-key"}}

    def list_templates(self, sub_source: str = "") -> list[dict[str, Any]]:
        return [{"source": "custom_siem", "sub_source": "alerts", "dialect": "json", "template_preview": "GET /alerts", "params": {}}]

    def default_chunk_duration(self, sub_source: str) -> timedelta:
        return timedelta(hours=12)

    def validate_job_spec(self, spec: JobSpec) -> None:
        return None

    def check_auth_status(self, profile: str = "default") -> dict[str, Any]:
        return {"profile": profile, "configured": True, "auth_mode": "api-key"}

    async def fetch_slice(self, job_id: str, spec: JobSpec, slice_start: datetime, slice_end: datetime, http: SeraHttpClient) -> SliceResult:
        payload = {"alert_id": "a-1", "ts": format_utc_iso(slice_start)}
        raw_str, raw_hash = canonical_raw_json(payload)
        ev = RawEventEnvelope(
            event_id=sha256_hex(f"custom|{format_utc_iso(slice_start)}"),
            job_id=job_id,
            ingested_at=utc_now_iso(),
            event_timestamp=format_utc_iso(slice_start),
            source="custom_siem",
            sub_source="alerts",
            table_or_endpoint="security",
            raw_sha256=raw_hash,
            raw_payload=raw_str,
            event_data=payload,
        )
        return SliceResult(events=[ev], truncated=False)


class _CustomMemorySink(BaseDestinationSink):
    sink_type = "custom_mem"
    required_packages = ("example-sink-lib>=2.0",)
    batches: list[bytes] = []

    @classmethod
    def option_specs(cls) -> tuple[SinkOptionSpec, ...]:
        return (SinkOptionSpec("bucket", "Target bucket", required=True), SinkOptionSpec("prefix", "Prefix", default="raw"))

    def describe_target(self) -> str:
        return f"mem://{self.dest_config.options['bucket']}/{self.dest_config.options['prefix']}"

    def config_summary(self) -> dict[str, Any]:
        return {"name": self.dest_config.name, "type": self.sink_type, **self.dest_config.options}

    async def ensure_ready(self) -> None:
        return None

    async def upload_ndjson_batch(self, ndjson_bytes: bytes, event_count: int, job: JobRecord, slice_id: str) -> None:
        self.batches.append(ndjson_bytes)

    async def record_job_summary(self, job: JobRecord) -> None:
        return None


async def test_drop_in_source_and_destination_plugins_work_end_to_end_without_core_changes(tmp_path: Path) -> None:
    src_reg = SourceRegistry(auto_discover=False)
    src_reg.register(_CustomDummySource)
    dst_reg = DestinationRegistry(auto_discover=False)
    dst_reg.register(_CustomMemorySink)
    _CustomMemorySink.batches = []

    pkgs = collect_required_uv_packages(src_reg, dst_reg)
    assert "example-siem-lib>=1.0" in pkgs
    assert "example-sink-lib>=2.0" in pkgs

    ws = tmp_path / "custom_case"
    initialize_workspace(
        ws,
        destination_type="custom_mem",
        destination_options={"bucket": "forensic-vault"},
        sync_uv_deps=False,
        source_registry=src_reg,
        destination_registry=dst_reg,
    )

    svc = SeraService(ws, source_registry=src_reg, destination_registry=dst_reg)
    assert svc.list_destinations()["configured"]["default"]["prefix"] == "raw"
    assert svc.list_templates()[0]["source"] == "custom_siem"

    receipt = svc.enqueue_job(
        JobSpec(
            source="custom_siem",
            sub_source="alerts",
            table_or_endpoint="security",
            start_time="2026-11-20T00:00:00Z",
            end_time="2026-11-20T06:00:00Z",
        )
    )
    rec = await svc.execute_enqueued_job(receipt["job_id"])
    assert rec.events_uploaded == 1
    assert len(_CustomMemorySink.batches) == 1
