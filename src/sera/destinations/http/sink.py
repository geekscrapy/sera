"""Self-contained HTTP/HEC destination sink plugin (`type = "http"`)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sera.config import DestinationConfig, NetworkConfig
from sera.core.http_client import SeraHttpClient
from sera.core.models import JobRecord, utc_now_iso
from sera.destinations.base import BaseDestinationSink, SinkOptionSpec
from sera.sources.base import AuthFieldSpec, AuthModeSpec


class HttpIngestDestination(BaseDestinationSink):
    """Forwards verified NDJSON batches to an HTTPS ingestion endpoint (`ndjson`, `json_array`, or `splunk_hec`)."""

    sink_type = "http"
    required_packages = ("httpx[socks]>=0.27.0",)

    @classmethod
    def option_specs(cls) -> tuple[SinkOptionSpec, ...]:
        return (
            SinkOptionSpec("url", "HTTPS ingestion endpoint URL", required=True),
            SinkOptionSpec("format", "Payload format: ndjson | json_array | splunk_hec", required=False, default="ndjson"),
            SinkOptionSpec("jobs_url", "Optional URL to POST job completion manifests", required=False, default=""),
            SinkOptionSpec(
                "proxy_url",
                "Optional HTTP/HTTPS/SOCKS5 proxy URL for this HTTP destination",
                required=False,
                default="",
            ),
            SinkOptionSpec(
                "ca_bundle",
                "Optional custom CA certificate PEM path for this HTTP destination",
                required=False,
                default="",
            ),
        )

    @classmethod
    def auth_modes(cls) -> dict[str, AuthModeSpec]:
        return {
            "none": AuthModeSpec(
                mode="none",
                description="Unauthenticated HTTPS ingestion endpoint",
                fields=(),
            ),
            "bearer": AuthModeSpec(
                mode="bearer",
                description="HTTP Authorization Bearer token",
                fields=(AuthFieldSpec("bearer_token", "Bearer authorization token", required=True, secret=True),),
            ),
            "splunk-hec": AuthModeSpec(
                mode="splunk-hec",
                description="Splunk HTTP Event Collector (HEC) token",
                fields=(AuthFieldSpec("hec_token", "Splunk HEC token", required=True, secret=True),),
            ),
        }

    def __init__(self, dest_config: DestinationConfig, workspace_dir: Path | None = None) -> None:
        super().__init__(dest_config, workspace_dir=workspace_dir)
        opts = self.apply_defaults(dest_config.options)
        self.url = str(opts.get("url", "")).strip()
        if not self.url:
            raise ValueError(f"HTTP destination '{dest_config.name}' requires 'url'")
        self.payload_format = str(opts.get("format", "ndjson")).strip()
        if self.payload_format not in {"ndjson", "json_array", "splunk_hec"}:
            raise ValueError(f"Unsupported HTTP destination format '{self.payload_format}'")
        self.proxy_url = str(opts.get("proxy_url", "")).strip()
        self.ca_bundle = str(opts.get("ca_bundle", "")).strip()
        self._inline_bearer = str(opts.get("bearer_token", "")).strip()
        self._inline_hec = str(opts.get("hec_token", "")).strip()
        raw_headers = opts.get("headers") or {}
        self.extra_headers = {str(k): str(v) for k, v in raw_headers.items()} if isinstance(raw_headers, dict) else {}

    def _sink_network(self) -> NetworkConfig:
        return NetworkConfig(proxy_url=self.proxy_url, ca_bundle=self.ca_bundle)

    def describe_target(self) -> str:
        return self.url

    def config_summary(self) -> dict[str, Any]:
        auth_data = self.load_auth_data()
        has_secret = bool(
            self._inline_bearer
            or self._inline_hec
            or auth_data.get("bearer_token")
            or auth_data.get("hec_token")
            or self.extra_headers
        )
        return {
            "name": self.dest_config.name,
            "type": self.sink_type,
            "url": self.url,
            "format": self.payload_format,
            "has_proxy": bool(self.proxy_url),
            "has_auth": has_secret,
            "auth_mode": str(auth_data.get("auth_mode") or ("inline" if has_secret else "none")),
        }

    def _headers(self) -> dict[str, str]:
        hdrs = dict(self.extra_headers)
        auth_data = self.load_auth_data()
        bearer = str(auth_data.get("bearer_token", "")).strip() or self._inline_bearer
        hec = str(auth_data.get("hec_token", "")).strip() or self._inline_hec
        if bearer:
            hdrs["Authorization"] = f"Bearer {bearer}"
        elif hec:
            hdrs["Authorization"] = f"Splunk {hec}"
        return hdrs

    async def ensure_ready(self) -> None:
        return None

    async def upload_ndjson_batch(
        self,
        ndjson_bytes: bytes,
        event_count: int,
        job: JobRecord,
        slice_id: str,
    ) -> None:
        if not ndjson_bytes or event_count <= 0:
            return
        headers = self._headers()
        async with SeraHttpClient(self._sink_network()) as http:
            assert http._client is not None
            if self.payload_format == "ndjson":
                headers["Content-Type"] = "application/x-ndjson"
                resp = await http._client.post(self.url, content=ndjson_bytes, headers=headers)
                resp.raise_for_status()
            elif self.payload_format == "json_array":
                rows = [json.loads(line) for line in ndjson_bytes.decode("utf-8").splitlines() if line.strip()]
                await http.request_json("POST", self.url, headers=headers, json_body={"events": rows})
            elif self.payload_format == "splunk_hec":
                hec_lines: list[str] = []
                for line in ndjson_bytes.decode("utf-8").splitlines():
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    hec_lines.append(
                        json.dumps(
                            {
                                "sourcetype": f"sera:{row['source']}:{row['sub_source']}",
                                "event": row,
                            },
                            separators=(",", ":"),
                        )
                    )
                headers["Content-Type"] = "application/json"
                resp = await http._client.post(
                    self.url,
                    content=("\n".join(hec_lines) + "\n").encode("utf-8"),
                    headers=headers,
                )
                resp.raise_for_status()

    async def record_job_summary(self, job: JobRecord) -> None:
        summary_url = str(self.dest_config.options.get("jobs_url", "")).strip()
        if not summary_url:
            return
        async with SeraHttpClient(self._sink_network()) as http:
            await http.request_json(
                "POST",
                summary_url,
                headers=self._headers(),
                json_body={"recorded_at": utc_now_iso(), **job.to_summary_dict()},
            )
