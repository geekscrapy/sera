"""Self-contained HTTP/HEC destination sink plugin (`type = "http"`)."""

from __future__ import annotations

import json
from typing import Any

from sera.config import DestinationConfig, NetworkConfig
from sera.core.http_client import SeraHttpClient
from sera.core.models import JobRecord, utc_now_iso
from sera.destinations.base import BaseDestinationSink, SinkOptionSpec


class HttpIngestDestination(BaseDestinationSink):
    """Forwards verified NDJSON batches to an HTTPS ingestion endpoint (`ndjson`, `json_array`, or `splunk_hec`)."""

    sink_type = "http"
    required_packages = ("httpx[socks]>=0.27.0",)

    @classmethod
    def option_specs(cls) -> tuple[SinkOptionSpec, ...]:
        return (
            SinkOptionSpec("url", "HTTPS ingestion endpoint URL", required=True),
            SinkOptionSpec("format", "Payload format: ndjson | json_array | splunk_hec", required=False, default="ndjson"),
            SinkOptionSpec("bearer_token", "Optional Bearer authorization token", required=False, default="", secret=True),
            SinkOptionSpec("hec_token", "Optional Splunk HEC authorization token", required=False, default="", secret=True),
            SinkOptionSpec("jobs_url", "Optional URL to POST job completion manifests", required=False, default=""),
        )

    def __init__(self, dest_config: DestinationConfig, network: NetworkConfig) -> None:
        super().__init__(dest_config, network)
        opts = self.apply_defaults(dest_config.options)
        self.url = str(opts.get("url", "")).strip()
        if not self.url:
            raise ValueError(f"HTTP destination '{dest_config.name}' requires 'url'")
        self.payload_format = str(opts.get("format", "ndjson")).strip()
        if self.payload_format not in {"ndjson", "json_array", "splunk_hec"}:
            raise ValueError(f"Unsupported HTTP destination format '{self.payload_format}'")
        self.bearer_token = str(opts.get("bearer_token", "")).strip()
        self.hec_token = str(opts.get("hec_token", "")).strip()
        raw_headers = opts.get("headers") or {}
        self.extra_headers = {str(k): str(v) for k, v in raw_headers.items()} if isinstance(raw_headers, dict) else {}

    def describe_target(self) -> str:
        return self.url

    def config_summary(self) -> dict[str, Any]:
        return {
            "name": self.dest_config.name,
            "type": self.sink_type,
            "url": self.url,
            "format": self.payload_format,
            "has_auth": bool(self.bearer_token or self.hec_token or self.extra_headers),
        }

    def _headers(self) -> dict[str, str]:
        hdrs = dict(self.extra_headers)
        if self.bearer_token:
            hdrs["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.hec_token:
            hdrs["Authorization"] = f"Splunk {self.hec_token}"
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
        async with SeraHttpClient(self.network) as http:
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
        async with SeraHttpClient(self.network) as http:
            await http.request_json(
                "POST",
                summary_url,
                headers=self._headers(),
                json_body={"recorded_at": utc_now_iso(), **job.to_summary_dict()},
            )
