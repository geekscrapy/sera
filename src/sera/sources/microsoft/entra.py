"""Microsoft Entra ID Graph connector (`signIns`, `directoryAudits`, `provisioning`, `riskDetections`)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sera.core.http_client import SeraHttpClient
from sera.core.models import (
    JobSpec,
    RawEventEnvelope,
    SliceResult,
    canonical_raw_json,
    format_utc_iso,
    parse_utc_iso,
    sha256_hex,
    utc_now_iso,
)
from sera.core.templates import TemplateRegistry, TemplateValidationError
from sera.sources.microsoft.auth import MicrosoftAuthManager, SCOPE_GRAPH


ENTRA_ENDPOINTS: dict[str, tuple[str, str]] = {
    "signIns": ("https://graph.microsoft.com/v1.0/auditLogs/signIns", "createdDateTime"),
    "directoryAudits": ("https://graph.microsoft.com/v1.0/auditLogs/directoryAudits", "activityDateTime"),
    "provisioning": ("https://graph.microsoft.com/v1.0/auditLogs/provisioning", "activityDateTime"),
    "riskDetections": ("https://graph.microsoft.com/v1.0/identityProtection/riskDetections", "detectedDateTime"),
}


def validate_entra_endpoint(endpoint: str) -> tuple[str, str]:
    if endpoint not in ENTRA_ENDPOINTS:
        valid = ", ".join(sorted(ENTRA_ENDPOINTS))
        raise TemplateValidationError(
            f"Unsupported Entra endpoint '{endpoint}'. Supported endpoints: {valid}"
        )
    return ENTRA_ENDPOINTS[endpoint]


async def fetch_entra_slice(
    job_id: str,
    spec: JobSpec,
    slice_start: datetime,
    slice_end: datetime,
    auth: MicrosoftAuthManager,
    http: SeraHttpClient,
    templates: TemplateRegistry,
    max_events_per_slice: int = 500_000,
) -> SliceResult:
    url, time_field = validate_entra_endpoint(spec.table_or_endpoint)
    extra_pred = templates.render_odata_predicate("entra", spec.params)
    start_iso = format_utc_iso(slice_start)
    end_iso = format_utc_iso(slice_end)

    time_pred = f"{time_field} ge {start_iso} and {time_field} lt {end_iso}"
    full_filter = f"({time_pred}) and ({extra_pred})" if extra_pred else time_pred

    headers = await auth.get_bearer_headers(spec.profile, SCOPE_GRAPH)
    refresh_cb = lambda: auth.get_bearer_headers(spec.profile, SCOPE_GRAPH, force_refresh=True)

    events: list[RawEventEnvelope] = []
    next_url: str | None = url
    query_params: dict[str, Any] | None = {"$filter": full_filter}
    ingested_at = utc_now_iso()

    while next_url:
        payload = await http.request_json(
            "GET",
            next_url,
            headers=headers,
            params=query_params,
            refresh_headers_on_401=refresh_cb,
        )
        # @odata.nextLink already embeds query parameters
        query_params = None
        rows = payload.get("value") or []
        if not isinstance(rows, list):
            break

        for item in rows:
            if not isinstance(item, dict):
                continue
            raw_payload, raw_sha256 = canonical_raw_json(item)
            native_id = str(item.get("id") or raw_sha256)
            raw_ts = str(item.get(time_field) or start_iso)
            norm_ts = format_utc_iso(parse_utc_iso(raw_ts))
            event_id = sha256_hex(f"microsoft|entra|{spec.table_or_endpoint}|{native_id}")
            events.append(
                RawEventEnvelope(
                    event_id=event_id,
                    job_id=job_id,
                    ingested_at=ingested_at,
                    event_timestamp=norm_ts,
                    source="microsoft",
                    sub_source="entra",
                    table_or_endpoint=spec.table_or_endpoint,
                    raw_sha256=raw_sha256,
                    raw_payload=raw_payload,
                    event_data=item,
                )
            )

        if len(events) >= max_events_per_slice and payload.get("@odata.nextLink"):
            return SliceResult(
                events=[],
                truncated=True,
                truncation_reason=f"Entra slice exceeded {max_events_per_slice} events with more pages remaining",
            )

        next_url = payload.get("@odata.nextLink")

    return SliceResult(events=events, truncated=False)
