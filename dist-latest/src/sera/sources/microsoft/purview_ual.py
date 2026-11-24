"""Microsoft Purview Unified Audit Log async Graph connector (`/security/auditLog/queries`)."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Awaitable, Callable

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
from sera.sources.microsoft.auth import MicrosoftAuthManager, SCOPE_GRAPH
from sera.sources.microsoft.templates import MicrosoftTemplateEngine, TemplateValidationError


PURVIEW_ENDPOINTS = frozenset({"auditLogRecords", "ual"})
DEFAULT_PURVIEW_BASE = "https://graph.microsoft.com/v1.0/security/auditLog/queries"


def validate_purview_endpoint(endpoint: str) -> str:
    if endpoint not in PURVIEW_ENDPOINTS:
        raise TemplateValidationError(
            f"Unsupported Purview UAL endpoint '{endpoint}'. Expected 'auditLogRecords' (or 'ual')."
        )
    return endpoint


async def fetch_purview_ual_slice(
    job_id: str,
    spec: JobSpec,
    slice_start: datetime,
    slice_end: datetime,
    auth: MicrosoftAuthManager,
    http: SeraHttpClient,
    templates: MicrosoftTemplateEngine,
    *,
    base_url: str = DEFAULT_PURVIEW_BASE,
    poll_interval_seconds: float = 2.0,
    max_polls: int = 900,
    cap_threshold: int = 950_000,
    sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> SliceResult:
    validate_purview_endpoint(spec.table_or_endpoint)
    filter_body = templates.render_purview_filters(spec.params)
    start_iso = format_utc_iso(slice_start)
    end_iso = format_utc_iso(slice_end)

    create_body: dict[str, Any] = {
        "@odata.type": "#microsoft.graph.security.auditLogQuery",
        "displayName": f"SERA-{job_id}-{start_iso}",
        "filterStartDateTime": start_iso,
        "filterEndDateTime": end_iso,
        **filter_body,
    }

    headers = await auth.get_bearer_headers(spec.profile, SCOPE_GRAPH)
    refresh_cb = lambda: auth.get_bearer_headers(spec.profile, SCOPE_GRAPH, force_refresh=True)

    created = await http.request_json(
        "POST",
        base_url,
        headers=headers,
        json_body=create_body,
        refresh_headers_on_401=refresh_cb,
    )
    query_id = str(created.get("id", "")).strip()
    if not query_id:
        raise RuntimeError(f"Purview UAL query creation did not return an 'id': {created}")

    status_url = f"{base_url}/{query_id}"
    final_query_obj = created
    status = str(created.get("status", "")).lower()
    polls = 0
    while status not in {"succeeded", "completed"}:
        if status in {"failed", "killed", "cancelled"}:
            raise RuntimeError(f"Purview UAL async query '{query_id}' failed with status='{status}'")
        polls += 1
        if polls > max_polls:
            raise TimeoutError(f"Purview UAL async query '{query_id}' timed out after {max_polls} polls")
        await sleep_fn(poll_interval_seconds)
        final_query_obj = await http.request_json(
            "GET",
            status_url,
            headers=headers,
            refresh_headers_on_401=refresh_cb,
        )
        status = str(final_query_obj.get("status", "")).lower()

    # Authoritative truncation check documented in Microsoft Graph v1.0 `auditLogQuery`:
    if bool(final_query_obj.get("isRecordCountLimitExceeded")):
        return SliceResult(
            events=[],
            truncated=True,
            truncation_reason=(
                f"Purview UAL query '{query_id}' reported isRecordCountLimitExceeded=true "
                f"(recordCountLimit={final_query_obj.get('recordCountLimit')})"
            ),
        )

    events: list[RawEventEnvelope] = []
    next_url: str | None = f"{status_url}/records"
    ingested_at = utc_now_iso()

    while next_url:
        page = await http.request_json(
            "GET",
            next_url,
            headers=headers,
            refresh_headers_on_401=refresh_cb,
        )
        records = page.get("value") or []
        if not isinstance(records, list):
            break

        for rec in records:
            if not isinstance(rec, dict):
                continue
            raw_payload, raw_sha256 = canonical_raw_json(rec)
            rec_id = str(rec.get("id") or raw_sha256)
            raw_ts = str(rec.get("createdDateTime") or start_iso)
            norm_ts = format_utc_iso(parse_utc_iso(raw_ts))
            event_id = sha256_hex(f"microsoft|purview_ual|{rec_id}")
            events.append(
                RawEventEnvelope(
                    event_id=event_id,
                    job_id=job_id,
                    ingested_at=ingested_at,
                    event_timestamp=norm_ts,
                    source="microsoft",
                    sub_source="purview_ual",
                    table_or_endpoint=spec.table_or_endpoint,
                    raw_sha256=raw_sha256,
                    raw_payload=raw_payload,
                    event_data=rec,
                )
            )

        if len(events) >= cap_threshold:
            return SliceResult(
                events=[],
                truncated=True,
                truncation_reason=f"Purview UAL slice reached {len(events)} records (near 1M query ceiling)",
            )

        next_url = page.get("@odata.nextLink")

    return SliceResult(events=events, truncated=False)
