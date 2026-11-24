"""Microsoft Defender for Endpoint (MDE) 180-Day Host Timeline connector (`defender_timeline`).

Bridges the 30-day Advanced Hunting limit by querying MDE's 180-day device timeline API
(`/apiproxy/mtp/mdeTimelineExperience/machines/{machine_id}/events`) using an isolated
portal session profile (`sccauth` Cookie + `X-XSRF-TOKEN`) in `<= 7d` adaptive slices.
"""

from __future__ import annotations

from collections import defaultdict
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
from sera.sources.microsoft.auth import MicrosoftAuthManager
from sera.sources.microsoft.templates import MicrosoftTemplateEngine


async def fetch_defender_timeline_slice(
    job_id: str,
    spec: JobSpec,
    slice_start: datetime,
    slice_end: datetime,
    auth: MicrosoftAuthManager,
    http: SeraHttpClient,
    templates: MicrosoftTemplateEngine,
    *,
    page_size: int = 1000,
    max_events_per_slice: int = 250_000,
) -> SliceResult:
    machine_id, timeline_opts = templates.render_mde_timeline_params(
        spec.table_or_endpoint,
        spec.params,
    )
    base_url, headers = auth.get_portal_session_headers(spec.profile)
    endpoint_url = f"{base_url}/apiproxy/mtp/mdeTimelineExperience/machines/{machine_id}/events"

    start_iso = format_utc_iso(slice_start)
    end_iso = format_utc_iso(slice_end)

    params: dict[str, Any] | None = {
        "fromDate": start_iso,
        "toDate": end_iso,
        "doNotUseCache": "false",
        "forceUseCache": "false",
        "pageSize": page_size,
    }
    if timeline_opts.get("search_text"):
        params["searchText"] = timeline_opts["search_text"]
    if timeline_opts.get("action_types"):
        params["actionTypes"] = ",".join(timeline_opts["action_types"])

    events: list[RawEventEnvelope] = []
    ordinal_tracker: dict[tuple[str, str], int] = defaultdict(int)
    next_url: str | None = endpoint_url
    ingested_at = utc_now_iso()

    while next_url:
        payload = await http.request_json(
            "GET",
            next_url,
            headers=headers,
            params=params,
        )
        items = (
            payload.get("Items")
            or payload.get("items")
            or payload.get("value")
            or payload.get("Events")
            or []
        )
        if not isinstance(items, list):
            items = []

        for item in items:
            if not isinstance(item, dict):
                continue
            raw_payload, raw_sha256 = canonical_raw_json(item)
            raw_ts = str(
                item.get("EventTime")
                or item.get("Timestamp")
                or item.get("ActionTime")
                or item.get("CreatedTime")
                or start_iso
            )
            norm_ts = format_utc_iso(parse_utc_iso(raw_ts))
            native_id = str(item.get("EventId") or item.get("Id") or item.get("id") or "")

            if native_id:
                event_id = sha256_hex(
                    f"microsoft|defender_timeline|{machine_id}|{native_id}|{raw_sha256}"
                )
            else:
                ord_key = (norm_ts, raw_sha256)
                ordinal_tracker[ord_key] += 1
                event_id = sha256_hex(
                    f"microsoft|defender_timeline|{machine_id}|{norm_ts}|{raw_sha256}|{ordinal_tracker[ord_key]}"
                )

            events.append(
                RawEventEnvelope(
                    event_id=event_id,
                    job_id=job_id,
                    ingested_at=ingested_at,
                    event_timestamp=norm_ts,
                    source="microsoft",
                    sub_source="defender_timeline",
                    table_or_endpoint=machine_id,
                    raw_sha256=raw_sha256,
                    raw_payload=raw_payload,
                    event_data=item,
                )
            )

        is_truncated_flag = bool(payload.get("IsTruncated") or payload.get("isTruncated"))
        continuation = payload.get("ContinuationToken") or payload.get("continuationToken")
        explicit_next = payload.get("NextPageUrl") or payload.get("nextLink") or payload.get("@odata.nextLink")

        if is_truncated_flag and not continuation and not explicit_next:
            return SliceResult(
                events=[],
                truncated=True,
                truncation_reason="MDE Timeline response reported IsTruncated=true without continuation cursor",
            )

        if len(events) >= max_events_per_slice and (continuation or explicit_next):
            return SliceResult(
                events=[],
                truncated=True,
                truncation_reason=f"MDE Timeline slice reached {len(events)} events with more pages pending",
            )

        if explicit_next:
            next_url = str(explicit_next)
            if next_url.startswith("/"):
                next_url = f"{base_url}{next_url}"
            params = None
        elif continuation:
            next_url = endpoint_url
            params = dict(params or {})
            params["continuationToken"] = str(continuation)
        else:
            next_url = None

    return SliceResult(events=events, truncated=False)
