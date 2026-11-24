"""Microsoft Defender XDR Advanced Hunting KQL connector (`/v1.0/security/runHuntingQuery`)."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from sera.core.http_client import SeraHttpClient, UpstreamApiError
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
from sera.sources.microsoft.templates import MicrosoftTemplateEngine


DEFENDER_HUNTING_URL = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
DEFENDER_TRUNCATION_TOKENS = (
    "ResultSetTooLarge",
    "ResponseTooLarge",
    "exceeded the maximum allowed size",
    "100000",
)


async def fetch_defender_hunting_slice(
    job_id: str,
    spec: JobSpec,
    slice_start: datetime,
    slice_end: datetime,
    auth: MicrosoftAuthManager,
    http: SeraHttpClient,
    templates: MicrosoftTemplateEngine,
    *,
    time_column: str = "Timestamp",
    max_rows_ceiling: int = 100_000,
) -> SliceResult:
    start_iso = format_utc_iso(slice_start)
    end_iso = format_utc_iso(slice_end)
    kql = templates.render_kql_query(
        sub_source="defender_hunting",
        table_name=spec.table_or_endpoint,
        time_column=time_column,
        start_iso=start_iso,
        end_iso=end_iso,
        params=spec.params,
        include_item_id=False,
    )

    headers = await auth.get_bearer_headers(spec.profile, SCOPE_GRAPH)
    headers["Content-Type"] = "application/json; charset=utf-8"
    refresh_cb = lambda: auth.get_bearer_headers(spec.profile, SCOPE_GRAPH, force_refresh=True)

    try:
        payload = await http.request_json(
            "POST",
            DEFENDER_HUNTING_URL,
            headers=headers,
            json_body={
                "Query": kql,
                "Timespan": f"{start_iso}/{end_iso}",
            },
            refresh_headers_on_401=refresh_cb,
        )
    except UpstreamApiError as exc:
        if any(tok in exc.body or tok in str(exc) for tok in DEFENDER_TRUNCATION_TOKENS):
            return SliceResult(
                events=[],
                truncated=True,
                truncation_reason=f"Defender Hunting query size/row ceiling hit: {exc}",
            )
        raise

    results = payload.get("results") or []
    if not isinstance(results, list):
        results = []

    if len(results) >= max_rows_ceiling:
        return SliceResult(
            events=[],
            truncated=True,
            truncation_reason=f"Defender Hunting returned {len(results)} rows (at {max_rows_ceiling} row ceiling)",
        )

    events: list[RawEventEnvelope] = []
    ordinal_tracker: dict[tuple[str, str], int] = defaultdict(int)
    ingested_at = utc_now_iso()

    for item in results:
        if not isinstance(item, dict):
            continue
        raw_payload, raw_sha256 = canonical_raw_json(item)
        raw_ts = str(item.get(time_column) or item.get("Timestamp") or start_iso)
        norm_ts = format_utc_iso(parse_utc_iso(raw_ts))

        locator = str(
            item.get("ReportId")
            or item.get("NetworkMessageId")
            or item.get("DeviceId")
            or item.get("AccountObjectId")
            or ""
        )
        ord_key = (norm_ts, raw_sha256)
        ordinal_tracker[ord_key] += 1
        ordinal = ordinal_tracker[ord_key]
        event_id = sha256_hex(
            f"microsoft|defender_hunting|{spec.table_or_endpoint}|{norm_ts}|{locator}|{raw_sha256}|{ordinal}"
        )

        events.append(
            RawEventEnvelope(
                event_id=event_id,
                job_id=job_id,
                ingested_at=ingested_at,
                event_timestamp=norm_ts,
                source="microsoft",
                sub_source="defender_hunting",
                table_or_endpoint=spec.table_or_endpoint,
                raw_sha256=raw_sha256,
                raw_payload=raw_payload,
                event_data=item,
            )
        )

    return SliceResult(events=events, truncated=False)
