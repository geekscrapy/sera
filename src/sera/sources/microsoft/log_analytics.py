"""Azure Monitor Log Analytics & Microsoft Sentinel KQL connector (`api.loganalytics.io`)."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

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
from sera.core.templates import TemplateRegistry, TemplateValidationError
from sera.sources.microsoft.auth import MicrosoftAuthManager, SCOPE_LOG_ANALYTICS


TRUNCATION_ERROR_TOKENS = (
    "PartialError",
    "E_QUERY_RESULT_SET_TOO_LARGE",
    "ResultSetTooLarge",
    "ResponseTooLarge",
    "query exceeded",
)


async def fetch_log_analytics_slice(
    job_id: str,
    spec: JobSpec,
    slice_start: datetime,
    slice_end: datetime,
    workspace_id: str,
    auth: MicrosoftAuthManager,
    http: SeraHttpClient,
    templates: TemplateRegistry,
    *,
    time_column: str = "TimeGenerated",
    max_rows_ceiling: int = 500_000,
) -> SliceResult:
    if not workspace_id.strip():
        raise TemplateValidationError(
            "Log Analytics / Sentinel requires 'target_id' (Log Analytics workspace GUID) "
            "or default_workspace_id in .sera/config.toml"
        )

    start_iso = format_utc_iso(slice_start)
    end_iso = format_utc_iso(slice_end)
    kql = templates.render_kql_query(
        template_name=spec.template,
        sub_source="log_analytics",
        table_name=spec.table_or_endpoint,
        time_column=time_column,
        start_iso=start_iso,
        end_iso=end_iso,
        params=spec.params,
        include_item_id=True,
    )

    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id.strip()}/query"
    headers = await auth.get_bearer_headers(spec.profile, SCOPE_LOG_ANALYTICS)
    refresh_cb = lambda: auth.get_bearer_headers(spec.profile, SCOPE_LOG_ANALYTICS, force_refresh=True)

    try:
        payload = await http.request_json(
            "POST",
            url,
            headers=headers,
            json_body={"query": kql},
            refresh_headers_on_401=refresh_cb,
        )
    except UpstreamApiError as exc:
        if any(tok in exc.body or tok in str(exc) for tok in TRUNCATION_ERROR_TOKENS):
            return SliceResult(
                events=[],
                truncated=True,
                truncation_reason=f"Log Analytics result cap hit: {exc}",
            )
        raise

    if "error" in payload and payload["error"]:
        err_blob = str(payload["error"])
        if any(tok in err_blob for tok in TRUNCATION_ERROR_TOKENS):
            return SliceResult(
                events=[],
                truncated=True,
                truncation_reason=f"Log Analytics PartialError: {err_blob[:300]}",
            )
        raise RuntimeError(f"Log Analytics returned error payload: {err_blob}")

    tables = payload.get("tables") or []
    if not tables:
        return SliceResult(events=[], truncated=False)

    primary = tables[0]
    col_defs = primary.get("columns") or []
    col_names = [str(c.get("name", f"col_{idx}")) for idx, c in enumerate(col_defs)]
    rows = primary.get("rows") or []

    if len(rows) >= max_rows_ceiling:
        return SliceResult(
            events=[],
            truncated=True,
            truncation_reason=f"Log Analytics returned {len(rows)} rows (at {max_rows_ceiling} row cap)",
        )

    events: list[RawEventEnvelope] = []
    ordinal_tracker: dict[tuple[str, str], int] = defaultdict(int)
    ingested_at = utc_now_iso()

    for row_vals in rows:
        if not isinstance(row_vals, list):
            continue
        item = {col_names[i]: row_vals[i] for i in range(min(len(col_names), len(row_vals)))}
        item_id = str(item.pop("_sera_item_id", "") or "").strip()

        raw_payload, raw_sha256 = canonical_raw_json(item)
        raw_ts = str(item.get(time_column) or item.get("TimeGenerated") or start_iso)
        norm_ts = format_utc_iso(parse_utc_iso(raw_ts))

        if item_id:
            event_id = sha256_hex(
                f"microsoft|log_analytics|{workspace_id.strip()}|{spec.table_or_endpoint}|{item_id}"
            )
        else:
            ord_key = (norm_ts, raw_sha256)
            ordinal_tracker[ord_key] += 1
            ordinal = ordinal_tracker[ord_key]
            event_id = sha256_hex(
                f"microsoft|log_analytics|{workspace_id.strip()}|{spec.table_or_endpoint}|{norm_ts}|{raw_sha256}|{ordinal}"
            )

        events.append(
            RawEventEnvelope(
                event_id=event_id,
                job_id=job_id,
                ingested_at=ingested_at,
                event_timestamp=norm_ts,
                source="microsoft",
                sub_source="log_analytics",
                table_or_endpoint=spec.table_or_endpoint,
                raw_sha256=raw_sha256,
                raw_payload=raw_payload,
                event_data=item,
            )
        )

    return SliceResult(events=events, truncated=False)
