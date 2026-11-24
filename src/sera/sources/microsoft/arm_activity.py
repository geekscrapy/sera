"""Azure Resource Manager (ARM) Subscription Activity Logs connector."""

from __future__ import annotations

from datetime import datetime, timedelta
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
from sera.sources.microsoft.auth import MicrosoftAuthManager, SCOPE_ARM


ARM_API_VERSION = "2015-04-01"


def validate_arm_endpoint(endpoint: str) -> str:
    if endpoint not in {"management", "activityLogs"}:
        raise TemplateValidationError(
            f"Unsupported ARM endpoint '{endpoint}'. Expected 'management' (or 'activityLogs')."
        )
    return endpoint


async def fetch_arm_activity_slice(
    job_id: str,
    spec: JobSpec,
    slice_start: datetime,
    slice_end: datetime,
    subscription_id: str,
    auth: MicrosoftAuthManager,
    http: SeraHttpClient,
    templates: TemplateRegistry,
) -> SliceResult:
    validate_arm_endpoint(spec.table_or_endpoint)
    if not subscription_id.strip():
        raise TemplateValidationError(
            "ARM Activity Logs require a 'target_id' (Azure subscription_id) or default_subscription_id in .sera/config.toml"
        )

    extra_pred = templates.render_odata_predicate("arm_activity", spec.params)
    start_iso = format_utc_iso(slice_start)
    # Subtract 1 microsecond for ARM's `le` upper bound to keep `[slice_start, slice_end)` half-open
    end_inclusive_dt = max(slice_start, slice_end - timedelta(microseconds=1))
    end_iso = format_utc_iso(end_inclusive_dt)

    filter_expr = f"eventTimestamp ge '{start_iso}' and eventTimestamp le '{end_iso}'"
    if extra_pred:
        filter_expr = f"{filter_expr} and {extra_pred}"

    url = (
        f"https://management.azure.com/subscriptions/{subscription_id.strip()}"
        f"/providers/microsoft.insights/eventtypes/management/values"
    )
    params: dict[str, Any] | None = {
        "api-version": ARM_API_VERSION,
        "$filter": filter_expr,
    }

    headers = await auth.get_bearer_headers(spec.profile, SCOPE_ARM)
    refresh_cb = lambda: auth.get_bearer_headers(spec.profile, SCOPE_ARM, force_refresh=True)

    events: list[RawEventEnvelope] = []
    next_url: str | None = url
    ingested_at = utc_now_iso()

    while next_url:
        payload = await http.request_json(
            "GET",
            next_url,
            headers=headers,
            params=params,
            refresh_headers_on_401=refresh_cb,
        )
        params = None
        rows = payload.get("value") or []
        if not isinstance(rows, list):
            break

        for item in rows:
            if not isinstance(item, dict):
                continue
            raw_payload, raw_sha256 = canonical_raw_json(item)
            native_uid = str(item.get("eventDataId") or item.get("id") or raw_sha256)
            raw_ts = str(item.get("eventTimestamp") or start_iso)
            norm_ts = format_utc_iso(parse_utc_iso(raw_ts))
            event_id = sha256_hex(f"microsoft|arm_activity|{subscription_id.strip()}|{native_uid}|{raw_sha256}")
            events.append(
                RawEventEnvelope(
                    event_id=event_id,
                    job_id=job_id,
                    ingested_at=ingested_at,
                    event_timestamp=norm_ts,
                    source="microsoft",
                    sub_source="arm_activity",
                    table_or_endpoint=spec.table_or_endpoint,
                    raw_sha256=raw_sha256,
                    raw_payload=raw_payload,
                    event_data=item,
                )
            )

        next_url = payload.get("nextLink") or payload.get("@odata.nextLink")

    return SliceResult(events=events, truncated=False)
