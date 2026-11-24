"""Wire-level `respx` unit tests across all 6 Microsoft DFIR surfaces (verified against Microsoft Learn specs)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import respx

from sera.config import NetworkConfig
from sera.core.http_client import SeraHttpClient
from sera.core.models import JobSpec
from sera.sources.microsoft.arm_activity import fetch_arm_activity_slice
from sera.sources.microsoft.auth import MicrosoftAuthManager
from sera.sources.microsoft.defender_hunting import fetch_defender_hunting_slice
from sera.sources.microsoft.defender_timeline import fetch_defender_timeline_slice
from sera.sources.microsoft.entra import fetch_entra_slice
from sera.sources.microsoft.log_analytics import fetch_log_analytics_slice
from sera.sources.microsoft.purview_ual import fetch_purview_ual_slice
from sera.sources.microsoft.templates import MicrosoftTemplateEngine


async def _noop_sleep(_: float) -> None:
    return None


def _setup_auth(tmp_path: Path) -> MicrosoftAuthManager:
    mgr = MicrosoftAuthManager(tmp_path, NetworkConfig(max_retries=2))
    mgr.save_profile("default", {"auth_mode": "static_bearer", "access_token": "test-bearer-tok"})
    mgr.save_profile(
        "mde_portal",
        {
            "auth_mode": "portal_session",
            "tenant_id": "tid-111",
            "cookie": "sccauth=secret-cookie-val",
            "xsrf_token": "xsrf-val-999",
            "base_url": "https://security.microsoft.com",
        },
    )
    return mgr


async def test_entra_pagination_429_retry_and_full_fidelity(tmp_path: Path) -> None:
    auth = _setup_auth(tmp_path)
    templates = MicrosoftTemplateEngine()
    s0 = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)
    s1 = datetime(2026, 11, 21, 0, 0, tzinfo=timezone.utc)
    spec = JobSpec(
        source="microsoft",
        sub_source="entra",
        table_or_endpoint="signIns",
        start_time="2026-11-20T00:00:00Z",
        end_time="2026-11-21T00:00:00Z",
        params={"in_list": {"userPrincipalName": ["alice@contoso.com"]}},
    )

    page1 = {
        "value": [{"id": "si-1", "createdDateTime": "2026-11-20T02:00:00Z", "unmappedBetaField": {"deep": [1, 2, 3]}}],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=page2",
    }
    page2 = {
        "value": [{"id": "si-2", "createdDateTime": "2026-11-20T03:00:00Z", "ipAddress": "198.51.100.8"}],
    }

    with respx.mock(assert_all_called=True) as router:
        router.get("https://graph.microsoft.com/v1.0/auditLogs/signIns").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0.05"}, json={"error": "throttled"}),
                httpx.Response(200, json=page1),
                httpx.Response(200, json=page2),
            ]
        )
        async with SeraHttpClient(NetworkConfig(max_retries=2), sleep_fn=_noop_sleep) as http:
            res = await fetch_entra_slice("job_1", spec, s0, s1, auth, http, templates)

    assert not res.truncated
    assert len(res.events) == 2
    assert json.loads(res.events[0].raw_payload)["unmappedBetaField"] == {"deep": [1, 2, 3]}


async def test_purview_ual_v1_ga_async_job_and_authoritative_limit_exceeded_flag(tmp_path: Path) -> None:
    auth = _setup_auth(tmp_path)
    templates = MicrosoftTemplateEngine()
    s0 = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)
    s1 = datetime(2026, 11, 21, 0, 0, tzinfo=timezone.utc)
    spec = JobSpec(
        source="microsoft",
        sub_source="purview_ual",
        table_or_endpoint="auditLogRecords",
        start_time="2026-11-20T00:00:00Z",
        end_time="2026-11-21T00:00:00Z",
        params={"operations": ["MailItemsAccessed"]},
    )

    with respx.mock(assert_all_called=True) as router:
        router.post("https://graph.microsoft.com/v1.0/security/auditLog/queries").mock(
            side_effect=[
                httpx.Response(201, json={"id": "q-555", "status": "running"}),
                httpx.Response(201, json={"id": "q-cap", "status": "succeeded", "isRecordCountLimitExceeded": True}),
            ]
        )
        router.get("https://graph.microsoft.com/v1.0/security/auditLog/queries/q-555").mock(
            return_value=httpx.Response(
                200,
                json={"id": "q-555", "status": "succeeded", "isRecordCountLimitExceeded": False},
            )
        )
        router.get("https://graph.microsoft.com/v1.0/security/auditLog/queries/q-555/records").mock(
            return_value=httpx.Response(
                200,
                json={
                    "value": [
                        {
                            "id": "ual-rec-1",
                            "createdDateTime": "2026-11-20T05:10:00Z",
                            "operation": "MailItemsAccessed",
                            "auditData": {"ClientIPAddress": "203.0.113.77", "Folders": [{"Path": "/Inbox"}]},
                        }
                    ]
                },
            )
        )
        async with SeraHttpClient(NetworkConfig(), sleep_fn=_noop_sleep) as http:
            res = await fetch_purview_ual_slice(
                "job_ual", spec, s0, s1, auth, http, templates, sleep_fn=_noop_sleep
            )
            trunc = await fetch_purview_ual_slice(
                "job_ual", spec, s0, s1, auth, http, templates, sleep_fn=_noop_sleep
            )

    assert len(res.events) == 1
    assert json.loads(res.events[0].raw_payload)["auditData"]["ClientIPAddress"] == "203.0.113.77"
    assert trunc.truncated is True
    assert "isRecordCountLimitExceeded=true" in trunc.truncation_reason


async def test_log_analytics_azure_com_endpoint_timespan_prefer_wait_and_partial_error(tmp_path: Path) -> None:
    auth = _setup_auth(tmp_path)
    templates = MicrosoftTemplateEngine()
    s0 = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)
    s1 = datetime(2026, 11, 21, 0, 0, tzinfo=timezone.utc)
    spec = JobSpec(
        source="microsoft",
        sub_source="log_analytics",
        table_or_endpoint="SigninLogs",
        start_time="2026-11-20T00:00:00Z",
        end_time="2026-11-21T00:00:00Z",
        params={"in_list": {"UserPrincipalName": ["bob@contoso.com"]}},
        target_id="ws-guid-123",
    )

    law_ok = {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "UserPrincipalName", "type": "string"},
                    {"name": "_sera_item_id", "type": "string"},
                ],
                "rows": [["2026-11-20T06:00:00Z", "bob@contoso.com", "item-guid-abc"]],
            }
        ]
    }
    law_truncated = {"error": {"code": "PartialError", "message": "E_QUERY_RESULT_SET_TOO_LARGE"}}

    with respx.mock(assert_all_called=True) as router:
        law_route = router.post("https://api.loganalytics.azure.com/v1/workspaces/ws-guid-123/query").mock(
            side_effect=[
                httpx.Response(200, json=law_ok),
                httpx.Response(200, json=law_truncated),
            ]
        )
        async with SeraHttpClient(NetworkConfig(), sleep_fn=_noop_sleep) as http:
            ok_res = await fetch_log_analytics_slice("job_law", spec, s0, s1, "ws-guid-123", auth, http, templates)
            trunc_res = await fetch_log_analytics_slice("job_law", spec, s0, s1, "ws-guid-123", auth, http, templates)

    sent_req = law_route.calls[0].request
    assert sent_req.headers["Prefer"] == "wait=600"
    assert json.loads(sent_req.content)["timespan"] == "2026-11-20T00:00:00Z/2026-11-21T00:00:00Z"
    assert len(ok_res.events) == 1
    assert "_sera_item_id" not in json.loads(ok_res.events[0].raw_payload)
    assert trunc_res.truncated is True


async def test_defender_hunting_timespan_defender_180d_timeline_and_arm_activity(tmp_path: Path) -> None:
    auth = _setup_auth(tmp_path)
    templates = MicrosoftTemplateEngine()
    s0 = datetime(2026, 7, 1, 0, 0, tzinfo=timezone.utc)
    s1 = datetime(2026, 7, 8, 0, 0, tzinfo=timezone.utc)

    hunt_spec = JobSpec(
        source="microsoft",
        sub_source="defender_hunting",
        table_or_endpoint="DeviceProcessEvents",
        start_time="2026-07-01T00:00:00Z",
        end_time="2026-07-08T00:00:00Z",
        params={"in_list": {"DeviceName": ["srv-dc01"]}},
    )
    timeline_spec = JobSpec(
        source="microsoft",
        sub_source="defender_timeline",
        table_or_endpoint="abcdef0123456789abcdef0123456789abcdef01",
        start_time="2026-07-01T00:00:00Z",
        end_time="2026-07-08T00:00:00Z",
        params={"search_text": "lsass"},
        profile="mde_portal",
    )
    arm_spec = JobSpec(
        source="microsoft",
        sub_source="arm_activity",
        table_or_endpoint="management",
        start_time="2026-07-01T00:00:00Z",
        end_time="2026-07-08T00:00:00Z",
        params={"equals": {"resourceGroupName": "rg-prod"}},
        target_id="sub-999",
    )

    with respx.mock(assert_all_called=True) as router:
        hunt_route = router.post("https://graph.microsoft.com/v1.0/security/runHuntingQuery").mock(
            return_value=httpx.Response(
                200,
                json={"results": [{"Timestamp": "2026-07-02T01:00:00Z", "DeviceId": "d1", "ReportId": 77, "FileName": "rundll32.exe"}]},
            )
        )
        router.get(
            "https://security.microsoft.com/apiproxy/mtp/mdeTimelineExperience/machines/abcdef0123456789abcdef0123456789abcdef01/events"
        ).mock(
            side_effect=[
                httpx.Response(
                    200,
                    json={
                        "Items": [{"EventId": "tl-1", "EventTime": "2026-07-01T10:00:00Z", "ActionType": "ProcessCreated"}],
                        "ContinuationToken": "tok-page-2",
                    },
                ),
                httpx.Response(
                    200,
                    json={
                        "Items": [{"EventId": "tl-2", "EventTime": "2026-07-03T12:00:00Z", "ActionType": "FileCreated"}],
                    },
                ),
            ]
        )
        arm_route = router.get(
            "https://management.azure.com/subscriptions/sub-999/providers/Microsoft.Insights/eventtypes/management/values"
        ).mock(
            return_value=httpx.Response(
                200,
                json={"value": [{"eventDataId": "arm-1", "eventTimestamp": "2026-07-04T08:00:00Z", "resourceGroupName": "rg-prod"}]},
            )
        )

        async with SeraHttpClient(NetworkConfig(), sleep_fn=_noop_sleep) as http:
            h_res = await fetch_defender_hunting_slice("j1", hunt_spec, s0, s1, auth, http, templates)
            t_res = await fetch_defender_timeline_slice("j2", timeline_spec, s0, s1, auth, http, templates)
            a_res = await fetch_arm_activity_slice("j3", arm_spec, s0, s1, "sub-999", auth, http, templates)

    assert json.loads(hunt_route.calls[0].request.content)["Timespan"] == "2026-07-01T00:00:00Z/2026-07-08T00:00:00Z"
    assert arm_route.calls[0].request.headers["Prefer"] == "wait=75"
    assert len(h_res.events) == 1
    assert len(t_res.events) == 2
    assert len(a_res.events) == 1
