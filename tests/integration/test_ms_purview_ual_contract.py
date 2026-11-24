"""Integration & contract diagnostic tests for Microsoft Purview Unified Audit Log Graph API."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from sera.config import load_workspace_config
from sera.core.http_client import SeraHttpClient
from sera.sources.microsoft.auth import MicrosoftAuthManager, SCOPE_GRAPH
from sera.sources.microsoft.purview_ual import DEFAULT_PURVIEW_BASE
from tests.integration.conftest import assert_required_fields_and_types, live_workspace_path


PURVIEW_QUERY_JOB_CONTRACT = {"id": str, "status": str, "isRecordCountLimitExceeded": bool}
PURVIEW_RECORD_ITEM_CONTRACT = {"id": str, "createdDateTime": str, "auditData": dict}


def test_ms_purview_ual_wire_schema_contract() -> None:
    query_job = {
        "@odata.type": "#microsoft.graph.security.auditLogQuery",
        "id": "8e1101d9-0000-4d00-a000-111111111111",
        "displayName": "SERA-diagnostic",
        "status": "succeeded",
        "isRecordCountLimitExceeded": False,
        "filterStartDateTime": "2026-11-23T00:00:00Z",
        "filterEndDateTime": "2026-11-23T00:05:00Z",
    }
    assert_required_fields_and_types(query_job, PURVIEW_QUERY_JOB_CONTRACT, "PurviewAuditLogQuery")

    records_page = {
        "value": [
            {
                "id": "rec-999",
                "createdDateTime": "2026-11-23T00:02:11Z",
                "operation": "UserLoggedIn",
                "service": "AzureActiveDirectory",
                "auditData": {"Id": "rec-999", "Workload": "AzureActiveDirectory"},
            }
        ]
    }
    assert_required_fields_and_types(records_page, {"value": list}, "PurviewAuditRecordsEnvelope")
    assert_required_fields_and_types(records_page["value"][0], PURVIEW_RECORD_ITEM_CONTRACT, "PurviewAuditRecord")


@pytest.mark.skipif(
    live_workspace_path() is None or os.environ.get("SERA_ITEST_ENABLE_PURVIEW") != "1",
    reason="Set SERA_ITEST_WORKSPACE and SERA_ITEST_ENABLE_PURVIEW=1 to run live Purview async query diagnostic",
)
async def test_live_ms_purview_ual_create_and_status_contract() -> None:
    ws = live_workspace_path()
    assert ws is not None
    cfg = load_workspace_config(ws)
    profile = os.environ.get("SERA_ITEST_MS_PROFILE", "default")
    mgr = MicrosoftAuthManager(ws, cfg.network)
    headers = await mgr.get_bearer_headers(profile, SCOPE_GRAPH)

    now = datetime.now(timezone.utc)
    start = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    async with SeraHttpClient(cfg.network) as http:
        created = await http.request_json(
            "POST",
            DEFAULT_PURVIEW_BASE,
            headers=headers,
            json_body={
                "displayName": "SERA-contract-diagnostic",
                "filterStartDateTime": start,
                "filterEndDateTime": end,
            },
        )
    assert_required_fields_and_types(created, PURVIEW_QUERY_JOB_CONTRACT, "LivePurviewCreateQuery")
