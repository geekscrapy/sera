"""Integration & contract diagnostic tests for Azure Monitor Log Analytics / Sentinel Query API."""

from __future__ import annotations

import os

import pytest

from sera.config import load_workspace_config
from sera.core.http_client import SeraHttpClient
from sera.sources.microsoft.auth import MicrosoftAuthManager, SCOPE_LOG_ANALYTICS
from tests.integration.conftest import assert_required_fields_and_types, live_workspace_path


LAW_RESPONSE_CONTRACT = {"tables": list}
LAW_TABLE_CONTRACT = {"name": str, "columns": list, "rows": list}
LAW_COLUMN_CONTRACT = {"name": str, "type": str}


def test_ms_log_analytics_wire_schema_contract() -> None:
    wire_payload = {
        "tables": [
            {
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "OperationName", "type": "string"},
                ],
                "rows": [["2026-11-23T01:00:00Z", "Sign-in activity"]],
            }
        ]
    }
    assert_required_fields_and_types(wire_payload, LAW_RESPONSE_CONTRACT, "LogAnalyticsResponse")
    tbl = wire_payload["tables"][0]
    assert_required_fields_and_types(tbl, LAW_TABLE_CONTRACT, "LogAnalyticsTable")
    assert_required_fields_and_types(tbl["columns"][0], LAW_COLUMN_CONTRACT, "LogAnalyticsColumn")
    assert isinstance(tbl["rows"][0], list)


@pytest.mark.skipif(
    live_workspace_path() is None or not os.environ.get("SERA_ITEST_LAW_WORKSPACE_ID"),
    reason="Set SERA_ITEST_WORKSPACE and SERA_ITEST_LAW_WORKSPACE_ID to run live Log Analytics contract test",
)
async def test_live_ms_log_analytics_query_contract() -> None:
    ws = live_workspace_path()
    assert ws is not None
    law_id = os.environ["SERA_ITEST_LAW_WORKSPACE_ID"].strip()
    cfg = load_workspace_config(ws)
    profile = os.environ.get("SERA_ITEST_MS_PROFILE", "default")
    mgr = MicrosoftAuthManager(ws, cfg.network)
    headers = await mgr.get_bearer_headers(profile, SCOPE_LOG_ANALYTICS)

    async with SeraHttpClient(cfg.network) as http:
        resp = await http.request_json(
            "POST",
            f"https://api.loganalytics.io/v1/workspaces/{law_id}/query",
            headers=headers,
            json_body={"query": "Usage | take 1"},
        )
    assert_required_fields_and_types(resp, LAW_RESPONSE_CONTRACT, "LiveLogAnalyticsResponse")
    assert resp["tables"], "Expected at least one table in Log Analytics response"
    assert_required_fields_and_types(resp["tables"][0], LAW_TABLE_CONTRACT, "LiveLogAnalyticsTable")
