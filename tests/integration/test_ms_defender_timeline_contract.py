"""Integration & contract diagnostic tests for MDE 180-Day Host Timeline (`/apiproxy/mtp/mdeTimelineExperience`)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from sera.config import load_workspace_config
from sera.core.http_client import SeraHttpClient
from sera.sources.microsoft.auth import MicrosoftAuthManager
from tests.integration.conftest import assert_required_fields_and_types, live_workspace_path


MDE_TIMELINE_ITEM_CONTRACT = {"EventTime": str, "ActionType": str}


def test_ms_defender_180d_timeline_wire_schema_contract() -> None:
    wire_payload = {
        "Items": [
            {
                "EventId": "tl-998877",
                "EventTime": "2026-06-15T14:22:01Z",
                "ActionType": "ProcessCreated",
                "FileName": "powershell.exe",
            }
        ],
        "IsTruncated": False,
        "ContinuationToken": None,
    }
    assert "Items" in wire_payload and isinstance(wire_payload["Items"], list)
    assert_required_fields_and_types(wire_payload["Items"][0], MDE_TIMELINE_ITEM_CONTRACT, "MdeTimelineItem")
    if wire_payload.get("ContinuationToken") is not None:
        assert isinstance(wire_payload["ContinuationToken"], str)


@pytest.mark.skipif(
    live_workspace_path() is None or not os.environ.get("SERA_ITEST_MDE_MACHINE_ID"),
    reason="Set SERA_ITEST_WORKSPACE and SERA_ITEST_MDE_MACHINE_ID to run live MDE 180d Host Timeline diagnostic",
)
async def test_live_ms_defender_timeline_api_contract() -> None:
    ws = live_workspace_path()
    assert ws is not None
    machine_id = os.environ["SERA_ITEST_MDE_MACHINE_ID"].strip()
    profile = os.environ.get("SERA_ITEST_MDE_PORTAL_PROFILE", "default")
    cfg = load_workspace_config(ws)
    mgr = MicrosoftAuthManager(ws, cfg.network)
    base_url, headers = mgr.get_portal_session_headers(profile)

    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    async with SeraHttpClient(cfg.network) as http:
        resp = await http.request_json(
            "GET",
            f"{base_url}/apiproxy/mtp/mdeTimelineExperience/machines/{machine_id}/events",
            headers=headers,
            params={"fromDate": start, "toDate": end, "pageSize": 5},
        )
    items = resp.get("Items") or resp.get("items") or resp.get("value")
    assert isinstance(items, list), f"MDE Timeline API contract changed: expected list in Items/items/value, got {list(resp.keys())}"
