"""Integration & contract diagnostic tests for Azure Resource Manager (ARM) Subscription Activity Logs."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from sera.config import load_workspace_config
from sera.core.http_client import SeraHttpClient
from sera.sources.microsoft.arm_activity import ARM_API_VERSION
from sera.sources.microsoft.auth import MicrosoftAuthManager, SCOPE_ARM
from tests.integration.conftest import assert_required_fields_and_types, live_workspace_path


ARM_ENVELOPE_CONTRACT = {"value": list}
ARM_EVENT_CONTRACT = {"eventDataId": str, "eventTimestamp": str}


def test_ms_arm_activity_wire_schema_contract() -> None:
    wire_payload = {
        "value": [
            {
                "id": "/subscriptions/0000/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1/events/e1",
                "eventDataId": "11111111-2222-3333-4444-555555555555",
                "eventTimestamp": "2026-11-23T09:00:00Z",
                "caller": "admin@contoso.com",
                "status": {"value": "Succeeded"},
            }
        ],
        "nextLink": "https://management.azure.com/subscriptions/0000/...?$skiptoken=xyz",
    }
    assert_required_fields_and_types(wire_payload, ARM_ENVELOPE_CONTRACT, "ArmActivityEnvelope")
    assert_required_fields_and_types(wire_payload["value"][0], ARM_EVENT_CONTRACT, "ArmActivityItem")
    if "nextLink" in wire_payload:
        assert isinstance(wire_payload["nextLink"], str)


@pytest.mark.skipif(
    live_workspace_path() is None or not os.environ.get("SERA_ITEST_AZURE_SUBSCRIPTION_ID"),
    reason="Set SERA_ITEST_WORKSPACE and SERA_ITEST_AZURE_SUBSCRIPTION_ID to run live ARM Activity diagnostic",
)
async def test_live_ms_arm_activity_api_contract() -> None:
    ws = live_workspace_path()
    assert ws is not None
    sub_id = os.environ["SERA_ITEST_AZURE_SUBSCRIPTION_ID"].strip()
    cfg = load_workspace_config(ws)
    profile = os.environ.get("SERA_ITEST_MS_PROFILE", "default")
    mgr = MicrosoftAuthManager(ws, cfg.network)
    headers = await mgr.get_bearer_headers(profile, SCOPE_ARM)

    now = datetime.now(timezone.utc)
    start = (now - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    async with SeraHttpClient(cfg.network) as http:
        resp = await http.request_json(
            "GET",
            f"https://management.azure.com/subscriptions/{sub_id}/providers/microsoft.insights/eventtypes/management/values",
            headers=headers,
            params={
                "api-version": ARM_API_VERSION,
                "$filter": f"eventTimestamp ge '{start}' and eventTimestamp le '{end}'",
            },
        )
    assert_required_fields_and_types(resp, ARM_ENVELOPE_CONTRACT, "LiveArmActivity")
    if resp["value"]:
        assert_required_fields_and_types(resp["value"][0], ARM_EVENT_CONTRACT, "LiveArmActivityItem")
