"""Integration & contract diagnostic tests for Microsoft Defender XDR Advanced Hunting API."""

from __future__ import annotations

import os

import pytest

from sera.config import load_workspace_config
from sera.core.http_client import SeraHttpClient
from sera.sources.microsoft.auth import MicrosoftAuthManager, SCOPE_GRAPH
from sera.sources.microsoft.defender_hunting import DEFENDER_HUNTING_URL
from tests.integration.conftest import assert_required_fields_and_types, live_workspace_path


DEFENDER_HUNTING_RESPONSE_CONTRACT = {"schema": list, "results": list}
DEFENDER_HUNTING_SCHEMA_COL_CONTRACT = {"name": str, "type": str}


def test_ms_defender_hunting_wire_schema_contract() -> None:
    wire_payload = {
        "schema": [
            {"name": "Timestamp", "type": "DateTime"},
            {"name": "DeviceId", "type": "String"},
            {"name": "ReportId", "type": "Long"},
        ],
        "results": [
            {
                "Timestamp": "2026-11-23T04:00:00Z",
                "DeviceId": "abcdef0123456789abcdef0123456789abcdef01",
                "ReportId": 123456,
            }
        ],
    }
    assert_required_fields_and_types(wire_payload, DEFENDER_HUNTING_RESPONSE_CONTRACT, "DefenderHuntingEnvelope")
    assert_required_fields_and_types(
        wire_payload["schema"][0], DEFENDER_HUNTING_SCHEMA_COL_CONTRACT, "DefenderHuntingSchemaColumn"
    )
    assert isinstance(wire_payload["results"][0], dict)


@pytest.mark.skipif(
    live_workspace_path() is None or os.environ.get("SERA_ITEST_ENABLE_DEFENDER_HUNT") != "1",
    reason="Set SERA_ITEST_WORKSPACE and SERA_ITEST_ENABLE_DEFENDER_HUNT=1 to run live Defender Hunting diagnostic",
)
async def test_live_ms_defender_hunting_api_contract() -> None:
    ws = live_workspace_path()
    assert ws is not None
    cfg = load_workspace_config(ws)
    profile = os.environ.get("SERA_ITEST_MS_PROFILE", "default")
    mgr = MicrosoftAuthManager(ws, cfg.network)
    headers = await mgr.get_bearer_headers(profile, SCOPE_GRAPH)

    async with SeraHttpClient(cfg.network) as http:
        resp = await http.request_json(
            "POST",
            DEFENDER_HUNTING_URL,
            headers=headers,
            json_body={"Query": "DeviceInfo | where Timestamp > ago(1h) | take 1"},
        )
    assert_required_fields_and_types(resp, DEFENDER_HUNTING_RESPONSE_CONTRACT, "LiveDefenderHunting")
