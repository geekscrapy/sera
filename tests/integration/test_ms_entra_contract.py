"""Integration & contract diagnostic tests for Microsoft Graph Entra ID Audit & Sign-In endpoints."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from sera.config import load_workspace_config
from sera.core.http_client import SeraHttpClient
from sera.sources.microsoft.auth import MicrosoftAuthManager, SCOPE_GRAPH
from tests.integration.conftest import assert_required_fields_and_types, live_workspace_path


ENTRA_COLLECTION_CONTRACT = {"value": list}
ENTRA_SIGNIN_ITEM_CONTRACT = {"id": str, "createdDateTime": str}
ENTRA_DIR_AUDIT_ITEM_CONTRACT = {"id": str, "activityDateTime": str}


def test_ms_entra_graph_wire_schema_contract() -> None:
    signin_wire = {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns",
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=abc",
        "value": [
            {
                "id": "66ea54eb-6301-432b-95e6-000000000000",
                "createdDateTime": "2026-11-23T10:15:30Z",
                "userPrincipalName": "user@contoso.com",
                "ipAddress": "198.51.100.22",
                "status": {"errorCode": 0},
            }
        ],
    }
    assert_required_fields_and_types(signin_wire, ENTRA_COLLECTION_CONTRACT, "EntraSignInsEnvelope")
    assert_required_fields_and_types(signin_wire["value"][0], ENTRA_SIGNIN_ITEM_CONTRACT, "EntraSignInItem")
    if "@odata.nextLink" in signin_wire:
        assert isinstance(signin_wire["@odata.nextLink"], str)

    audit_wire = {
        "value": [
            {
                "id": "Directory_12345",
                "activityDateTime": "2026-11-23T10:20:00Z",
                "activityDisplayName": "Add member to role",
            }
        ]
    }
    assert_required_fields_and_types(audit_wire, ENTRA_COLLECTION_CONTRACT, "EntraDirAuditEnvelope")
    assert_required_fields_and_types(audit_wire["value"][0], ENTRA_DIR_AUDIT_ITEM_CONTRACT, "EntraDirAuditItem")


@pytest.mark.skipif(
    live_workspace_path() is None,
    reason="Set SERA_ITEST_WORKSPACE to validate live MS Graph Entra API response contract",
)
async def test_live_ms_entra_signins_api_contract() -> None:
    ws = live_workspace_path()
    assert ws is not None
    cfg = load_workspace_config(ws)
    profile = os.environ.get("SERA_ITEST_MS_PROFILE", "default")
    mgr = MicrosoftAuthManager(ws, cfg.network)
    headers = await mgr.get_bearer_headers(profile, SCOPE_GRAPH)

    now = datetime.now(timezone.utc)
    start = (now - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
    async with SeraHttpClient(cfg.network) as http:
        resp = await http.request_json(
            "GET",
            "https://graph.microsoft.com/v1.0/auditLogs/signIns",
            headers=headers,
            params={"$filter": f"createdDateTime ge {start}", "$top": 1},
        )
    assert_required_fields_and_types(resp, ENTRA_COLLECTION_CONTRACT, "LiveEntraSignIns")
    if resp["value"]:
        assert_required_fields_and_types(resp["value"][0], ENTRA_SIGNIN_ITEM_CONTRACT, "LiveEntraSignInItem")
