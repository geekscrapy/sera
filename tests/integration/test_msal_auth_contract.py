"""Integration & contract diagnostic tests for Microsoft Entra ID / MSAL OAuth2 token acquisition."""

from __future__ import annotations

import os

import pytest

from sera.config import load_workspace_config
from sera.sources.microsoft.auth import MicrosoftAuthManager, SCOPE_GRAPH
from tests.integration.conftest import assert_required_fields_and_types, live_workspace_path


MSAL_TOKEN_CONTRACT = {
    "token_type": str,
    "expires_in": int,
    "access_token": str,
}


def test_msal_oauth2_token_response_schema_contract() -> None:
    """Validate SERA's MSAL token contract expectations against Entra ID's OAuth2 v2.0 specification."""
    sample_entra_token_response = {
        "token_type": "Bearer",
        "expires_in": 3599,
        "ext_expires_in": 3599,
        "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.payload.sig",
    }
    assert_required_fields_and_types(sample_entra_token_response, MSAL_TOKEN_CONTRACT, "EntraOAuth2Token")
    assert sample_entra_token_response["token_type"] == "Bearer"
    assert sample_entra_token_response["expires_in"] > 0


@pytest.mark.skipif(
    live_workspace_path() is None,
    reason="Set SERA_ITEST_WORKSPACE=/path/to/initialized_case to run live MSAL token diagnostic",
)
async def test_live_msal_token_acquisition_contract() -> None:
    ws = live_workspace_path()
    assert ws is not None
    cfg = load_workspace_config(ws)
    profile = os.environ.get("SERA_ITEST_MS_PROFILE", "default")
    mgr = MicrosoftAuthManager(ws, cfg.network)
    headers = await mgr.get_bearer_headers(profile, SCOPE_GRAPH)
    assert_required_fields_and_types(headers, {"Authorization": str, "Accept": str}, "LiveMSALHeaders")
    assert headers["Authorization"].startswith("Bearer ")
