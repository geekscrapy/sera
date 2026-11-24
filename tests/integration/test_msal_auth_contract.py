"""Integration & contract diagnostic tests for Microsoft Entra ID / MSAL OAuth2 token acquisition."""

from __future__ import annotations

import os

import pytest

from sera.config import NetworkConfig, load_workspace_config
from sera.core.http_client import SeraHttpClient
from sera.sources.microsoft.auth import MicrosoftAuthManager, SCOPE_GRAPH, _build_requests_session
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


async def test_socks5_proxy_support_across_msal_requests_and_httpx() -> None:
    """Ensure both `requests` (used by MSAL) and `httpx` (used by SERA) have SOCKS5/PySocks support."""
    import socks  # PySocks must be installed for MSAL `requests` SOCKS5 proxies

    assert hasattr(socks, "SOCKS5")

    for proxy_url in ("socks5://127.0.0.1:1080", "socks5h://127.0.0.1:1080"):
        net = NetworkConfig(proxy_url=proxy_url)
        req_session = _build_requests_session(net)
        adapter = req_session.get_adapter("https://login.microsoftonline.com")
        # Raises `InvalidSchema: Missing dependencies for SOCKS support` if PySocks is absent
        proxy_mgr = adapter.proxy_manager_for(proxy_url)
        assert proxy_mgr is not None

        async with SeraHttpClient(net) as http_client:
            assert http_client._client is not None


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
