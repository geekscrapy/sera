"""Workspace-isolated Microsoft authentication (`msal` + MDE Portal Session) stored in `.sera/creds/`."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes
import msal
import requests

from sera.config import NetworkConfig, sera_dir_for_workspace


DEFAULT_GRAPH_POWERSHELL_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

SCOPE_GRAPH = "https://graph.microsoft.com/.default"
SCOPE_LOG_ANALYTICS = "https://api.loganalytics.azure.com/.default"
SCOPE_ARM = "https://management.azure.com/.default"


class MicrosoftAuthError(RuntimeError):
    """Raised when Microsoft authentication is missing, expired, or rejected."""


def creds_path_for_profile(workspace_dir: Path, profile: str = "default") -> Path:
    safe_profile = "".join(c for c in profile if c.isalnum() or c in ("-", "_")) or "default"
    return sera_dir_for_workspace(workspace_dir) / "creds" / f"microsoft_{safe_profile}.json"


def _build_requests_session(network: NetworkConfig) -> requests.Session:
    session = requests.Session()
    if network.proxy_url:
        session.proxies = {"http": network.proxy_url, "https": network.proxy_url}
    if network.ca_bundle:
        session.verify = network.ca_bundle
    else:
        session.verify = network.verify_tls
    return session


class MicrosoftAuthManager:
    """Manages isolated per-engagement Microsoft credentials and Microsoft-scoped proxy settings in `<workspace>/.sera/creds/`."""

    def __init__(
        self,
        workspace_dir: Path,
        network: NetworkConfig,
        default_proxy_url: str = "",
        default_ca_bundle: str = "",
    ) -> None:
        self.workspace_dir = workspace_dir
        self.network = network
        self.default_proxy_url = default_proxy_url.strip()
        self.default_ca_bundle = default_ca_bundle.strip()

    def load_profile(self, profile: str = "default") -> dict[str, Any]:
        path = creds_path_for_profile(self.workspace_dir, profile)
        if not path.exists():
            raise MicrosoftAuthError(
                f"Microsoft auth profile '{profile}' not configured in {path.parent}. "
                f"Run `sera auth add microsoft --profile {profile}` first."
            )
        return json.loads(path.read_text(encoding="utf-8"))

    def save_profile(self, profile: str, data: dict[str, Any]) -> Path:
        path = creds_path_for_profile(self.workspace_dir, profile)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def effective_network(
        self,
        profile: str = "default",
        *,
        override_proxy_url: str = "",
        override_ca_bundle: str = "",
    ) -> NetworkConfig:
        """Resolve Microsoft-specific proxy and CA bundle settings without affecting destinations like BigQuery."""
        prof_proxy = ""
        prof_ca = ""
        path = creds_path_for_profile(self.workspace_dir, profile)
        if path.exists():
            try:
                pdata = json.loads(path.read_text(encoding="utf-8"))
                prof_proxy = str(pdata.get("proxy_url", "")).strip()
                prof_ca = str(pdata.get("ca_bundle", "")).strip()
            except Exception:
                pass
        proxy = override_proxy_url.strip() or prof_proxy or self.default_proxy_url or self.network.proxy_url
        ca = override_ca_bundle.strip() or prof_ca or self.default_ca_bundle or self.network.ca_bundle
        return replace(self.network, proxy_url=proxy, ca_bundle=ca)

    def check_status(self, profile: str = "default") -> dict[str, Any]:
        path = creds_path_for_profile(self.workspace_dir, profile)
        if not path.exists():
            return {"profile": profile, "configured": False, "auth_mode": None}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"profile": profile, "configured": False, "error": f"Corrupt profile JSON: {exc}"}

        mode = str(data.get("auth_mode", "unknown"))
        eff_net = self.effective_network(profile)
        info: dict[str, Any] = {
            "profile": profile,
            "configured": True,
            "auth_mode": mode,
            "tenant_id": data.get("tenant_id", ""),
        }
        if eff_net.proxy_url:
            info["has_proxy"] = True
        if mode == "portal_session":
            info["has_cookie"] = bool(data.get("cookie"))
            info["has_xsrf_token"] = bool(data.get("xsrf_token"))
            info["portal_base_url"] = data.get("base_url", "https://security.microsoft.com")
        elif mode == "delegated":
            cache = msal.SerializableTokenCache()
            if data.get("token_cache"):
                cache.deserialize(data["token_cache"])
            accounts = cache.find(msal.TokenCache.CredentialType.ACCOUNT)
            info["cached_accounts"] = [a.get("username", "") for a in accounts]
        return info

    def interactive_device_code_login(
        self,
        profile: str,
        tenant_id: str,
        client_id: str = DEFAULT_GRAPH_POWERSHELL_CLIENT_ID,
        scopes: list[str] | None = None,
        on_prompt: Callable[[str], None] | None = None,
        proxy_url: str = "",
        ca_bundle: str = "",
    ) -> dict[str, Any]:
        """Run MSAL Device-Code login isolated strictly to `<workspace>/.sera/creds/`."""
        target_scopes = scopes or ["https://graph.microsoft.com/.default"]
        cache = msal.SerializableTokenCache()
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        eff_net = self.effective_network(
            profile,
            override_proxy_url=proxy_url,
            override_ca_bundle=ca_bundle,
        )
        http_client = _build_requests_session(eff_net)
        app = msal.PublicClientApplication(
            client_id=client_id,
            authority=authority,
            token_cache=cache,
            http_client=http_client,
        )
        flow = app.initiate_device_flow(scopes=target_scopes)
        if "user_code" not in flow:
            raise MicrosoftAuthError(f"Failed to start Device Code flow: {flow}")
        if on_prompt:
            on_prompt(str(flow.get("message", f"Enter code {flow['user_code']}")))
        result = app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            raise MicrosoftAuthError(
                f"Device Code authentication failed: {result.get('error_description') or result}"
            )
        profile_data: dict[str, Any] = {
            "auth_mode": "delegated",
            "tenant_id": tenant_id,
            "client_id": client_id,
            "token_cache": cache.serialize(),
        }
        if proxy_url.strip():
            profile_data["proxy_url"] = proxy_url.strip()
        if ca_bundle.strip():
            profile_data["ca_bundle"] = ca_bundle.strip()
        self.save_profile(profile, profile_data)
        return {"profile": profile, "tenant_id": tenant_id, "auth_mode": "delegated"}

    def interactive_browser_login(
        self,
        profile: str,
        tenant_id: str,
        client_id: str = DEFAULT_GRAPH_POWERSHELL_CLIENT_ID,
        scopes: list[str] | None = None,
        proxy_url: str = "",
        ca_bundle: str = "",
    ) -> dict[str, Any]:
        """Run MSAL Interactive Browser login isolated strictly to `<workspace>/.sera/creds/`."""
        target_scopes = scopes or ["https://graph.microsoft.com/.default"]
        cache = msal.SerializableTokenCache()
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        eff_net = self.effective_network(
            profile,
            override_proxy_url=proxy_url,
            override_ca_bundle=ca_bundle,
        )
        http_client = _build_requests_session(eff_net)
        app = msal.PublicClientApplication(
            client_id=client_id,
            authority=authority,
            token_cache=cache,
            http_client=http_client,
        )
        result = app.acquire_token_interactive(scopes=target_scopes)
        if "access_token" not in result:
            raise MicrosoftAuthError(
                f"Interactive browser login failed: {result.get('error_description') or result}"
            )
        profile_data: dict[str, Any] = {
            "auth_mode": "delegated",
            "tenant_id": tenant_id,
            "client_id": client_id,
            "token_cache": cache.serialize(),
        }
        if proxy_url.strip():
            profile_data["proxy_url"] = proxy_url.strip()
        if ca_bundle.strip():
            profile_data["ca_bundle"] = ca_bundle.strip()
        self.save_profile(profile, profile_data)
        return {"profile": profile, "tenant_id": tenant_id, "auth_mode": "delegated"}

    def _acquire_bearer_sync(self, profile: str, scope: str, force_refresh: bool = False) -> str:
        data = self.load_profile(profile)
        mode = str(data.get("auth_mode", ""))

        if mode == "static_bearer":
            token = str(data.get("access_token", "")).strip()
            if not token:
                raise MicrosoftAuthError(f"Profile '{profile}' static_bearer has empty access_token")
            return token

        tenant_id = str(data.get("tenant_id", "")).strip()
        client_id = str(data.get("client_id", "")).strip()
        if not tenant_id or not client_id:
            raise MicrosoftAuthError(f"Profile '{profile}' is missing tenant_id or client_id")

        authority = f"https://login.microsoftonline.com/{tenant_id}"
        cache = msal.SerializableTokenCache()
        if data.get("token_cache"):
            cache.deserialize(data["token_cache"])
        http_client = _build_requests_session(self.effective_network(profile))

        if mode in {"service_principal_secret", "service_principal_cert"}:
            if mode == "service_principal_secret":
                credential: Any = str(data.get("client_secret", ""))
                if not credential:
                    raise MicrosoftAuthError(f"Profile '{profile}' is missing client_secret")
            else:
                key_path = Path(str(data.get("private_key_path", ""))).expanduser()
                private_key_pem = key_path.read_text(encoding="utf-8")
                cert_path_raw = str(data.get("public_certificate_path", "")).strip()
                public_cert_pem = (
                    Path(cert_path_raw).expanduser().read_text(encoding="utf-8")
                    if cert_path_raw
                    else ""
                )
                thumbprint = str(data.get("thumbprint", "")).strip()
                if not thumbprint and public_cert_pem:
                    cert_obj = x509.load_pem_x509_certificate(public_cert_pem.encode("utf-8"))
                    thumbprint = cert_obj.fingerprint(hashes.SHA1()).hex()
                if not thumbprint:
                    raise MicrosoftAuthError(
                        f"Profile '{profile}' requires 'thumbprint' (or 'public_certificate_path' to derive it)"
                    )
                credential = {
                    "private_key": private_key_pem,
                    "thumbprint": thumbprint,
                }
                if public_cert_pem:
                    credential["public_certificate"] = public_cert_pem
            app = msal.ConfidentialClientApplication(
                client_id=client_id,
                client_credential=credential,
                authority=authority,
                token_cache=cache,
                http_client=http_client,
            )
            result = app.acquire_token_for_client(scopes=[scope])
        elif mode == "delegated":
            pub_app = msal.PublicClientApplication(
                client_id=client_id,
                authority=authority,
                token_cache=cache,
                http_client=http_client,
            )
            accounts = pub_app.get_accounts()
            if not accounts:
                raise MicrosoftAuthError(
                    f"Delegated profile '{profile}' has no cached account. Re-run `sera auth add microsoft`."
                )
            result = pub_app.acquire_token_silent(
                scopes=[scope],
                account=accounts[0],
                force_refresh=force_refresh,
            )
            if not result or "access_token" not in result:
                raise MicrosoftAuthError(
                    f"Silent token refresh failed for '{profile}' (scope {scope}): "
                    f"{(result or {}).get('error_description', 'expired refresh token')}"
                )
        else:
            raise MicrosoftAuthError(
                f"Profile '{profile}' uses auth_mode='{mode}', which cannot mint OAuth Bearer tokens for {scope}"
            )

        if not result or "access_token" not in result:
            raise MicrosoftAuthError(
                f"Failed to acquire Microsoft token for '{profile}' ({scope}): "
                f"{(result or {}).get('error_description') or result}"
            )

        if cache.has_state_changed:
            data["token_cache"] = cache.serialize()
            self.save_profile(profile, data)

        return str(result["access_token"])

    async def get_bearer_headers(
        self,
        profile: str,
        scope: str,
        force_refresh: bool = False,
    ) -> dict[str, str]:
        token = await asyncio.to_thread(self._acquire_bearer_sync, profile, scope, force_refresh)
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    def get_portal_session_headers(self, profile: str) -> tuple[str, dict[str, str]]:
        """Return `(base_url, headers)` for MDE 180-day portal timeline downloads (`defender_timeline`)."""
        data = self.load_profile(profile)
        if data.get("auth_mode") != "portal_session":
            raise MicrosoftAuthError(
                f"Profile '{profile}' has auth_mode='{data.get('auth_mode')}', expected 'portal_session' "
                f"for 180-day MDE host timeline downloads. Run `sera auth add microsoft --mode portal-session --profile {profile}`."
            )
        cookie = str(data.get("cookie", "")).strip()
        xsrf = str(data.get("xsrf_token", "")).strip()
        if not cookie or not xsrf:
            raise MicrosoftAuthError(
                f"Portal session profile '{profile}' requires non-empty 'cookie' and 'xsrf_token'."
            )
        base_url = str(data.get("base_url", "https://security.microsoft.com")).rstrip("/")
        headers: dict[str, str] = {
            "Cookie": cookie,
            "X-XSRF-TOKEN": xsrf,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        }
        if data.get("tenant_id"):
            headers["tenant-id"] = str(data["tenant_id"]).strip()
        return base_url, headers
