"""Self-contained `microsoft` source evidence plugin (`MicrosoftSourceConnector`)."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from sera.config import WorkspaceConfig
from sera.core.http_client import SeraHttpClient
from sera.core.models import JobSpec, SliceResult
from sera.core.template_primitives import TemplateValidationError, validate_table_ident
from sera.sources.base import AuthFieldSpec, AuthModeSpec, BaseSourceConnector
from sera.sources.microsoft.arm_activity import fetch_arm_activity_slice, validate_arm_endpoint
from sera.sources.microsoft.auth import DEFAULT_GRAPH_POWERSHELL_CLIENT_ID, MicrosoftAuthManager
from sera.sources.microsoft.defender_hunting import fetch_defender_hunting_slice
from sera.sources.microsoft.defender_timeline import fetch_defender_timeline_slice
from sera.sources.microsoft.entra import ENTRA_ENDPOINTS, fetch_entra_slice, validate_entra_endpoint
from sera.sources.microsoft.log_analytics import fetch_log_analytics_slice
from sera.sources.microsoft.purview_ual import fetch_purview_ual_slice, validate_purview_endpoint
from sera.sources.microsoft.templates import MicrosoftTemplateEngine, validate_machine_id


SUB_SOURCE_SPECS: dict[str, dict[str, Any]] = {
    "entra": {
        "description": "Microsoft Entra ID Audit, Sign-In, Provisioning, and Risk Detections via MS Graph v1.0.",
        "endpoints": sorted(ENTRA_ENDPOINTS),
        "default_chunk_hours": 24,
        "auth": "msal (secret | cert | device-code | browser)",
    },
    "purview_ual": {
        "description": "M365 Purview Unified Audit Log via GA MS Graph `/v1.0/security/auditLog/queries`.",
        "endpoints": ["auditLogRecords"],
        "default_chunk_hours": 24,
        "auth": "msal (AuditLogsQuery.Read.All)",
    },
    "log_analytics": {
        "description": "Azure Monitor Log Analytics & Microsoft Sentinel workspace tables (`api.loganalytics.azure.com`).",
        "endpoints": ["<Any Log Analytics / Sentinel table name, e.g. SigninLogs, SecurityEvent>"],
        "requires_target_id": "Log Analytics Workspace GUID (or default_workspace_id in [sources.microsoft])",
        "default_chunk_hours": 24,
        "auth": "msal (Log Analytics Reader)",
    },
    "defender_hunting": {
        "description": "Microsoft Defender XDR Advanced Hunting tables (`/v1.0/security/runHuntingQuery`).",
        "endpoints": ["<Any XDR table, e.g. DeviceProcessEvents, EmailEvents, IdentityLogonEvents>"],
        "default_chunk_hours": 24,
        "auth": "msal (ThreatHunting.Read.All)",
    },
    "defender_timeline": {
        "description": "Microsoft Defender for Endpoint 180-Day Host Timeline (`table_or_endpoint` = machine_id).",
        "endpoints": ["<MDE 40-hex MachineId / DeviceId>"],
        "default_chunk_hours": 168,  # 7 days
        "auth": "portal-session (sccauth Cookie + X-XSRF-TOKEN)",
    },
    "arm_activity": {
        "description": "Azure Subscription ARM Activity Logs (`management.azure.com`, up to 90-day lookback).",
        "endpoints": ["management"],
        "requires_target_id": "Azure Subscription GUID (or default_subscription_id in [sources.microsoft])",
        "default_chunk_hours": 168,  # 7 days
        "auth": "msal (Reader on Subscription)",
    },
}


class MicrosoftSourceConnector(BaseSourceConnector):
    """Self-contained Microsoft/Azure telemetry plugin across all 6 DFIR surfaces."""

    source_name = "microsoft"
    required_packages = ("msal>=1.28.0", "cryptography>=42.0.0")

    def __init__(self, workspace_dir: Path, config: WorkspaceConfig) -> None:
        super().__init__(workspace_dir, config)
        self.auth = MicrosoftAuthManager(workspace_dir=workspace_dir, network=config.network)
        self.templates = MicrosoftTemplateEngine()

    @classmethod
    def auth_modes(cls) -> dict[str, AuthModeSpec]:
        return {
            "secret": AuthModeSpec(
                mode="secret",
                description="Entra App Registration (Service Principal) using Client Secret",
                fields=(
                    AuthFieldSpec("tenant_id", "Microsoft Entra Tenant ID", required=True),
                    AuthFieldSpec("client_id", "App Registration Client ID", required=True),
                    AuthFieldSpec("client_secret", "App Registration Client Secret", required=True, secret=True),
                ),
            ),
            "cert": AuthModeSpec(
                mode="cert",
                description="Entra App Registration (Service Principal) using PEM Certificate",
                fields=(
                    AuthFieldSpec("tenant_id", "Microsoft Entra Tenant ID", required=True),
                    AuthFieldSpec("client_id", "App Registration Client ID", required=True),
                    AuthFieldSpec("private_key_path", "PEM private key file path", required=True),
                    AuthFieldSpec("thumbprint", "SHA-1 certificate thumbprint (optional if public_certificate_path set)", required=False),
                    AuthFieldSpec("public_certificate_path", "Optional public PEM certificate file path", required=False),
                ),
            ),
            "device-code": AuthModeSpec(
                mode="device-code",
                description="Delegated user login via MSAL Device-Code flow",
                fields=(
                    AuthFieldSpec("tenant_id", "Microsoft Entra Tenant ID", required=True),
                    AuthFieldSpec(
                        "client_id",
                        "Public Client ID",
                        required=False,
                        default=DEFAULT_GRAPH_POWERSHELL_CLIENT_ID,
                    ),
                ),
            ),
            "browser": AuthModeSpec(
                mode="browser",
                description="Delegated user login via MSAL Interactive Browser flow",
                fields=(
                    AuthFieldSpec("tenant_id", "Microsoft Entra Tenant ID", required=True),
                    AuthFieldSpec(
                        "client_id",
                        "Public Client ID",
                        required=False,
                        default=DEFAULT_GRAPH_POWERSHELL_CLIENT_ID,
                    ),
                ),
            ),
            "portal-session": AuthModeSpec(
                mode="portal-session",
                description="MDE 180-Day Host Timeline portal session (Cookie + X-XSRF-TOKEN)",
                fields=(
                    AuthFieldSpec("cookie", "MDE Portal Cookie header containing sccauth=...", required=True, secret=True),
                    AuthFieldSpec("xsrf_token", "MDE Portal X-XSRF-TOKEN header", required=True, secret=True),
                    AuthFieldSpec("tenant_id", "Optional tenant-id header", required=False, default=""),
                    AuthFieldSpec("base_url", "Portal base URL", required=False, default="https://security.microsoft.com"),
                ),
            ),
            "static-bearer": AuthModeSpec(
                mode="static-bearer",
                description="Pre-acquired static OAuth2 Bearer access token",
                fields=(
                    AuthFieldSpec("access_token", "Bearer access token", required=True, secret=True),
                    AuthFieldSpec("tenant_id", "Optional tenant identifier", required=False, default=""),
                ),
            ),
        }

    def configure_auth(
        self,
        profile: str,
        mode: str,
        values: dict[str, str],
        on_message: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        modes = self.auth_modes()
        if mode not in modes:
            raise ValueError(f"Unsupported Microsoft auth mode '{mode}'. Valid modes: {', '.join(sorted(modes))}")

        if mode == "secret":
            tid = values["tenant_id"].strip()
            cid = values["client_id"].strip()
            path = self.auth.save_profile(
                profile,
                {
                    "auth_mode": "service_principal_secret",
                    "tenant_id": tid,
                    "client_id": cid,
                    "client_secret": values["client_secret"].strip(),
                },
            )
            return {"profile": profile, "auth_mode": "service_principal_secret", "tenant_id": tid, "client_id": cid, "path": str(path)}

        if mode == "cert":
            tid = values["tenant_id"].strip()
            cid = values["client_id"].strip()
            path = self.auth.save_profile(
                profile,
                {
                    "auth_mode": "service_principal_cert",
                    "tenant_id": tid,
                    "client_id": cid,
                    "private_key_path": values["private_key_path"].strip(),
                    "thumbprint": values.get("thumbprint", "").strip(),
                    "public_certificate_path": values.get("public_certificate_path", "").strip(),
                },
            )
            return {"profile": profile, "auth_mode": "service_principal_cert", "tenant_id": tid, "client_id": cid, "path": str(path)}

        if mode == "device-code":
            tid = values["tenant_id"].strip()
            cid = values.get("client_id", "").strip() or DEFAULT_GRAPH_POWERSHELL_CLIENT_ID
            res = self.auth.interactive_device_code_login(profile=profile, tenant_id=tid, client_id=cid, on_prompt=on_message)
            return {**res, "client_id": cid}

        if mode == "browser":
            tid = values["tenant_id"].strip()
            cid = values.get("client_id", "").strip() or DEFAULT_GRAPH_POWERSHELL_CLIENT_ID
            res = self.auth.interactive_browser_login(profile=profile, tenant_id=tid, client_id=cid)
            return {**res, "client_id": cid}

        if mode == "portal-session":
            tid = values.get("tenant_id", "").strip()
            path = self.auth.save_profile(
                profile,
                {
                    "auth_mode": "portal_session",
                    "tenant_id": tid,
                    "cookie": values["cookie"].strip(),
                    "xsrf_token": values["xsrf_token"].strip(),
                    "base_url": values.get("base_url", "").strip() or "https://security.microsoft.com",
                },
            )
            return {"profile": profile, "auth_mode": "portal_session", "tenant_id": tid, "client_id": "", "path": str(path)}

        # static-bearer
        tid = values.get("tenant_id", "").strip()
        path = self.auth.save_profile(
            profile,
            {
                "auth_mode": "static_bearer",
                "tenant_id": tid,
                "access_token": values["access_token"].strip(),
            },
        )
        return {"profile": profile, "auth_mode": "static_bearer", "tenant_id": tid, "client_id": "", "path": str(path)}

    def supported_sub_sources(self) -> dict[str, dict[str, Any]]:
        return SUB_SOURCE_SPECS

    def list_templates(self, sub_source: str = "") -> list[dict[str, Any]]:
        return self.templates.list_templates(sub_source=sub_source)

    def default_chunk_duration(self, sub_source: str) -> timedelta:
        if sub_source not in SUB_SOURCE_SPECS:
            raise KeyError(f"Unsupported Microsoft sub_source '{sub_source}'")
        return timedelta(hours=float(SUB_SOURCE_SPECS[sub_source]["default_chunk_hours"]))

    def _resolve_target_id(self, spec: JobSpec, default_key: str) -> str:
        if spec.target_id.strip():
            return spec.target_id.strip()
        ms_defaults = self.config.source_defaults.get("microsoft", {})
        return str(ms_defaults.get(default_key, "")).strip()

    def validate_job_spec(self, spec: JobSpec) -> None:
        if spec.sub_source not in SUB_SOURCE_SPECS:
            valid = ", ".join(sorted(SUB_SOURCE_SPECS))
            raise TemplateValidationError(
                f"Unknown Microsoft sub_source '{spec.sub_source}'. Supported: {valid}"
            )
        start_dt, end_dt = spec.normalized_window()
        s_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        e_iso = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        if spec.sub_source == "entra":
            validate_entra_endpoint(spec.table_or_endpoint)
            self.templates.render_odata_predicate("entra", spec.params)
        elif spec.sub_source == "purview_ual":
            validate_purview_endpoint(spec.table_or_endpoint)
            self.templates.render_purview_filters(spec.params)
        elif spec.sub_source == "log_analytics":
            ws_id = self._resolve_target_id(spec, "default_workspace_id")
            if not ws_id:
                raise TemplateValidationError(
                    "Log Analytics requires `target_id` (workspace GUID) or `default_workspace_id` in .sera/config.toml"
                )
            validate_table_ident(spec.table_or_endpoint)
            self.templates.render_kql_query(
                "log_analytics", spec.table_or_endpoint, "TimeGenerated", s_iso, e_iso, spec.params
            )
        elif spec.sub_source == "defender_hunting":
            validate_table_ident(spec.table_or_endpoint)
            self.templates.render_kql_query(
                "defender_hunting", spec.table_or_endpoint, "Timestamp", s_iso, e_iso, spec.params
            )
        elif spec.sub_source == "defender_timeline":
            validate_machine_id(spec.table_or_endpoint)
            self.templates.render_mde_timeline_params(spec.table_or_endpoint, spec.params)
        elif spec.sub_source == "arm_activity":
            sub_id = self._resolve_target_id(spec, "default_subscription_id")
            if not sub_id:
                raise TemplateValidationError(
                    "ARM Activity Logs require `target_id` (subscription GUID) or `default_subscription_id` in .sera/config.toml"
                )
            validate_arm_endpoint(spec.table_or_endpoint)
            self.templates.render_odata_predicate("arm_activity", spec.params)

    def check_auth_status(self, profile: str = "default") -> dict[str, Any]:
        return self.auth.check_status(profile=profile)

    async def fetch_slice(
        self,
        job_id: str,
        spec: JobSpec,
        slice_start: datetime,
        slice_end: datetime,
        http: SeraHttpClient,
    ) -> SliceResult:
        if spec.sub_source == "entra":
            return await fetch_entra_slice(job_id, spec, slice_start, slice_end, self.auth, http, self.templates)
        if spec.sub_source == "purview_ual":
            return await fetch_purview_ual_slice(
                job_id, spec, slice_start, slice_end, self.auth, http, self.templates
            )
        if spec.sub_source == "log_analytics":
            ws_id = self._resolve_target_id(spec, "default_workspace_id")
            return await fetch_log_analytics_slice(
                job_id, spec, slice_start, slice_end, ws_id, self.auth, http, self.templates
            )
        if spec.sub_source == "defender_hunting":
            return await fetch_defender_hunting_slice(
                job_id, spec, slice_start, slice_end, self.auth, http, self.templates
            )
        if spec.sub_source == "defender_timeline":
            return await fetch_defender_timeline_slice(
                job_id, spec, slice_start, slice_end, self.auth, http, self.templates
            )
        if spec.sub_source == "arm_activity":
            sub_id = self._resolve_target_id(spec, "default_subscription_id")
            return await fetch_arm_activity_slice(
                job_id, spec, slice_start, slice_end, sub_id, self.auth, http, self.templates
            )
        raise KeyError(f"Unsupported Microsoft sub_source '{spec.sub_source}'")
