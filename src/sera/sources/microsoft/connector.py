"""Unified `microsoft` source connector routing across all 6 DFIR telemetry surfaces."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sera.config import WorkspaceConfig
from sera.core.http_client import SeraHttpClient
from sera.core.models import JobSpec, SliceResult
from sera.core.templates import (
    TemplateRegistry,
    TemplateValidationError,
    validate_machine_id,
    validate_table_ident,
)
from sera.sources.base import BaseSourceConnector
from sera.sources.microsoft.arm_activity import fetch_arm_activity_slice, validate_arm_endpoint
from sera.sources.microsoft.auth import MicrosoftAuthManager
from sera.sources.microsoft.defender_hunting import fetch_defender_hunting_slice
from sera.sources.microsoft.defender_timeline import fetch_defender_timeline_slice
from sera.sources.microsoft.entra import ENTRA_ENDPOINTS, fetch_entra_slice, validate_entra_endpoint
from sera.sources.microsoft.log_analytics import fetch_log_analytics_slice
from sera.sources.microsoft.purview_ual import fetch_purview_ual_slice, validate_purview_endpoint


SUB_SOURCE_SPECS: dict[str, dict[str, Any]] = {
    "entra": {
        "description": "Microsoft Entra ID Audit, Sign-In, Provisioning, and Risk Detections via MS Graph.",
        "endpoints": sorted(ENTRA_ENDPOINTS),
        "default_chunk_hours": 24,
        "auth": "msal (service_principal_secret | service_principal_cert | delegated)",
    },
    "purview_ual": {
        "description": "M365 Purview Unified Audit Log via async MS Graph `/security/auditLog/queries` (up to 1M records/slice).",
        "endpoints": ["auditLogRecords"],
        "default_chunk_hours": 24,
        "auth": "msal (AuditLogsQuery.Read.All)",
    },
    "log_analytics": {
        "description": "Azure Monitor Log Analytics & Microsoft Sentinel workspace tables via KQL templates.",
        "endpoints": ["<Any Log Analytics / Sentinel table name, e.g. SigninLogs, SecurityEvent>"],
        "requires_target_id": "Log Analytics Workspace GUID (or default_workspace_id in config.toml)",
        "default_chunk_hours": 24,
        "auth": "msal (Log Analytics Reader)",
    },
    "defender_hunting": {
        "description": "Microsoft Defender XDR Advanced Hunting tables (30-day KQL retention).",
        "endpoints": ["<Any XDR table, e.g. DeviceProcessEvents, EmailEvents, IdentityLogonEvents>"],
        "default_chunk_hours": 24,
        "auth": "msal (ThreatHunting.Read.All)",
    },
    "defender_timeline": {
        "description": "Microsoft Defender for Endpoint 180-Day Host Timeline (`table_or_endpoint` = machine_id).",
        "endpoints": ["<MDE 40-hex MachineId / DeviceId>"],
        "default_chunk_hours": 168,  # 7 days
        "auth": "portal_session (sccauth Cookie + X-XSRF-TOKEN)",
    },
    "arm_activity": {
        "description": "Azure Subscription ARM Activity Logs (`management.azure.com`, up to 90-day lookback).",
        "endpoints": ["management"],
        "requires_target_id": "Azure Subscription GUID (or default_subscription_id in config.toml)",
        "default_chunk_hours": 168,  # 7 days
        "auth": "msal (Reader on Subscription)",
    },
}


class MicrosoftSourceConnector(BaseSourceConnector):
    """Routes validated jobs across all 6 Microsoft/Azure DFIR surfaces."""

    source_name = "microsoft"

    def __init__(self, workspace_dir: Path, config: WorkspaceConfig) -> None:
        super().__init__(workspace_dir, config)
        self.auth = MicrosoftAuthManager(workspace_dir=workspace_dir, network=config.network)

    def supported_sub_sources(self) -> dict[str, dict[str, Any]]:
        return SUB_SOURCE_SPECS

    def default_chunk_duration(self, sub_source: str) -> timedelta:
        if sub_source not in SUB_SOURCE_SPECS:
            raise KeyError(f"Unsupported Microsoft sub_source '{sub_source}'")
        return timedelta(hours=float(SUB_SOURCE_SPECS[sub_source]["default_chunk_hours"]))

    def _resolve_target_id(self, spec: JobSpec, default_key: str) -> str:
        if spec.target_id.strip():
            return spec.target_id.strip()
        ms_defaults = self.config.source_defaults.get("microsoft", {})
        return str(ms_defaults.get(default_key, "")).strip()

    def validate_job_spec(self, spec: JobSpec, templates: TemplateRegistry) -> None:
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
            templates.render_odata_predicate("entra", spec.params)
        elif spec.sub_source == "purview_ual":
            validate_purview_endpoint(spec.table_or_endpoint)
            templates.render_purview_filters(spec.params)
        elif spec.sub_source == "log_analytics":
            ws_id = self._resolve_target_id(spec, "default_workspace_id")
            if not ws_id:
                raise TemplateValidationError(
                    "Log Analytics requires `target_id` (workspace GUID) or `default_workspace_id` in .sera/config.toml"
                )
            validate_table_ident(spec.table_or_endpoint)
            templates.render_kql_query(
                "log_analytics", spec.table_or_endpoint, "TimeGenerated", s_iso, e_iso, spec.params
            )
        elif spec.sub_source == "defender_hunting":
            validate_table_ident(spec.table_or_endpoint)
            templates.render_kql_query(
                "defender_hunting", spec.table_or_endpoint, "Timestamp", s_iso, e_iso, spec.params
            )
        elif spec.sub_source == "defender_timeline":
            validate_machine_id(spec.table_or_endpoint)
            templates.render_mde_timeline_params(spec.table_or_endpoint, spec.params)
        elif spec.sub_source == "arm_activity":
            sub_id = self._resolve_target_id(spec, "default_subscription_id")
            if not sub_id:
                raise TemplateValidationError(
                    "ARM Activity Logs require `target_id` (subscription GUID) or `default_subscription_id` in .sera/config.toml"
                )
            validate_arm_endpoint(spec.table_or_endpoint)
            templates.render_odata_predicate("arm_activity", spec.params)

    def check_auth_status(self, profile: str = "default") -> dict[str, Any]:
        return self.auth.check_status(profile=profile)

    async def fetch_slice(
        self,
        job_id: str,
        spec: JobSpec,
        slice_start: datetime,
        slice_end: datetime,
        http: SeraHttpClient,
        templates: TemplateRegistry,
    ) -> SliceResult:
        if spec.sub_source == "entra":
            return await fetch_entra_slice(job_id, spec, slice_start, slice_end, self.auth, http, templates)
        if spec.sub_source == "purview_ual":
            return await fetch_purview_ual_slice(
                job_id, spec, slice_start, slice_end, self.auth, http, templates
            )
        if spec.sub_source == "log_analytics":
            ws_id = self._resolve_target_id(spec, "default_workspace_id")
            return await fetch_log_analytics_slice(
                job_id, spec, slice_start, slice_end, ws_id, self.auth, http, templates
            )
        if spec.sub_source == "defender_hunting":
            return await fetch_defender_hunting_slice(
                job_id, spec, slice_start, slice_end, self.auth, http, templates
            )
        if spec.sub_source == "defender_timeline":
            return await fetch_defender_timeline_slice(
                job_id, spec, slice_start, slice_end, self.auth, http, templates
            )
        if spec.sub_source == "arm_activity":
            sub_id = self._resolve_target_id(spec, "default_subscription_id")
            return await fetch_arm_activity_slice(
                job_id, spec, slice_start, slice_end, sub_id, self.auth, http, templates
            )
        raise KeyError(f"Unsupported Microsoft sub_source '{spec.sub_source}'")
