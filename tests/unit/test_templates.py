"""Unit tests for the `microsoft` plugin's canonical full-event query template engine."""

from __future__ import annotations

import pytest

from sera.core.template_primitives import TemplateValidationError
from sera.sources.microsoft.templates import MicrosoftTemplateEngine


def test_canonical_odata_template_escapes_values_and_expands_or_disjunctions() -> None:
    reg = MicrosoftTemplateEngine()
    assert reg.render_odata_predicate("entra", {}) == ""

    pred = reg.render_odata_predicate(
        "entra",
        {"in_list": {"userPrincipalName": ["alice@contoso.com", "bob.o'brien@contoso.com"]}},
    )
    assert pred == "(userPrincipalName eq 'alice@contoso.com' or userPrincipalName eq 'bob.o''brien@contoso.com')"

    # Attempt to inject $select or query operators via field identifier
    with pytest.raises(TemplateValidationError):
        reg.render_odata_predicate(
            "entra",
            {"equals": {"userPrincipalName eq 'a'&$select=id": "alice@contoso.com"}},
        )


def test_canonical_kql_template_preserves_pipes_inside_string_values_and_blocks_column_injection() -> None:
    reg = MicrosoftTemplateEngine()
    kql = reg.render_kql_query(
        sub_source="defender_hunting",
        table_name="DeviceProcessEvents",
        time_column="Timestamp",
        start_iso="2026-11-20T00:00:00Z",
        end_iso="2026-11-21T00:00:00Z",
        params={
            "equals": {"FileName": "cmd.exe"},
            "contains": {"ProcessCommandLine": "whoami | findstr admin"},
            "in_list": {"DeviceName": ["wkstn-01", "wkstn-02"]},
        },
    )
    assert 'table("DeviceProcessEvents")' in kql
    assert '| where FileName == "cmd.exe"' in kql
    assert '| where tostring(ProcessCommandLine) contains "whoami | findstr admin"' in kql
    assert '| where DeviceName in~ (dynamic(["wkstn-01", "wkstn-02"]))' in kql
    assert "summarize" not in kql
    assert "project" not in kql

    with pytest.raises(TemplateValidationError):
        reg.render_kql_query(
            sub_source="log_analytics",
            table_name="SigninLogs | project IPAddress",
            time_column="TimeGenerated",
            start_iso="2026-11-20T00:00:00Z",
            end_iso="2026-11-21T00:00:00Z",
            params={},
        )

    with pytest.raises(TemplateValidationError):
        reg.render_kql_query(
            sub_source="log_analytics",
            table_name="SigninLogs",
            time_column="TimeGenerated",
            start_iso="2026-11-20T00:00:00Z",
            end_iso="2026-11-21T00:00:00Z",
            params={"equals": {"UserPrincipalName | summarize count()": "a@b.com"}},
        )


def test_purview_arm_strict_filter_rules_and_mde_timeline_validation() -> None:
    reg = MicrosoftTemplateEngine()
    for sub in ("entra", "purview_ual", "log_analytics", "defender_hunting", "defender_timeline", "arm_activity"):
        specs = reg.list_templates(sub_source=sub)
        assert len(specs) == 1
        assert specs[0]["sub_source"] == sub

    purview = reg.render_purview_filters(
        {
            "users": ["admin@contoso.com"],
            "ips": ["203.0.113.5"],
            "operations": ["FileDownloaded"],
            "administrative_unit_ids": ["au-1"],
        },
    )
    assert purview == {
        "userPrincipalNameFilters": ["admin@contoso.com"],
        "ipAddressFilters": ["203.0.113.5"],
        "operationFilters": ["FileDownloaded"],
        "administrativeUnitIdFilters": ["au-1"],
    }

    # ARM strictly allows at most ONE of resourceGroupName, resourceUri, resourceProvider, correlationId
    assert (
        reg.render_odata_predicate("arm_activity", {"equals": {"resourceGroupName": "rg-prod"}})
        == "resourceGroupName eq 'rg-prod'"
    )
    with pytest.raises(TemplateValidationError):
        reg.render_odata_predicate("arm_activity", {"equals": {"caller": "ops@contoso.com"}})
    with pytest.raises(TemplateValidationError):
        reg.render_odata_predicate(
            "arm_activity",
            {"equals": {"resourceGroupName": "rg-prod", "resourceProvider": "Microsoft.Compute"}},
        )

    machine_id, opts = reg.render_mde_timeline_params(
        "0123456789abcdef0123456789abcdef01234567",
        {"action_types": ["ProcessCreated"], "search_text": "powershell"},
    )
    assert machine_id == "0123456789abcdef0123456789abcdef01234567"
    assert opts == {"action_types": ["ProcessCreated"], "search_text": "powershell"}
