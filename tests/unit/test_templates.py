"""Unit tests for SERA's allowlisted Parameterized Query Template Engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from sera.core.templates import TemplateRegistry, TemplateValidationError


def test_odata_templates_escape_values_and_reject_bad_identifiers() -> None:
    reg = TemplateRegistry()
    pred = reg.render_odata_predicate(
        "by_user",
        "entra",
        {"users": ["alice@contoso.com", "bob.o'brien@contoso.com"]},
    )
    assert pred == "userPrincipalName in ('alice@contoso.com', 'bob.o''brien@contoso.com')"

    # Attempt to inject $select or query operators via field identifier
    with pytest.raises(TemplateValidationError):
        reg.render_odata_predicate(
            "by_user",
            "entra",
            {"users": ["alice@contoso.com"], "field": "userPrincipalName eq 'a'&$select=id"},
        )


def test_kql_templates_preserve_pipes_inside_string_values_and_block_column_injection() -> None:
    reg = TemplateRegistry()
    kql = reg.render_kql_query(
        template_name="structured_filter",
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
            template_name="structured_filter",
            sub_source="log_analytics",
            table_name="SigninLogs | project IPAddress",
            time_column="TimeGenerated",
            start_iso="2026-11-20T00:00:00Z",
            end_iso="2026-11-21T00:00:00Z",
            params={"equals": {"UserPrincipalName": "a@b.com"}},
        )

    with pytest.raises(TemplateValidationError):
        reg.render_kql_query(
            template_name="structured_filter",
            sub_source="log_analytics",
            table_name="SigninLogs",
            time_column="TimeGenerated",
            start_iso="2026-11-20T00:00:00Z",
            end_iso="2026-11-21T00:00:00Z",
            params={"equals": {"UserPrincipalName | summarize count()": "a@b.com"}},
        )


def test_purview_arm_and_mde_timeline_template_validation() -> None:
    reg = TemplateRegistry()
    purview = reg.render_purview_filters(
        "ual_scope",
        {"users": ["admin@contoso.com"], "ips": ["203.0.113.5"], "operations": ["FileDownloaded"]},
    )
    assert purview == {
        "userPrincipalNameFilters": ["admin@contoso.com"],
        "ipAddressFilters": ["203.0.113.5"],
        "operationFilters": ["FileDownloaded"],
    }

    # ARM restricts allowed filter fields
    with pytest.raises(TemplateValidationError):
        reg.render_odata_predicate(
            "structured_filter",
            "arm_activity",
            {"equals": {"unsupportedField": "val"}},
        )

    machine_id, opts = reg.render_mde_timeline_params(
        "machine_timeline",
        "0123456789abcdef0123456789abcdef01234567",
        {"action_types": ["ProcessCreated"], "search_text": "powershell"},
    )
    assert machine_id == "0123456789abcdef0123456789abcdef01234567"
    assert opts == {"action_types": ["ProcessCreated"], "search_text": "powershell"}


def test_custom_workspace_toml_templates_allow_predicates_and_reject_pipes(tmp_path: Path) -> None:
    tpl_dir = tmp_path / "templates"
    tpl_dir.mkdir()
    (tpl_dir / "custom_hunt.toml").write_text(
        """
name = "suspicious_logon"
dialect = "kql"
description = "Filter sign-ins by app and error code"
sub_sources = ["log_analytics"]
predicate_template = "AppDisplayName == {{app}} and ResultType in ({{codes}})"

[params]
app = "str"
codes = "list[str]"
""",
        encoding="utf-8",
    )
    reg = TemplateRegistry(tpl_dir)
    rendered = reg.render_kql_query(
        "suspicious_logon",
        "log_analytics",
        "SigninLogs",
        "TimeGenerated",
        "2026-11-01T00:00:00Z",
        "2026-11-02T00:00:00Z",
        {"app": "Azure Portal", "codes": ["50126", "50074"]},
        include_item_id=True,
    )
    assert '| where (AppDisplayName == "Azure Portal" and ResultType in (dynamic(["50126", "50074"])))' in rendered
    assert "_sera_item_id" in rendered

    # Bad custom template trying to smuggle `| summarize`
    (tpl_dir / "bad.toml").write_text(
        """
name = "bad_pipe"
dialect = "kql"
sub_sources = ["log_analytics"]
predicate_template = "true | summarize count()"
""",
        encoding="utf-8",
    )
    with pytest.raises(TemplateValidationError):
        TemplateRegistry(tpl_dir)
