"""Self-contained query templates for the `microsoft` source plugin (OData, Purview, KQL, MDE, ARM)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from sera.core.template_primitives import (
    TemplateValidationError,
    validate_field_ident,
    validate_table_ident,
)


MACHINE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
ARM_ALLOWED_FIELDS = frozenset({"resourceGroupName", "resourceUri", "resourceProvider", "correlationId"})


def validate_machine_id(machine_id: str) -> str:
    cleaned = machine_id.strip()
    if not MACHINE_ID_RE.match(cleaned):
        raise TemplateValidationError(
            f"Invalid MDE machine_id '{machine_id}'. Expected 40-char hex or valid device identifier."
        )
    return cleaned


def odata_literal(val: Any) -> str:
    """Safely encode a scalar value as an OData literal."""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        return repr(val)
    if isinstance(val, str):
        escaped = val.replace("'", "''")
        return f"'{escaped}'"
    raise TemplateValidationError(f"Unsupported OData scalar parameter type: {type(val).__name__}")


def odata_in_list(field_name: str, values: list[Any]) -> str:
    """Expand list membership into `eq` disjunctions supported across all Entra `/auditLogs/*` endpoints."""
    ident = validate_field_ident(field_name)
    if not isinstance(values, list) or not values:
        raise TemplateValidationError(f"Parameter list for '{field_name}' must be a non-empty list")
    if len(values) == 1:
        return f"{ident} eq {odata_literal(values[0])}"
    parts = [f"{ident} eq {odata_literal(v)}" for v in values]
    return "(" + " or ".join(parts) + ")"


def kql_literal(val: Any) -> str:
    """Safely encode a scalar value as a KQL literal using JSON string encoding."""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        return repr(val)
    if isinstance(val, str):
        return json.dumps(val, ensure_ascii=False)
    raise TemplateValidationError(f"Unsupported KQL scalar parameter type: {type(val).__name__}")


def kql_dynamic_list(values: list[Any]) -> str:
    if not isinstance(values, list) or not values:
        raise TemplateValidationError("KQL list parameter must be a non-empty list")
    for item in values:
        if not isinstance(item, (str, int, float, bool)):
            raise TemplateValidationError(f"Unsupported item type in KQL list: {type(item).__name__}")
    return f"dynamic({json.dumps(values, ensure_ascii=False)})"


@dataclass(frozen=True)
class CanonicalTemplateSpec:
    """Describes the single canonical query template and allowed `params` for a Microsoft `sub_source`."""

    sub_source: str
    dialect: str
    template_preview: str
    param_schema: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": "microsoft",
            "sub_source": self.sub_source,
            "dialect": self.dialect,
            "template_preview": self.template_preview,
            "params": dict(self.param_schema),
        }


SURFACE_TEMPLATES: dict[str, CanonicalTemplateSpec] = {
    "entra": CanonicalTemplateSpec(
        sub_source="entra",
        dialect="odata",
        template_preview="$filter=<time_field> ge <start> and <time_field> lt <end>[ and (<typed_predicates>)]",
        param_schema={
            "equals": "optional dict[field_name, str|int|bool]",
            "in_list": "optional dict[field_name, list[str|int]] (e.g. {'userPrincipalName': ['alice@contoso.com']})",
            "contains": "optional dict[field_name, str]",
            "startswith": "optional dict[field_name, str]",
        },
    ),
    "purview_ual": CanonicalTemplateSpec(
        sub_source="purview_ual",
        dialect="purview",
        template_preview="POST /v1.0/security/auditLog/queries {filterStartDateTime, filterEndDateTime, ...optional filters}",
        param_schema={
            "users": "optional list[str] -> userPrincipalNameFilters",
            "ips": "optional list[str] -> ipAddressFilters",
            "operations": "optional list[str] -> operationFilters",
            "services": "optional list[str] -> serviceFilters",
            "record_types": "optional list[str] -> recordTypeFilters",
            "object_ids": "optional list[str] -> objectIdFilters",
            "administrative_unit_ids": "optional list[str] -> administrativeUnitIdFilters",
            "keyword": "optional str -> keywordFilter",
        },
    ),
    "log_analytics": CanonicalTemplateSpec(
        sub_source="log_analytics",
        dialect="kql",
        template_preview='table("<table_name>") | where TimeGenerated >= datetime(<start>) and TimeGenerated < datetime(<end>) [| where ...]',
        param_schema={
            "equals": "optional dict[column, str|int|bool]",
            "in_list": "optional dict[column, list[str|int]] (case-insensitive `in~` for strings)",
            "contains": "optional dict[column, str]",
            "startswith": "optional dict[column, str]",
        },
    ),
    "defender_hunting": CanonicalTemplateSpec(
        sub_source="defender_hunting",
        dialect="kql",
        template_preview='table("<table_name>") | where Timestamp >= datetime(<start>) and Timestamp < datetime(<end>) [| where ...]',
        param_schema={
            "equals": "optional dict[column, str|int|bool]",
            "in_list": "optional dict[column, list[str|int]] (case-insensitive `in~` for strings)",
            "contains": "optional dict[column, str]",
            "startswith": "optional dict[column, str]",
        },
    ),
    "defender_timeline": CanonicalTemplateSpec(
        sub_source="defender_timeline",
        dialect="mde_timeline",
        template_preview="GET /apiproxy/mtp/mdeTimelineExperience/machines/<machine_id>/events?fromDate=<start>&toDate=<end>",
        param_schema={
            "action_types": "optional list[str] of MDE ActionType names",
            "search_text": "optional str server-side search filter",
        },
    ),
    "arm_activity": CanonicalTemplateSpec(
        sub_source="arm_activity",
        dialect="arm_odata",
        template_preview="$filter=eventTimestamp ge '<start>' and eventTimestamp le '<end>'[ and <single_allowed_field> eq '<val>']",
        param_schema={
            "equals": "optional single-entry dict[resourceGroupName|resourceUri|resourceProvider|correlationId, str]",
        },
    ),
}


class MicrosoftTemplateEngine:
    """Renders the single canonical full-event query template for each Microsoft `sub_source`."""

    def list_templates(self, sub_source: str = "") -> list[dict[str, Any]]:
        if sub_source:
            if sub_source not in SURFACE_TEMPLATES:
                raise TemplateValidationError(f"Unknown Microsoft sub_source '{sub_source}'")
            return [SURFACE_TEMPLATES[sub_source].to_dict()]
        return [spec.to_dict() for spec in SURFACE_TEMPLATES.values()]

    def render_odata_predicate(self, sub_source: str, params: dict[str, Any]) -> str:
        if not params:
            return ""
        return _render_structured_odata(params, arm_mode=(sub_source == "arm_activity"))

    def render_purview_filters(self, params: dict[str, Any]) -> dict[str, Any]:
        if not params:
            return {}
        mapping = {
            "users": "userPrincipalNameFilters",
            "ips": "ipAddressFilters",
            "operations": "operationFilters",
            "services": "serviceFilters",
            "record_types": "recordTypeFilters",
            "object_ids": "objectIdFilters",
            "administrative_unit_ids": "administrativeUnitIdFilters",
        }
        allowed_keys = set(mapping) | {"keyword"}
        unknown = set(params) - allowed_keys
        if unknown:
            raise TemplateValidationError(
                f"Unknown Purview UAL filter parameter(s): {', '.join(sorted(unknown))}"
            )
        payload: dict[str, Any] = {}
        for param_key, api_key in mapping.items():
            if param_key in params and params[param_key] is not None:
                payload[api_key] = _require_non_empty_str_list(params, param_key)
        if params.get("keyword"):
            payload["keywordFilter"] = _require_str(params, "keyword")
        return payload

    def render_kql_query(
        self,
        sub_source: str,
        table_name: str,
        time_column: str,
        start_iso: str,
        end_iso: str,
        params: dict[str, Any],
        include_item_id: bool = False,
    ) -> str:
        if sub_source not in {"log_analytics", "defender_hunting"}:
            raise TemplateValidationError(f"Unsupported KQL sub_source '{sub_source}'")
        safe_table = validate_table_ident(table_name)
        safe_time_col = validate_field_ident(time_column)

        lines = [
            f"table({kql_literal(safe_table)})",
            f"| where {safe_time_col} >= datetime({kql_literal(start_iso)}) and {safe_time_col} < datetime({kql_literal(end_iso)})",
        ]
        if params:
            lines.extend(_render_structured_kql_clauses(params))
        if include_item_id:
            lines.append('| extend _sera_item_id = tostring(column_ifexists("_ItemId", ""))')
        return "\n".join(lines)

    def render_mde_timeline_params(
        self,
        machine_id: str,
        params: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        safe_machine = validate_machine_id(machine_id)
        if not params:
            return safe_machine, {}
        allowed = {"action_types", "search_text"}
        unknown = set(params) - allowed
        if unknown:
            raise TemplateValidationError(
                f"Unknown MDE timeline parameter(s): {', '.join(sorted(unknown))}"
            )
        out: dict[str, Any] = {}
        if params.get("action_types"):
            out["action_types"] = _require_non_empty_str_list(params, "action_types")
        if params.get("search_text"):
            out["search_text"] = _require_str(params, "search_text")
        return safe_machine, out


def _require_str(params: dict[str, Any], key: str) -> str:
    val = params.get(key)
    if not isinstance(val, str) or not val.strip():
        raise TemplateValidationError(f"Parameter '{key}' must be a non-empty string")
    return val.strip()


def _require_non_empty_str_list(params: dict[str, Any], key: str) -> list[str]:
    val = params.get(key)
    if not isinstance(val, list) or not val or not all(isinstance(x, str) and x.strip() for x in val):
        raise TemplateValidationError(f"Parameter '{key}' must be a non-empty list of non-empty strings")
    return [x.strip() for x in val]


def _render_structured_odata(params: dict[str, Any], arm_mode: bool = False) -> str:
    allowed = {"equals", "in_list", "contains", "startswith"}
    unknown = set(params) - allowed
    if unknown:
        raise TemplateValidationError(
            f"Unsupported OData filter key(s): {', '.join(sorted(unknown))} (expected: {sorted(allowed)})"
        )
    clauses: list[str] = []

    def _chk_field(fname: str) -> str:
        ident = validate_field_ident(fname)
        if arm_mode and ident not in ARM_ALLOWED_FIELDS:
            raise TemplateValidationError(
                f"ARM Activity Logs only support filtering on {sorted(ARM_ALLOWED_FIELDS)} (got '{ident}')"
            )
        return ident

    eq_map = params.get("equals") or {}
    if arm_mode and len(eq_map) > 1:
        raise TemplateValidationError(
            "ARM Activity Logs REST $filter allows at most ONE additional equality filter "
            "(resourceGroupName, resourceUri, resourceProvider, or correlationId)."
        )
    for field_name, val in eq_map.items():
        ident = _chk_field(field_name)
        clauses.append(f"{ident} eq {odata_literal(val)}")

    if arm_mode and any(params.get(k) for k in ("in_list", "contains", "startswith")):
        raise TemplateValidationError(
            "ARM Activity Logs REST $filter only supports 'equals' predicates on allowed fields."
        )

    for field_name, vals in (params.get("in_list") or {}).items():
        ident = _chk_field(field_name)
        clauses.append(odata_in_list(ident, vals))

    for field_name, sub in (params.get("contains") or {}).items():
        ident = _chk_field(field_name)
        if not isinstance(sub, str) or not sub:
            raise TemplateValidationError(f"'contains.{field_name}' must be a non-empty string")
        clauses.append(f"contains({ident}, {odata_literal(sub)})")

    for field_name, prefix in (params.get("startswith") or {}).items():
        ident = _chk_field(field_name)
        if not isinstance(prefix, str) or not prefix:
            raise TemplateValidationError(f"'startswith.{field_name}' must be a non-empty string")
        clauses.append(f"startswith({ident}, {odata_literal(prefix)})")

    return " and ".join(clauses)


def _render_structured_kql_clauses(params: dict[str, Any]) -> list[str]:
    allowed = {"equals", "in_list", "contains", "startswith"}
    unknown = set(params) - allowed
    if unknown:
        raise TemplateValidationError(
            f"Unsupported KQL filter key(s): {', '.join(sorted(unknown))} (expected: {sorted(allowed)})"
        )
    lines: list[str] = []
    for field_name, val in (params.get("equals") or {}).items():
        ident = validate_field_ident(field_name)
        lines.append(f"| where {ident} == {kql_literal(val)}")

    for field_name, vals in (params.get("in_list") or {}).items():
        ident = validate_field_ident(field_name)
        if not isinstance(vals, list) or not vals:
            raise TemplateValidationError(f"'in_list.{field_name}' must be a non-empty list")
        op = "in~" if all(isinstance(v, str) for v in vals) else "in"
        lines.append(f"| where {ident} {op} ({kql_dynamic_list(vals)})")

    for field_name, sub in (params.get("contains") or {}).items():
        ident = validate_field_ident(field_name)
        if not isinstance(sub, str) or not sub:
            raise TemplateValidationError(f"'contains.{field_name}' must be a non-empty string")
        lines.append(f"| where tostring({ident}) contains {kql_literal(sub)}")

    for field_name, prefix in (params.get("startswith") or {}).items():
        ident = validate_field_ident(field_name)
        if not isinstance(prefix, str) or not prefix:
            raise TemplateValidationError(f"'startswith.{field_name}' must be a non-empty string")
        lines.append(f"| where tostring({ident}) startswith {kql_literal(prefix)}")

    return lines
