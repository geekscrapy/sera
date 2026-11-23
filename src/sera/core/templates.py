"""Allowlisted Parameterized Query Template Engine (zero regex blacklisting).

Every query in SERA is rendered from a registered, strongly-typed template that
always retrieves full events without projection, aggregation, or row caps.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


FIELD_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_./-]{0,127}$")
TABLE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,127}$")
MACHINE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


class TemplateValidationError(ValueError):
    """Raised when template name, field identifiers, or typed parameters are invalid."""


def validate_field_ident(name: str) -> str:
    cleaned = name.strip()
    if not FIELD_IDENT_RE.match(cleaned):
        raise TemplateValidationError(
            f"Invalid field identifier '{name}'. Only alphanumeric, '_', '.', '/', '-' characters are allowed."
        )
    return cleaned


def validate_table_ident(name: str) -> str:
    cleaned = name.strip()
    if not TABLE_IDENT_RE.match(cleaned):
        raise TemplateValidationError(
            f"Invalid table/endpoint identifier '{name}'. Only alphanumeric, '_', '-' characters are allowed."
        )
    return cleaned


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
    ident = validate_field_ident(field_name)
    if not isinstance(values, list) or not values:
        raise TemplateValidationError(f"Parameter list for '{field_name}' must be a non-empty list")
    encoded = ", ".join(odata_literal(v) for v in values)
    return f"{ident} in ({encoded})"


def kql_literal(val: Any) -> str:
    """Safely encode a scalar value as a KQL literal using JSON string encoding."""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        return repr(val)
    if isinstance(val, str):
        # KQL double-quoted string literals follow JSON string escaping rules.
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
class QueryTemplateSpec:
    """Metadata and schema definition for a registered query template."""

    name: str
    dialect: str  # odata | purview | kql | mde_timeline | arm_odata
    description: str
    sub_sources: tuple[str, ...]
    param_schema: dict[str, str] = field(default_factory=dict)
    custom_body: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "dialect": self.dialect,
            "description": self.description,
            "sub_sources": list(self.sub_sources),
            "params": dict(self.param_schema),
            "is_custom": self.custom_body is not None,
        }


BUILTIN_TEMPLATES: tuple[QueryTemplateSpec, ...] = (
    # Universal
    QueryTemplateSpec(
        name="all",
        dialect="universal",
        description="Download 100% of full events within [start_time, end_time) with no extra row filter.",
        sub_sources=("entra", "purview_ual", "log_analytics", "defender_hunting", "defender_timeline", "arm_activity"),
        param_schema={},
    ),
    QueryTemplateSpec(
        name="structured_filter",
        dialect="universal",
        description=(
            "Composable typed filter across any validated field names without raw query strings. "
            "Supports `equals` (dict[field, scalar]), `in_list` (dict[field, list]), "
            "`contains` (dict[field, str]), and `startswith` (dict[field, str])."
        ),
        sub_sources=("entra", "log_analytics", "defender_hunting", "arm_activity"),
        param_schema={
            "equals": "optional dict[field_name, str|int|bool]",
            "in_list": "optional dict[field_name, list[str|int]]",
            "contains": "optional dict[field_name, str]",
            "startswith": "optional dict[field_name, str]",
        },
    ),
    # Entra ID specific convenience templates
    QueryTemplateSpec(
        name="by_user",
        dialect="odata",
        description="Filter Entra events by one or more userPrincipalName or userId values.",
        sub_sources=("entra",),
        param_schema={
            "users": "list[str] of UPNs (e.g. ['alice@contoso.com'])",
            "field": "optional field override (default: 'userPrincipalName')",
        },
    ),
    QueryTemplateSpec(
        name="by_ip",
        dialect="odata",
        description="Filter Entra sign-ins / risk detections by one or more source IP addresses.",
        sub_sources=("entra",),
        param_schema={"ips": "list[str] of IPv4/IPv6 addresses"},
    ),
    QueryTemplateSpec(
        name="by_app",
        dialect="odata",
        description="Filter Entra sign-ins by appId or appDisplayName.",
        sub_sources=("entra",),
        param_schema={
            "app_ids": "optional list[str] of Entra appId GUIDs",
            "app_names": "optional list[str] of appDisplayName strings",
        },
    ),
    QueryTemplateSpec(
        name="risky_only",
        dialect="odata",
        description="Filter Entra sign-ins or risk detections where riskLevelDuringSignIn / riskLevel is elevated.",
        sub_sources=("entra",),
        param_schema={"levels": "optional list[str] (default: ['low', 'medium', 'high'])"},
    ),
    # Purview UAL
    QueryTemplateSpec(
        name="ual_scope",
        dialect="purview",
        description="Scoped M365 Purview Unified Audit Log search using native server-side filter arrays.",
        sub_sources=("purview_ual",),
        param_schema={
            "users": "optional list[str] -> userPrincipalNameFilters",
            "ips": "optional list[str] -> ipAddressFilters",
            "operations": "optional list[str] -> operationFilters",
            "services": "optional list[str] -> serviceFilters (e.g. ['Exchange', 'SharePoint', 'AzureActiveDirectory'])",
            "record_types": "optional list[str] -> recordTypeFilters",
            "object_ids": "optional list[str] -> objectIdFilters",
            "keyword": "optional str -> keywordFilter",
        },
    ),
    # KQL (Log Analytics / Sentinel & Defender Hunting)
    QueryTemplateSpec(
        name="by_actor",
        dialect="kql",
        description="Filter a KQL table where an actor/account column matches one or more identities (case-insensitive).",
        sub_sources=("log_analytics", "defender_hunting"),
        param_schema={
            "actors": "list[str] of UPNs / account names",
            "column": "optional str column name (default: 'UserPrincipalName')",
        },
    ),
    QueryTemplateSpec(
        name="by_host",
        dialect="kql",
        description="Filter a KQL table by one or more host/device names or DeviceId values (case-insensitive).",
        sub_sources=("log_analytics", "defender_hunting"),
        param_schema={
            "hosts": "list[str] of hostnames or device IDs",
            "column": "optional str column name (default: 'DeviceName')",
        },
    ),
    QueryTemplateSpec(
        name="by_ip_kql",
        dialect="kql",
        description="Filter a KQL table by one or more IP addresses on a specified IP column.",
        sub_sources=("log_analytics", "defender_hunting"),
        param_schema={
            "ips": "list[str] of IP addresses",
            "column": "optional str column name (default: 'IPAddress')",
        },
    ),
    # MDE 180-Day Host Timeline
    QueryTemplateSpec(
        name="machine_timeline",
        dialect="mde_timeline",
        description="Download 180-day MDE host timeline events for a machine_id (`table_or_endpoint`), optionally scoped by action_types or search_text.",
        sub_sources=("defender_timeline",),
        param_schema={
            "action_types": "optional list[str] of MDE ActionType names",
            "search_text": "optional str server-side search filter",
        },
    ),
    # Azure ARM Activity Logs
    QueryTemplateSpec(
        name="by_caller",
        dialect="arm_odata",
        description="Filter Azure Subscription ARM Activity Logs by caller UPN / service principal objectId.",
        sub_sources=("arm_activity",),
        param_schema={"caller": "str UPN or objectId"},
    ),
    QueryTemplateSpec(
        name="by_resource_group",
        dialect="arm_odata",
        description="Filter Azure Subscription ARM Activity Logs by resourceGroupName.",
        sub_sources=("arm_activity",),
        param_schema={"resource_group": "str resourceGroupName"},
    ),
    QueryTemplateSpec(
        name="by_resource_type",
        dialect="arm_odata",
        description="Filter Azure Subscription ARM Activity Logs by resourceProvider / resourceType.",
        sub_sources=("arm_activity",),
        param_schema={"resource_type": "str (e.g. 'Microsoft.Compute/virtualMachines')"},
    ),
)


ARM_ALLOWED_FIELDS = frozenset({"caller", "resourceGroupName", "resourceType", "resourceId", "status"})


class TemplateRegistry:
    """Manages built-in and workspace-custom (`<workspace>/.sera/templates/*.toml`) templates."""

    def __init__(self, custom_templates_dir: Path | None = None) -> None:
        self._templates: dict[str, QueryTemplateSpec] = {t.name: t for t in BUILTIN_TEMPLATES}
        if custom_templates_dir and custom_templates_dir.exists():
            self._load_custom_templates(custom_templates_dir)

    def _load_custom_templates(self, directory: Path) -> None:
        for toml_file in sorted(directory.glob("*.toml")):
            data = tomllib.loads(toml_file.read_text(encoding="utf-8"))
            name = str(data["name"]).strip()
            dialect = str(data["dialect"]).strip()
            if dialect not in {"odata", "kql", "arm_odata"}:
                raise TemplateValidationError(
                    f"Custom template '{name}' in {toml_file.name} has unsupported dialect '{dialect}'"
                )
            body = str(data["predicate_template"]).strip()
            # Ensure custom predicate templates cannot smuggle KQL pipe operators or OData query options
            if dialect == "kql" and "|" in _strip_quoted(body):
                raise TemplateValidationError(
                    f"Custom KQL predicate template '{name}' cannot contain pipe ('|') operators; "
                    "SERA automatically wraps predicates inside full-row `where (...)` clauses."
                )
            if dialect in {"odata", "arm_odata"} and any(tok in body for tok in ("$select", "$top", "&")):
                raise TemplateValidationError(
                    f"Custom OData predicate template '{name}' cannot contain '$select', '$top', or '&'."
                )
            self._templates[name] = QueryTemplateSpec(
                name=name,
                dialect=dialect,
                description=str(data.get("description", f"Custom {dialect} predicate template")),
                sub_sources=tuple(data.get("sub_sources", [])),
                param_schema={str(k): str(v) for k, v in data.get("params", {}).items()},
                custom_body=body,
            )

    def list_templates(self, sub_source: str = "") -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for spec in self._templates.values():
            if sub_source and sub_source not in spec.sub_sources:
                continue
            out.append(spec.to_dict())
        return out

    def get_for_sub_source(self, template_name: str, sub_source: str) -> QueryTemplateSpec:
        if template_name not in self._templates:
            valid = ", ".join(sorted(self._templates))
            raise TemplateValidationError(
                f"Unknown query template '{template_name}'. Available templates: {valid}"
            )
        spec = self._templates[template_name]
        if spec.sub_sources and sub_source not in spec.sub_sources:
            raise TemplateValidationError(
                f"Template '{template_name}' is not valid for sub_source '{sub_source}' "
                f"(supported: {', '.join(spec.sub_sources)})"
            )
        return spec

    def render_odata_predicate(self, template_name: str, sub_source: str, params: dict[str, Any]) -> str:
        """Render a pure OData boolean predicate (without time bounds, which the connector prepends)."""
        spec = self.get_for_sub_source(template_name, sub_source)
        if spec.custom_body is not None:
            return self._render_custom_body(spec, params, literal_fn=odata_literal, list_fn=None)

        if template_name == "all":
            _require_empty_params(template_name, params)
            return ""
        if template_name == "by_user":
            users = _require_non_empty_str_list(params, "users")
            field_name = validate_field_ident(str(params.get("field", "userPrincipalName")))
            return odata_in_list(field_name, users)
        if template_name == "by_ip":
            ips = _require_non_empty_str_list(params, "ips")
            return odata_in_list("ipAddress", ips)
        if template_name == "by_app":
            clauses: list[str] = []
            if params.get("app_ids"):
                clauses.append(odata_in_list("appId", _require_non_empty_str_list(params, "app_ids")))
            if params.get("app_names"):
                clauses.append(
                    odata_in_list("appDisplayName", _require_non_empty_str_list(params, "app_names"))
                )
            if not clauses:
                raise TemplateValidationError("Template 'by_app' requires 'app_ids' and/or 'app_names'")
            return "(" + " or ".join(clauses) + ")"
        if template_name == "risky_only":
            levels = params.get("levels") or ["low", "medium", "high"]
            if not isinstance(levels, list) or not levels:
                raise TemplateValidationError("'levels' must be a non-empty list of strings")
            return odata_in_list("riskLevel", [str(x) for x in levels])
        if template_name == "by_caller":
            caller = _require_str(params, "caller")
            return f"caller eq {odata_literal(caller)}"
        if template_name == "by_resource_group":
            rg = _require_str(params, "resource_group")
            return f"resourceGroupName eq {odata_literal(rg)}"
        if template_name == "by_resource_type":
            rt = _require_str(params, "resource_type")
            return f"resourceType eq {odata_literal(rt)}"
        if template_name == "structured_filter":
            return _render_structured_odata(params, arm_mode=(sub_source == "arm_activity"))

        raise TemplateValidationError(f"Template '{template_name}' cannot render OData for '{sub_source}'")

    def render_purview_filters(self, template_name: str, params: dict[str, Any]) -> dict[str, Any]:
        """Render validated Purview Graph `auditLogQuery` filter payload properties."""
        self.get_for_sub_source(template_name, "purview_ual")
        if template_name == "all":
            _require_empty_params(template_name, params)
            return {}
        if template_name != "ual_scope":
            raise TemplateValidationError(f"Unsupported Purview template '{template_name}'")

        mapping = {
            "users": "userPrincipalNameFilters",
            "ips": "ipAddressFilters",
            "operations": "operationFilters",
            "services": "serviceFilters",
            "record_types": "recordTypeFilters",
            "object_ids": "objectIdFilters",
        }
        allowed_keys = set(mapping) | {"keyword"}
        unknown = set(params) - allowed_keys
        if unknown:
            raise TemplateValidationError(
                f"Unknown parameter(s) for 'ual_scope': {', '.join(sorted(unknown))}"
            )
        payload: dict[str, Any] = {}
        for param_key, api_key in mapping.items():
            if param_key in params and params[param_key] is not None:
                vals = _require_non_empty_str_list(params, param_key)
                payload[api_key] = vals
        if params.get("keyword"):
            payload["keywordFilter"] = _require_str(params, "keyword")
        return payload

    def render_kql_query(
        self,
        template_name: str,
        sub_source: str,
        table_name: str,
        time_column: str,
        start_iso: str,
        end_iso: str,
        params: dict[str, Any],
        include_item_id: bool = False,
    ) -> str:
        """Render a complete, guaranteed full-row KQL query with zero projection/aggregation."""
        spec = self.get_for_sub_source(template_name, sub_source)
        safe_table = validate_table_ident(table_name)
        safe_time_col = validate_field_ident(time_column)

        lines = [
            f"table({kql_literal(safe_table)})",
            f"| where {safe_time_col} >= datetime({kql_literal(start_iso)}) and {safe_time_col} < datetime({kql_literal(end_iso)})",
        ]

        if spec.custom_body is not None:
            pred = self._render_custom_body(spec, params, literal_fn=kql_literal, list_fn=kql_dynamic_list)
            lines.append(f"| where ({pred})")
        elif template_name == "all":
            _require_empty_params(template_name, params)
        elif template_name == "by_actor":
            actors = _require_non_empty_str_list(params, "actors")
            col = validate_field_ident(str(params.get("column", "UserPrincipalName")))
            lines.append(f"| where {col} in~ ({kql_dynamic_list(actors)})")
        elif template_name == "by_host":
            hosts = _require_non_empty_str_list(params, "hosts")
            col = validate_field_ident(str(params.get("column", "DeviceName")))
            lines.append(f"| where {col} in~ ({kql_dynamic_list(hosts)})")
        elif template_name == "by_ip_kql":
            ips = _require_non_empty_str_list(params, "ips")
            col = validate_field_ident(str(params.get("column", "IPAddress")))
            lines.append(f"| where {col} in ({kql_dynamic_list(ips)})")
        elif template_name == "structured_filter":
            lines.extend(_render_structured_kql_clauses(params))
        else:
            raise TemplateValidationError(f"Unsupported KQL template '{template_name}'")

        if include_item_id:
            lines.append('| extend _sera_item_id = tostring(column_ifexists("_ItemId", ""))')

        return "\n".join(lines)

    def render_mde_timeline_params(
        self,
        template_name: str,
        machine_id: str,
        params: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        """Validate machine_id and optional MDE host timeline filter parameters."""
        self.get_for_sub_source(template_name, "defender_timeline")
        safe_machine = validate_machine_id(machine_id)
        if template_name == "all":
            _require_empty_params(template_name, params)
            return safe_machine, {}
        if template_name != "machine_timeline":
            raise TemplateValidationError(f"Unsupported MDE timeline template '{template_name}'")

        allowed = {"action_types", "search_text"}
        unknown = set(params) - allowed
        if unknown:
            raise TemplateValidationError(
                f"Unknown parameter(s) for 'machine_timeline': {', '.join(sorted(unknown))}"
            )
        out: dict[str, Any] = {}
        if params.get("action_types"):
            out["action_types"] = _require_non_empty_str_list(params, "action_types")
        if params.get("search_text"):
            out["search_text"] = _require_str(params, "search_text")
        return safe_machine, out

    @staticmethod
    def _render_custom_body(
        spec: QueryTemplateSpec,
        params: dict[str, Any],
        literal_fn: Any,
        list_fn: Any,
    ) -> str:
        assert spec.custom_body is not None
        placeholders = set(PLACEHOLDER_RE.findall(spec.custom_body))
        missing = placeholders - set(params)
        if missing:
            raise TemplateValidationError(
                f"Missing required parameter(s) for custom template '{spec.name}': {', '.join(sorted(missing))}"
            )

        def _replace(match: re.Match[str]) -> str:
            key = match.group(1)
            val = params[key]
            if isinstance(val, list):
                if list_fn is None:
                    return "(" + ", ".join(literal_fn(x) for x in val) + ")"
                return list_fn(val)
            return literal_fn(val)

        return PLACEHOLDER_RE.sub(_replace, spec.custom_body)


def _strip_quoted(text: str) -> str:
    """Strip single- and double-quoted string literals to inspect structural characters safely."""
    return re.sub(r"""('([^'\\]|\\.)*'|"([^"\\]|\\.)*")""", "''", text)


def _require_empty_params(template_name: str, params: dict[str, Any]) -> None:
    if params:
        raise TemplateValidationError(
            f"Template '{template_name}' does not accept parameters (got: {', '.join(sorted(params))})"
        )


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
            f"Unsupported structured_filter key(s): {', '.join(sorted(unknown))}"
        )
    clauses: list[str] = []

    def _chk_field(fname: str) -> str:
        ident = validate_field_ident(fname)
        if arm_mode and ident not in ARM_ALLOWED_FIELDS:
            raise TemplateValidationError(
                f"ARM Activity Logs only support filtering on {sorted(ARM_ALLOWED_FIELDS)} (got '{ident}')"
            )
        return ident

    for field_name, val in (params.get("equals") or {}).items():
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

    if not clauses:
        raise TemplateValidationError("structured_filter requires at least one non-empty predicate")
    return " and ".join(clauses)


def _render_structured_kql_clauses(params: dict[str, Any]) -> list[str]:
    allowed = {"equals", "in_list", "contains", "startswith"}
    unknown = set(params) - allowed
    if unknown:
        raise TemplateValidationError(
            f"Unsupported structured_filter key(s): {', '.join(sorted(unknown))}"
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
        ident = _chk_ident_kql(field_name)
        if not isinstance(prefix, str) or not prefix:
            raise TemplateValidationError(f"'startswith.{field_name}' must be a non-empty string")
        lines.append(f"| where tostring({ident}) startswith {kql_literal(prefix)}")

    if not lines:
        raise TemplateValidationError("structured_filter requires at least one non-empty predicate")
    return lines


def _chk_ident_kql(field_name: str) -> str:
    return validate_field_ident(field_name)
