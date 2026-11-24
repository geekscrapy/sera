"""Engagement workspace configuration loader and serializer (`<workspace>/.sera/config.toml`)."""

from __future__ import annotations

import json
import tomllib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DOT_SERA_DIRNAME = ".sera"


@dataclass
class NetworkConfig:
    """HTTP client timeout, retry, and optional plugin-scoped proxy/TLS settings."""

    proxy_url: str = ""
    ca_bundle: str = ""
    verify_tls: bool = True
    timeout_seconds: float = 120.0
    max_retries: int = 5


@dataclass
class SourceProfileConfig:
    """Configured source profile (`microsoft`, `splunk`, etc.) and its non-secret source options."""

    name: str
    type: str
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class DestinationConfig:
    """Configured destination profile (`bigquery`, `jsonl`, `http`, or custom plugin) and its non-secret options."""

    name: str
    type: str
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkspaceConfig:
    """Top-level configuration stored in `<workspace>/.sera/config.toml`."""

    workspace_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    default_source: str = ""
    default_destination: str = ""
    batch_size: int = 5000
    network: NetworkConfig = field(default_factory=NetworkConfig)
    sources: dict[str, SourceProfileConfig] = field(default_factory=dict)
    destinations: dict[str, DestinationConfig] = field(default_factory=dict)
    source_defaults: dict[str, dict[str, Any]] = field(default_factory=dict)

    def get_source_profile(self, name_or_type: str = "", profile: str = "default") -> SourceProfileConfig | None:
        if profile in self.sources:
            src_prof = self.sources[profile]
            if not name_or_type or src_prof.type == name_or_type or src_prof.name == name_or_type:
                return src_prof
        if name_or_type in self.sources:
            return self.sources[name_or_type]
        if not name_or_type and self.default_source and self.default_source in self.sources:
            return self.sources[self.default_source]
        return None

    def get_destination(self, name: str = "") -> DestinationConfig:
        if not self.destinations:
            raise KeyError(
                "No destination configured in .sera/config.toml. Run `sera dest add <type>` first."
            )
        target = name or self.default_destination
        if not target and len(self.destinations) == 1:
            target = next(iter(self.destinations))
        if target not in self.destinations:
            available = ", ".join(sorted(self.destinations)) or "<none>"
            raise KeyError(
                f"Destination '{target}' is not configured in .sera/config.toml (available: {available}). "
                f"Run `sera dest add <type>` to add one."
            )
        return self.destinations[target]


def sera_dir_for_workspace(workspace_dir: Path) -> Path:
    return workspace_dir.resolve() / DOT_SERA_DIRNAME


def _toml_val(val: Any) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        return json.dumps(val)
    if isinstance(val, (list, tuple)):
        return "[" + ", ".join(_toml_val(item) for item in val) + "]"
    raise TypeError(f"Unsupported TOML scalar/list value: {type(val)!r}")


def _append_profile_section(lines: list[str], prefix: str, prof_name: str, prof_type: str, options: dict[str, Any]) -> None:
    lines.append(f"[{prefix}.{prof_name}]")
    lines.append(f"type = {_toml_val(prof_type)}")
    nested_dicts: list[tuple[str, dict[str, Any]]] = []
    for k, v in sorted(options.items()):
        if v is None:
            continue
        if isinstance(v, dict):
            nested_dicts.append((k, v))
        else:
            lines.append(f"{k} = {_toml_val(v)}")
    lines.append("")
    for sub_key, sub_map in nested_dicts:
        lines.append(f"[{prefix}.{prof_name}.{sub_key}]")
        for mk, mv in sorted(sub_map.items()):
            if mv is not None:
                lines.append(f"{mk} = {_toml_val(mv)}")
        lines.append("")


def dump_config_toml(cfg: WorkspaceConfig) -> str:
    """Serialize WorkspaceConfig to human-readable TOML without external writer deps."""
    lines: list[str] = [
        "# SERA — Secure Extraction for Response Agents (Workspace Configuration)",
        f"workspace_uuid = {_toml_val(cfg.workspace_uuid)}",
        f"default_source = {_toml_val(cfg.default_source)}",
        f"default_destination = {_toml_val(cfg.default_destination)}",
        f"batch_size = {_toml_val(cfg.batch_size)}",
        "",
        "[network]",
        f"timeout_seconds = {_toml_val(cfg.network.timeout_seconds)}",
        f"max_retries = {_toml_val(cfg.network.max_retries)}",
        "",
    ]

    for sname, sprof in sorted(cfg.sources.items()):
        _append_profile_section(lines, "sources", sname, sprof.type, sprof.options)

    for source_type, defaults in sorted(cfg.source_defaults.items()):
        if source_type in cfg.sources:
            continue
        lines.append(f"[source_defaults.{source_type}]")
        for k, v in sorted(defaults.items()):
            if v is not None:
                lines.append(f"{k} = {_toml_val(v)}")
        lines.append("")

    for dest_name, dest in sorted(cfg.destinations.items()):
        _append_profile_section(lines, "destinations", dest_name, dest.type, dest.options)

    return "\n".join(lines).rstrip() + "\n"


def load_workspace_config(workspace_dir: Path) -> WorkspaceConfig:
    """Load `<workspace>/.sera/config.toml`."""
    cfg_path = sera_dir_for_workspace(workspace_dir) / "config.toml"
    if not cfg_path.exists():
        raise FileNotFoundError(
            f"SERA is not initialized in '{workspace_dir}'. Run `sera init` first."
        )
    raw = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    net_raw = raw.get("network", {})
    network = NetworkConfig(
        proxy_url=str(net_raw.get("proxy_url", "")),
        ca_bundle=str(net_raw.get("ca_bundle", "")),
        verify_tls=bool(net_raw.get("verify_tls", True)),
        timeout_seconds=float(net_raw.get("timeout_seconds", 120.0)),
        max_retries=int(net_raw.get("max_retries", 5)),
    )

    sources: dict[str, SourceProfileConfig] = {}
    source_defaults: dict[str, dict[str, Any]] = {}
    for src_name, src_raw in raw.get("sources", {}).items():
        if not isinstance(src_raw, dict):
            continue
        if "type" in src_raw:
            opts = {k: v for k, v in src_raw.items() if k != "type"}
            sources[src_name] = SourceProfileConfig(
                name=src_name,
                type=str(src_raw.get("type", "")),
                options=opts,
            )
        else:
            source_defaults[src_name] = dict(src_raw)

    for src_type, sdef_raw in raw.get("source_defaults", {}).items():
        if isinstance(sdef_raw, dict):
            source_defaults[src_type] = dict(sdef_raw)

    destinations: dict[str, DestinationConfig] = {}
    for dest_name, dest_raw in raw.get("destinations", {}).items():
        if not isinstance(dest_raw, dict):
            continue
        opts = {k: v for k, v in dest_raw.items() if k != "type"}
        destinations[dest_name] = DestinationConfig(
            name=dest_name,
            type=str(dest_raw.get("type", "")),
            options=opts,
        )

    return WorkspaceConfig(
        workspace_uuid=str(raw.get("workspace_uuid", str(uuid.uuid4()))),
        default_source=str(raw.get("default_source", "")),
        default_destination=str(raw.get("default_destination", "")),
        batch_size=int(raw.get("batch_size", 5000)),
        network=network,
        sources=sources,
        destinations=destinations,
        source_defaults=source_defaults,
    )


def save_workspace_config(workspace_dir: Path, cfg: WorkspaceConfig) -> Path:
    """Write `<workspace>/.sera/config.toml`."""
    sdir = sera_dir_for_workspace(workspace_dir)
    sdir.mkdir(parents=True, exist_ok=True)
    cfg_path = sdir / "config.toml"
    cfg_path.write_text(dump_config_toml(cfg), encoding="utf-8")
    return cfg_path
