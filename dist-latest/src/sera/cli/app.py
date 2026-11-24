"""Plugin-agnostic Rich + Typer CLI for SERA (1-to-1 MCP parity, symmetric source & dest workflow)."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sera import __app_name__, __version__
from sera.cli.watch import run_job_watcher
from sera.config import load_workspace_config, save_workspace_config
from sera.core.models import JobRecord, JobSpec
from sera.core.registry import DestinationRegistry, SourceRegistry
from sera.plugin_packager import build_plugin_release
from sera.service import SeraService, initialize_workspace


console = Console()
app = typer.Typer(
    name="sera",
    help=f"{__app_name__} (v{__version__})",
    no_args_is_help=True,
    add_completion=False,
)
source_app = typer.Typer(
    help="Configure source plugins (source-specific options like proxies + isolated auth credentials)",
    no_args_is_help=True,
)
dest_app = typer.Typer(
    help="Configure destination sink plugins (sink-specific options like file paths/proxies + isolated auth)",
    no_args_is_help=True,
)
auth_app = typer.Typer(
    help="Inspect or update source plugin authentication profiles in .sera/creds/",
    no_args_is_help=True,
)

app.add_typer(source_app, name="source")
app.add_typer(dest_app, name="dest")
app.add_typer(dest_app, name="destination", hidden=True)
app.add_typer(auth_app, name="auth")


def _ws(workspace: Optional[Path]) -> Path:
    return workspace.resolve() if workspace else Path.cwd().resolve()


def _worker_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    pkg_parent = str(Path(__file__).resolve().parents[2])
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{pkg_parent}{os.pathsep}{existing}" if existing else pkg_parent
    return env


def _parse_kv_pairs(pairs: list[str] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in pairs or []:
        if "=" not in item:
            raise typer.BadParameter(f"Expected KEY=VALUE format, got '{item}'")
        k, raw_v = item.split("=", 1)
        key = k.strip()
        val_str = raw_v.strip()
        if val_str.startswith(("[", "{")):
            try:
                out[key] = json.loads(val_str)
                continue
            except json.JSONDecodeError:
                pass
        out[key] = val_str
    return out


@app.command("version")
def cmd_version() -> None:
    """Print SERA version."""
    console.print(f"[bold cyan]{__app_name__}[/bold cyan] v{__version__}")


@app.command("init")
def cmd_init(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Engagement workspace directory"),
    batch_size: int = typer.Option(5000, "--batch-size", help="Events per encrypted spool batch"),
    skip_uv: bool = typer.Option(False, "--skip-uv", help="Skip upfront `uv pip install` sync into active `.venv`"),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON output"),
) -> None:
    """Initialize `<workspace>/.sera/` (`config.toml`, `sera.sqlite`, `creds/`, `spool/`) and sync active `.venv` deps."""
    ws = _ws(workspace)
    result = initialize_workspace(
        ws,
        batch_size=batch_size,
        sync_uv_deps=not skip_uv,
    )
    if as_json:
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
        return

    console.print(
        Panel.fit(
            f"[bold green]Initialized SERA workspace[/bold green]\n"
            f"Workspace: [cyan]{result['workspace_dir']}[/cyan]\n"
            f"Config:    [cyan]{result['config_path']}[/cyan]\n"
            f"Database:  [cyan]{result['sqlite_path']}[/cyan]\n"
            f"uv `.venv` Sync: {result['uv'].get('synced')}\n\n"
            f"[bold]Next steps:[/bold]\n"
            f"  1. Add a source & auth:      [cyan]sera source add <type>[/cyan]  (inspect via `sera source types`)\n"
            f"  2. Add a destination & auth: [cyan]sera dest add <type>[/cyan]    (inspect via `sera dest types`)",
            title=__app_name__,
        )
    )


# ──────────────────────────────────────────────────────────────────────────────
# `sera source ...` — Symmetric Source Configuration & Auth
# ──────────────────────────────────────────────────────────────────────────────


@source_app.command("types")
def cmd_source_types(
    source_type: str = typer.Argument("", help="Optional source plugin name to inspect"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List discovered source plugin types, source options (e.g. proxies), and auth modes."""
    reg = SourceRegistry()
    names = [source_type] if source_type else reg.names()
    out: dict[str, Any] = {}
    for sname in names:
        cls = reg.get_class(sname)
        out[sname] = {
            "options": [
                {"name": o.name, "required": o.required, "default": o.default, "description": o.description}
                for o in cls.option_specs()
            ],
            "auth_modes": {
                m: {
                    "description": spec.description,
                    "fields": [
                        {
                            "name": f.name,
                            "required": f.required,
                            "secret": f.secret,
                            "default": f.default,
                            "description": f.description,
                        }
                        for f in spec.fields
                    ],
                }
                for m, spec in cls.auth_modes().items()
            },
        }
    if as_json:
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return

    for sname, info in out.items():
        opt_tbl = Table(title=f"Source Plugin '{sname}' — Source Options (`--opt KEY=VALUE`)")
        opt_tbl.add_column("Option", style="cyan")
        opt_tbl.add_column("Required")
        opt_tbl.add_column("Default")
        opt_tbl.add_column("Description")
        for o in info["options"]:
            opt_tbl.add_row(o["name"], "yes" if o["required"] else "no", json.dumps(o["default"]), o["description"])
        if info["options"]:
            console.print(opt_tbl)

        auth_tbl = Table(title=f"Source Plugin '{sname}' — Auth Modes (`--auth-mode <mode>`)")
        auth_tbl.add_column("Auth Mode", style="magenta")
        auth_tbl.add_column("Fields")
        auth_tbl.add_column("Description")
        for m, mdata in info["auth_modes"].items():
            f_str = ", ".join(f"{f['name']}{'*' if f['required'] else ''}" for f in mdata["fields"]) or "(none)"
            auth_tbl.add_row(m, f_str, mdata["description"])
        console.print(auth_tbl)


@source_app.command("add")
def cmd_source_add(
    source_type: str = typer.Argument(..., help="Discovered source plugin type (e.g. microsoft)"),
    name: str = typer.Option("default", "--name", "--profile", "-p", help="Source profile name"),
    auth_mode: str = typer.Option("", "--auth-mode", "--mode", "-m", help="Source authentication mode"),
    opt: Optional[list[str]] = typer.Option(
        None,
        "--opt",
        "-o",
        help="Source option or auth field as KEY=VALUE (repeatable; missing required fields prompt interactively)",
    ),
    options_json: str = typer.Option("{}", "--options-json", help="Source options and auth fields as JSON object"),
    set_default: bool = typer.Option(False, "--set-default", help="Make this source profile the workspace default"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Add or update a source profile with source-specific options (e.g. proxy) and auth credentials."""
    ws = _ws(workspace)
    svc = SeraService(ws)
    stype = source_type.strip()
    src_cls = svc.sources.get_class(stype)
    modes = src_cls.auth_modes()

    chosen_mode = auth_mode.strip()
    if not chosen_mode:
        if len(modes) == 1:
            chosen_mode = next(iter(modes))
        else:
            chosen_mode = typer.prompt(
                f"Authentication mode for '{stype}' ({', '.join(sorted(modes))})"
            ).strip()
    if chosen_mode not in modes:
        console.print(f"[red]Unknown auth mode '{chosen_mode}' for '{stype}'. Valid: {', '.join(sorted(modes))}[/red]")
        raise typer.Exit(code=1)

    combined = json.loads(options_json)
    if not isinstance(combined, dict):
        raise typer.BadParameter("--options-json must decode to a JSON object")
    combined.update(_parse_kv_pairs(opt))

    opt_specs = {s.name: s for s in src_cls.option_specs()}
    source_opts: dict[str, Any] = {}
    for sname_opt, spec in opt_specs.items():
        if sname_opt in combined:
            source_opts[sname_opt] = combined[sname_opt]
        elif spec.required:
            source_opts[sname_opt] = typer.prompt(f"{spec.description} ({spec.name})").strip()

    auth_vals: dict[str, str] = {
        str(k): str(v) for k, v in combined.items() if k not in opt_specs or k in {"proxy_url", "ca_bundle"}
    }
    for fspec in modes[chosen_mode].fields:
        if fspec.name in opt_specs and fspec.name in source_opts:
            auth_vals[fspec.name] = str(source_opts[fspec.name])
            continue
        if not auth_vals.get(fspec.name, "").strip():
            if fspec.required:
                auth_vals[fspec.name] = typer.prompt(
                    f"{fspec.description} ({fspec.name})",
                    default=fspec.default or None,
                    hide_input=fspec.secret,
                ).strip()
            elif fspec.default:
                auth_vals[fspec.name] = fspec.default

    receipt = svc.add_source(
        source_type=stype,
        profile=name.strip(),
        auth_mode=chosen_mode,
        source_options=source_opts,
        auth_values=auth_vals,
        set_default=set_default,
        on_message=lambda msg: console.print(Panel(msg, title=f"{stype} Authentication")),
    )
    if as_json:
        sys.stdout.write(json.dumps(receipt, indent=2) + "\n")
    else:
        console.print(
            f"[green]Configured source '[bold]{receipt['profile']}[/bold]' ({stype}, auth={receipt['auth_mode']}).[/green]"
        )


@source_app.command("set-default")
def cmd_source_set_default(
    name: str = typer.Argument(..., help="Configured source profile name"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Set the default source profile in `.sera/config.toml`."""
    ws = _ws(workspace)
    cfg = load_workspace_config(ws)
    if name not in cfg.sources:
        available = ", ".join(sorted(cfg.sources)) or "<none>"
        console.print(f"[red]Source profile '{name}' not found (available: {available})[/red]")
        raise typer.Exit(code=1)
    cfg.default_source = name
    save_workspace_config(ws, cfg)
    console.print(f"[green]Default source updated to '[bold]{name}[/bold]'.[/green]")


@source_app.command("list")
def cmd_source_list(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List configured source profiles, options, and authentication readiness."""
    cmd_auth_status(workspace=workspace, as_json=as_json)


# ──────────────────────────────────────────────────────────────────────────────
# `sera dest ...` — Symmetric Destination Configuration & Auth
# ──────────────────────────────────────────────────────────────────────────────


@dest_app.command("types")
def cmd_dest_types(
    dest_type: str = typer.Argument("", help="Optional destination plugin type to inspect"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List discovered destination sink plugin types, options, and auth modes."""
    reg = DestinationRegistry()
    types = [dest_type] if dest_type else reg.types()
    out: dict[str, Any] = {}
    for dtype in types:
        cls = reg.get_class(dtype)
        out[dtype] = {
            "options": [
                {
                    "name": s.name,
                    "required": s.required,
                    "default": s.default,
                    "secret": s.secret,
                    "description": s.description,
                }
                for s in cls.option_specs()
            ],
            "auth_modes": {
                m: {
                    "description": spec.description,
                    "fields": [
                        {
                            "name": f.name,
                            "required": f.required,
                            "secret": f.secret,
                            "default": f.default,
                            "description": f.description,
                        }
                        for f in spec.fields
                    ],
                }
                for m, spec in cls.auth_modes().items()
            },
        }
    if as_json:
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return

    for dtype, info in out.items():
        tbl = Table(title=f"Destination Plugin '{dtype}' — Options (`--opt KEY=VALUE`)")
        tbl.add_column("Option", style="cyan")
        tbl.add_column("Required")
        tbl.add_column("Default")
        tbl.add_column("Description")
        for s in info["options"]:
            tbl.add_row(s["name"], "yes" if s["required"] else "no", json.dumps(s["default"]), s["description"])
        console.print(tbl)

        auth_tbl = Table(title=f"Destination Plugin '{dtype}' — Auth Modes (`--auth-mode <mode>`)")
        auth_tbl.add_column("Auth Mode", style="magenta")
        auth_tbl.add_column("Fields")
        auth_tbl.add_column("Description")
        for m, mdata in info["auth_modes"].items():
            f_str = ", ".join(f"{f['name']}{'*' if f['required'] else ''}" for f in mdata["fields"]) or "(none)"
            auth_tbl.add_row(m, f_str, mdata["description"])
        console.print(auth_tbl)


@dest_app.command("add")
def cmd_dest_add(
    dest_type: str = typer.Argument(..., help="Discovered destination plugin type (e.g. bigquery, jsonl, http)"),
    name: str = typer.Option("default", "--name", "-n", help="Destination profile name"),
    auth_mode: str = typer.Option("", "--auth-mode", "--mode", "-m", help="Destination authentication mode"),
    opt: Optional[list[str]] = typer.Option(
        None,
        "--opt",
        "-o",
        help="Destination option or auth field as KEY=VALUE (repeatable; missing required fields prompt interactively)",
    ),
    options_json: str = typer.Option("{}", "--options-json", help="Destination options and auth fields as JSON object"),
    set_default: bool = typer.Option(False, "--set-default", help="Make this destination the workspace default"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Add or update a destination sink profile with sink-specific options (file paths, HTTP proxy, dataset) and auth."""
    ws = _ws(workspace)
    svc = SeraService(ws)
    dtype = dest_type.strip()
    sink_cls = svc.destinations.get_class(dtype)
    modes = sink_cls.auth_modes()

    combined = json.loads(options_json)
    if not isinstance(combined, dict):
        raise typer.BadParameter("--options-json must decode to a JSON object")
    combined.update(_parse_kv_pairs(opt))

    chosen_mode = auth_mode.strip() or next(iter(modes))
    if chosen_mode not in modes:
        console.print(f"[red]Unknown auth mode '{chosen_mode}' for '{dtype}'. Valid: {', '.join(sorted(modes))}[/red]")
        raise typer.Exit(code=1)

    opt_specs = {s.name: s for s in sink_cls.option_specs()}
    auth_field_names = {f.name for m in modes.values() for f in m.fields}

    dest_opts: dict[str, Any] = {k: v for k, v in combined.items() if k not in auth_field_names}
    for spec in sink_cls.option_specs():
        if spec.required and not str(dest_opts.get(spec.name, "")).strip():
            dest_opts[spec.name] = typer.prompt(
                f"{spec.description} ({spec.name})",
                hide_input=spec.secret,
            ).strip()

    auth_vals: dict[str, str] = {str(k): str(v) for k, v in combined.items() if k in auth_field_names}
    for fspec in modes[chosen_mode].fields:
        if not auth_vals.get(fspec.name, "").strip():
            if fspec.required:
                auth_vals[fspec.name] = typer.prompt(
                    f"{fspec.description} ({fspec.name})",
                    default=fspec.default or None,
                    hide_input=fspec.secret,
                ).strip()
            elif fspec.default:
                auth_vals[fspec.name] = fspec.default

    receipt = svc.add_destination(
        dest_type=dtype,
        name=name.strip(),
        auth_mode=chosen_mode,
        dest_options=dest_opts,
        auth_values=auth_vals,
        set_default=set_default,
    )
    if as_json:
        sys.stdout.write(json.dumps(receipt, indent=2) + "\n")
    else:
        console.print(
            f"[green]Configured destination '[bold]{receipt['name']}[/bold]' ({dtype}, auth={receipt['auth_mode']}) -> {receipt['target']}[/green]"
        )


@dest_app.command("set-default")
def cmd_dest_set_default(
    name: str = typer.Argument(..., help="Existing destination profile name"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Set the default destination profile in `.sera/config.toml`."""
    ws = _ws(workspace)
    cfg = load_workspace_config(ws)
    cfg.get_destination(name)
    cfg.default_destination = name
    save_workspace_config(ws, cfg)
    console.print(f"[green]Default destination updated to '[bold]{name}[/bold]'.[/green]")


@dest_app.command("list")
def cmd_dest_list(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List configured destination profiles and target coordinates."""
    cmd_destinations(workspace=workspace, as_json=as_json)


# ──────────────────────────────────────────────────────────────────────────────
# `sera auth ...` — Compatibility Aliases Over Source Auth
# ──────────────────────────────────────────────────────────────────────────────


@auth_app.command("modes")
def cmd_auth_modes(
    source: str = typer.Argument("", help="Optional source plugin name"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List authentication modes and options declared by discovered source plugins."""
    cmd_source_types(source_type=source, as_json=as_json)


@auth_app.command("add")
def cmd_auth_add(
    source: str = typer.Argument(..., help="Discovered source plugin name (e.g. microsoft)"),
    mode: str = typer.Option(..., "--mode", "--auth-mode", "-m", help="Plugin auth mode"),
    profile: str = typer.Option("default", "--profile", "--name", "-p", help="Profile alias"),
    opt: Optional[list[str]] = typer.Option(None, "--opt", "-o", help="Option or credential field as KEY=VALUE"),
    options_json: str = typer.Option("{}", "--options-json", help="Options as JSON object"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Alias for `sera source add` configuring source options and credentials."""
    cmd_source_add(
        source_type=source,
        name=profile,
        auth_mode=mode,
        opt=opt,
        options_json=options_json,
        set_default=False,
        workspace=workspace,
        as_json=as_json,
    )


@auth_app.command("status")
def cmd_auth_status(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Display configured source profiles, options, and authentication readiness without exposing secrets."""
    svc = SeraService(_ws(workspace))
    sources = svc.list_sources()
    if as_json:
        sys.stdout.write(json.dumps(sources, indent=2) + "\n")
        return

    tbl = Table(title="SERA Configured Sources & Authentication Status")
    tbl.add_column("Source", style="cyan")
    tbl.add_column("Profile", style="bold")
    tbl.add_column("Configured")
    tbl.add_column("Auth Mode")
    tbl.add_column("Details & Options")
    for sname, sdata in sources.items():
        for prof in sdata["profiles"]:
            ok = "[green]yes[/green]" if prof.get("configured") else "[yellow]no[/yellow]"
            extra = {k: v for k, v in prof.items() if k not in {"profile", "configured", "auth_mode"}}
            tbl.add_row(
                sname,
                str(prof.get("profile", "")),
                ok,
                str(prof.get("auth_mode") or "-"),
                json.dumps(extra) if extra else "-",
            )
    console.print(tbl)


# ──────────────────────────────────────────────────────────────────────────────
# 1-to-1 Runtime Commands Shared With SERA MCP Server
# ──────────────────────────────────────────────────────────────────────────────


@app.command("destinations")
def cmd_destinations(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List configured destinations and target coordinates (mirrors MCP `destinations`)."""
    svc = SeraService(_ws(workspace))
    info = svc.list_destinations()
    if as_json:
        sys.stdout.write(json.dumps(info, indent=2) + "\n")
        return

    tbl = Table(title=f"SERA Destinations (default: {info['default_destination'] or '<none>'})")
    tbl.add_column("Name", style="cyan", no_wrap=True)
    tbl.add_column("Type", style="magenta")
    tbl.add_column("Default")
    tbl.add_column("Configuration Summary")
    for dname, summary in info["configured"].items():
        is_def = "yes" if dname == info["default_destination"] else ""
        tbl.add_row(dname, summary["type"], is_def, json.dumps(summary))
    console.print(tbl)


@app.command("sources")
def cmd_sources(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List discovered source plugins, supported `sub_source`s, and readiness (mirrors MCP `sources`)."""
    svc = SeraService(_ws(workspace))
    data = svc.list_sources()
    if as_json:
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
        return

    for sname, sinfo in data.items():
        tbl = Table(title=f"Source Plugin: {sname}")
        tbl.add_column("Sub-Source", style="cyan", no_wrap=True)
        tbl.add_column("Chunk Hours", justify="right")
        tbl.add_column("Auth Requirement")
        tbl.add_column("Description")
        for sub_name, spec in sinfo["sub_sources"].items():
            tbl.add_row(
                sub_name,
                str(spec.get("default_chunk_hours", "-")),
                str(spec.get("auth", "-")),
                str(spec.get("description", "")),
            )
        console.print(tbl)


@app.command("templates")
def cmd_templates(
    source: str = typer.Option("", "--source", help="Filter by source plugin name"),
    sub_source: str = typer.Option("", "--sub-source", "-s", help="Filter by sub_source"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List canonical full-event templates from discovered source plugins (mirrors MCP `templates`)."""
    svc = SeraService(_ws(workspace))
    items = svc.list_templates(source=source.strip(), sub_source=sub_source.strip())
    if as_json:
        sys.stdout.write(json.dumps(items, indent=2) + "\n")
        return

    tbl = Table(title="SERA Canonical Query Template Per Sub-Source")
    tbl.add_column("Source/Sub-Source", style="cyan", no_wrap=True)
    tbl.add_column("Dialect", style="magenta")
    tbl.add_column("Allowed Filter Params")
    tbl.add_column("Canonical Full-Event Template")
    for item in items:
        tbl.add_row(
            f"{item.get('source', '')}/{item['sub_source']}",
            item["dialect"],
            json.dumps(item["params"]) if item["params"] else "{}",
            item["template_preview"],
        )
    console.print(tbl)


@app.command("collect")
def cmd_collect(
    source: str = typer.Option("", "--source", help="Source plugin or configured source profile (defaults to workspace default_source)"),
    sub_source: str = typer.Option(..., "--sub-source", help="Plugin sub_source identifier"),
    target: str = typer.Option(..., "--target", "--table", help="Endpoint, table, index, or host identifier"),
    start_time: str = typer.Option(..., "--start", help="UTC start ISO-8601 timestamp"),
    end_time: str = typer.Option(..., "--end", help="UTC end ISO-8601 timestamp"),
    params_json: str = typer.Option("{}", "--params", help="Optional JSON object of typed filter parameters"),
    profile: str = typer.Option("default", "--profile", "-p", help="Source profile name"),
    target_id: str = typer.Option("", "--target-id", help="Optional container/tenant resource ID"),
    destination: str = typer.Option("", "--destination", "-d", help="Destination override name"),
    chunk_hours: Optional[float] = typer.Option(None, "--chunk-hours", help="Override initial slice duration in hours"),
    background: bool = typer.Option(False, "--background", "-b", help="Submit non-blocking background worker and return job_id immediately"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Submit and execute a forensic extraction job (foreground Rich progress or `--background`, mirrors MCP `collect`)."""
    ws = _ws(workspace)
    params = json.loads(params_json)
    if not isinstance(params, dict):
        raise typer.BadParameter("--params must decode to a JSON object")

    svc = SeraService(ws)
    resolved_source, resolved_profile = svc.resolve_source_and_profile(source, profile)
    if not resolved_source:
        raise typer.BadParameter("Pass `--source <name>` or configure a default source with `sera source add <type>`.")

    spec = JobSpec(
        source=resolved_source,
        sub_source=sub_source.strip(),
        table_or_endpoint=target.strip(),
        start_time=start_time.strip(),
        end_time=end_time.strip(),
        template="canonical",
        params=params,
        profile=resolved_profile,
        target_id=target_id.strip(),
        destination=destination.strip(),
        initial_chunk_hours=chunk_hours,
    )
    receipt = svc.enqueue_job(spec)
    job_id = receipt["job_id"]

    if background:
        subprocess.Popen(
            [sys.executable, "-B", "-m", "sera.cli.app", "_worker", job_id, "--workspace", str(ws)],
            env=_worker_env(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        if as_json:
            sys.stdout.write(json.dumps(receipt, indent=2) + "\n")
        else:
            console.print(
                f"[green]Submitted background job [bold]{job_id}[/bold] -> {receipt['destination_target']}[/green]\n"
                f"Lookup: [cyan]{receipt['lookup_hint']}[/cyan]"
            )
        return

    def _progress(rec: JobRecord) -> None:
        if not as_json:
            console.print(
                f"  [dim]{rec.job_id}[/dim] slices completed={rec.slices_completed} split={rec.slices_split} "
                f"uploaded=[bold green]{rec.events_uploaded}[/bold green]"
            )

    final_rec = asyncio.run(svc.execute_enqueued_job(job_id, on_slice_progress=_progress))
    summary = final_rec.to_summary_dict()
    if as_json:
        sys.stdout.write(json.dumps(summary, indent=2) + "\n")
    else:
        console.print(
            Panel.fit(
                f"Job ID:          [bold cyan]{summary['job_id']}[/bold cyan]\n"
                f"Status:          [bold green]{summary['status']}[/bold green]\n"
                f"Destination:     {summary['destination_target']}\n"
                f"Events Fetched:  {summary['events_fetched']}\n"
                f"Events Uploaded: [bold green]{summary['events_uploaded']}[/bold green]\n"
                f"Already Uploaded Skipped: {summary['events_already_uploaded_skipped']}\n"
                f"Slices Completed: {summary['slices']['completed']} (splits: {summary['slices']['split']})",
                title="SERA Extraction Complete",
            )
        )


@app.command("jobs")
def cmd_jobs(
    limit: int = typer.Option(25, "--limit", "-n"),
    watch: bool = typer.Option(False, "--watch", help="Open live Rich job & slice progress monitor"),
    bell: bool = typer.Option(
        False,
        "--bell",
        help="Terminal bell in watch mode: 1 ding on new job, 2 dings on completion, 3 dings on failure",
    ),
    interval: float = typer.Option(0.5, "--interval", "-i", help="Refresh interval in seconds when `--watch` is active"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Check recent extraction jobs and uploaded event totals (mirrors MCP `jobs`; pass `--watch` for live UI)."""
    if watch:
        run_job_watcher(_ws(workspace), bell=bell, interval=interval, console=console)
        return

    svc = SeraService(_ws(workspace))
    data = svc.check_jobs(limit=limit)
    if as_json:
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
        return

    tbl = Table(
        title=f"SERA Jobs (Total Uploaded Events in Workspace: {data['total_uploaded_events_in_workspace']})"
    )
    tbl.add_column("Job ID", style="cyan", no_wrap=True)
    tbl.add_column("Status")
    tbl.add_column("Surface")
    tbl.add_column("Target")
    tbl.add_column("Uploaded", justify="right", style="green")
    tbl.add_column("Slices (Done/Split)", justify="right")
    tbl.add_column("Destination")
    for j in data["jobs"]:
        status_str = j["status"]
        color = {"completed": "green", "running": "yellow", "failed": "red"}.get(status_str, "white")
        tbl.add_row(
            j["job_id"],
            f"[{color}]{status_str}[/{color}]",
            f"{j['source']}/{j['sub_source']}",
            j["table_or_endpoint"],
            str(j["events_uploaded"]),
            f"{j['slices']['completed']}/{j['slices']['split']}",
            j["destination_target"],
        )
    console.print(tbl)


@app.command("watch")
def cmd_watch(
    bell: bool = typer.Option(
        False,
        "--bell",
        help="Ring terminal bell: 1 ding when a job arrives, 2 dings when completed, 3 dings if failed",
    ),
    interval: float = typer.Option(0.5, "--interval", "-i", help="Live poll interval in seconds"),
    show_all: bool = typer.Option(False, "--all", "-a", help="Also show historical completed/failed jobs"),
    max_slices: int = typer.Option(20, "--max-slices", help="Maximum slice sub-tasks shown under each job"),
    exit_when_idle: bool = typer.Option(False, "--exit-when-idle", help="Exit automatically once all active jobs finish"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Engagement workspace directory"),
) -> None:
    """Live Rich interface tracking running jobs and their slice sub-tasks with optional `--bell` alerts."""
    run_job_watcher(
        _ws(workspace),
        bell=bell,
        interval=interval,
        show_all=show_all,
        max_slices_per_job=max_slices,
        exit_when_idle=exit_when_idle,
        console=console,
    )


@app.command("status")
def cmd_status(
    job_id: str = typer.Argument(..., help="Job ID returned by collect"),
    slices: bool = typer.Option(False, "--slices", help="Include per-slice interval breakdown"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Inspect detailed progress or final summary for a single `job_id` (mirrors MCP `status`)."""
    svc = SeraService(_ws(workspace))
    summary = svc.check_jobs(job_id=job_id, include_slices=slices)
    if as_json:
        sys.stdout.write(json.dumps(summary, indent=2) + "\n")
        return

    console.print(Panel.fit(json.dumps(summary, indent=2), title=f"SERA Job {job_id}"))


@app.command("resume")
def cmd_resume(
    job_id: str = typer.Argument(..., help="Interrupted or failed job_id to resume"),
    background: bool = typer.Option(False, "--background", "-b"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Resume uncommitted slices of an interrupted/failed job (mirrors MCP `resume`)."""
    ws = _ws(workspace)
    svc = SeraService(ws)
    rec = svc.prepare_resume(job_id)
    if rec.status.value == "completed":
        msg = {"job_id": job_id, "status": "completed", "events_uploaded": rec.events_uploaded}
        if as_json:
            sys.stdout.write(json.dumps(msg, indent=2) + "\n")
        else:
            console.print(f"[green]Job {job_id} is already completed ({rec.events_uploaded} events uploaded).[/green]")
        return

    if background:
        subprocess.Popen(
            [sys.executable, "-B", "-m", "sera.cli.app", "_worker", job_id, "--workspace", str(ws)],
            env=_worker_env(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        out = {"job_id": job_id, "status": "resuming"}
        if as_json:
            sys.stdout.write(json.dumps(out, indent=2) + "\n")
        else:
            console.print(f"[green]Resuming job [bold]{job_id}[/bold] in background.[/green]")
        return

    final_rec = asyncio.run(svc.execute_enqueued_job(job_id))
    if as_json:
        sys.stdout.write(json.dumps(final_rec.to_summary_dict(), indent=2) + "\n")
    else:
        console.print(
            f"[green]Resumed job [bold]{job_id}[/bold] completed — total uploaded: {final_rec.events_uploaded}[/green]"
        )


@app.command("plugin-build")
def cmd_plugin_build(
    repo_dir: Optional[Path] = typer.Option(
        None,
        "--repo-dir",
        help="SERA git repository root (defaults to package repository root)",
    ),
    version: str = typer.Option(__version__, "--version", help="Plugin release version string"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Build versioned plugin zip in `dist/sera-<version>.zip` and unpacked `dist-latest/`."""
    git_root = repo_dir.resolve() if repo_dir else Path(__file__).resolve().parents[3]
    result = build_plugin_release(git_root, version=version)
    if as_json:
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
        return
    console.print(
        Panel.fit(
            f"Version:     [bold]{result['version']}[/bold]\n"
            f"Unpacked:    [cyan]{result['dist_latest_dir']}[/cyan]\n"
            f"Archive Zip: [cyan]{result['zip_path']}[/cyan]",
            title="SERA Antigravity Plugin Built",
        )
    )


@app.command("_worker", hidden=True)
def cmd_hidden_worker(
    job_id: str = typer.Argument(...),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Internal background worker entrypoint used by `sera collect --background` and `sera resume --background`."""
    svc = SeraService(_ws(workspace))
    try:
        asyncio.run(svc.execute_enqueued_job(job_id))
    except Exception:
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
