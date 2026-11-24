"""Plugin-agnostic Rich + Typer CLI for SERA (100% MCP parity, zero hardcoded vendor/sink imports)."""

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
from sera.config import DestinationConfig, load_workspace_config, save_workspace_config
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
auth_app = typer.Typer(help="Manage workspace-isolated source plugin authentication in .sera/creds/")
dest_app = typer.Typer(help="Configure destination sink plugins in .sera/config.toml")
app.add_typer(auth_app, name="auth")
app.add_typer(dest_app, name="destination")


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
    dest_name: str = typer.Option("default", "--dest-name", help="Destination profile name in .sera/config.toml"),
    dest_type: str = typer.Option(..., "--dest-type", "-t", help="Destination plugin type (e.g. bigquery, jsonl, http)"),
    dest_opt: Optional[list[str]] = typer.Option(
        None,
        "--dest-opt",
        "-o",
        help="Destination plugin option as KEY=VALUE (repeatable; missing required options prompt interactively)",
    ),
    dest_options_json: str = typer.Option("{}", "--dest-options-json", help="Destination plugin options as JSON object"),
    source_default: Optional[list[str]] = typer.Option(
        None,
        "--source-default",
        help="Optional source default as SOURCE.KEY=VALUE (e.g. microsoft.default_workspace_id=..., microsoft.proxy_url=...)",
    ),
    skip_uv: bool = typer.Option(False, "--skip-uv", help="Skip upfront `uv pip install` sync"),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON output"),
) -> None:
    """Initialize `<workspace>/.sera/` using discovered source & destination plugins and sync `uv` dependencies."""
    ws = _ws(workspace)
    dst_reg = DestinationRegistry()
    src_reg = SourceRegistry()

    try:
        sink_cls = dst_reg.get_class(dest_type.strip())
    except KeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1)

    opts = json.loads(dest_options_json)
    if not isinstance(opts, dict):
        raise typer.BadParameter("--dest-options-json must decode to a JSON object")
    opts.update(_parse_kv_pairs(dest_opt))

    # Prompt dynamically for any required options declared on the chosen destination plugin
    for spec in sink_cls.option_specs():
        if spec.required and not str(opts.get(spec.name, "")).strip():
            opts[spec.name] = typer.prompt(
                f"{spec.description} ({spec.name})",
                hide_input=spec.secret,
            ).strip()

    src_defaults_map: dict[str, dict[str, Any]] = {}
    for entry in source_default or []:
        if "=" not in entry or "." not in entry.split("=", 1)[0]:
            raise typer.BadParameter(f"--source-default requires SOURCE.KEY=VALUE, got '{entry}'")
        lhs, rhs = entry.split("=", 1)
        sname, skey = lhs.split(".", 1)
        src_defaults_map.setdefault(sname.strip(), {})[skey.strip()] = rhs.strip()

    result = initialize_workspace(
        ws,
        destination_type=dest_type.strip(),
        destination_name=dest_name.strip(),
        destination_options=opts,
        source_defaults=src_defaults_map,
        sync_uv_deps=not skip_uv,
        source_registry=src_reg,
        destination_registry=dst_reg,
    )
    if as_json:
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
        return

    console.print(
        Panel.fit(
            f"[bold green]Initialized SERA workspace[/bold green]\n"
            f"Workspace:   [cyan]{result['workspace_dir']}[/cyan]\n"
            f"Config:      [cyan]{result['config_path']}[/cyan]\n"
            f"Database:    [cyan]{result['sqlite_path']}[/cyan]\n"
            f"Destination: [bold]{dest_name}[/bold] ({dest_type})\n"
            f"uv Upfront Sync: {result['uv'].get('synced')}",
            title=__app_name__,
        )
    )


@dest_app.command("types")
def cmd_dest_types(as_json: bool = typer.Option(False, "--json")) -> None:
    """List all discovered destination sink plugins and their configurable options."""
    reg = DestinationRegistry()
    payload = {
        t: [
            {"name": s.name, "required": s.required, "default": s.default, "description": s.description}
            for s in reg.get_class(t).option_specs()
        ]
        for t in reg.types()
    }
    if as_json:
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return

    for t, specs in payload.items():
        tbl = Table(title=f"Destination Plugin: {t}")
        tbl.add_column("Option", style="cyan")
        tbl.add_column("Required")
        tbl.add_column("Default")
        tbl.add_column("Description")
        for s in specs:
            tbl.add_row(s["name"], "yes" if s["required"] else "no", json.dumps(s["default"]), s["description"])
        console.print(tbl)


@dest_app.command("add")
def cmd_dest_add(
    name: str = typer.Argument(..., help="Destination profile name"),
    dest_type: str = typer.Option(..., "--type", "-t", help="Discovered destination plugin type"),
    opt: Optional[list[str]] = typer.Option(None, "--opt", "-o", help="Option as KEY=VALUE (repeatable)"),
    options_json: str = typer.Option("{}", "--options-json", help="JSON object of destination options"),
    set_default: bool = typer.Option(False, "--set-default", help="Make this destination the workspace default"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Add or update a destination sink profile in `.sera/config.toml`."""
    ws = _ws(workspace)
    cfg = load_workspace_config(ws)
    opts = json.loads(options_json)
    if not isinstance(opts, dict):
        raise typer.BadParameter("--options-json must decode to a JSON object")
    opts.update(_parse_kv_pairs(opt))

    svc = SeraService(ws)
    sink_cls = svc.destinations.get_class(dest_type.strip())
    for spec in sink_cls.option_specs():
        if spec.required and not str(opts.get(spec.name, "")).strip():
            opts[spec.name] = typer.prompt(f"{spec.description} ({spec.name})", hide_input=spec.secret).strip()

    cfg.destinations[name] = DestinationConfig(
        name=name,
        type=dest_type.strip(),
        options=sink_cls.apply_defaults(opts),
    )
    if set_default:
        cfg.default_destination = name
    sink = svc.destinations.create(cfg.destinations[name])
    save_workspace_config(ws, cfg)
    console.print(
        f"[green]Saved destination '[bold]{name}[/bold]' ({dest_type}) -> {sink.describe_target()}[/green]"
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

    tbl = Table(title=f"SERA Destinations (default: {info['default_destination']})")
    tbl.add_column("Name", style="cyan", no_wrap=True)
    tbl.add_column("Type", style="magenta")
    tbl.add_column("Default")
    tbl.add_column("Configuration Summary")
    for dname, summary in info["configured"].items():
        is_def = "yes" if dname == info["default_destination"] else ""
        tbl.add_row(dname, summary["type"], is_def, json.dumps(summary))
    console.print(tbl)


@auth_app.command("modes")
def cmd_auth_modes(
    source: str = typer.Argument("", help="Optional source plugin name"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List authentication modes and required fields declared by discovered source plugins."""
    reg = SourceRegistry()
    target_names = [source] if source else reg.names()
    out: dict[str, Any] = {}
    for sname in target_names:
        cls = reg.get_class(sname)
        out[sname] = {
            m: {
                "description": spec.description,
                "fields": [
                    {"name": f.name, "required": f.required, "secret": f.secret, "default": f.default, "description": f.description}
                    for f in spec.fields
                ],
            }
            for m, spec in cls.auth_modes().items()
        }
    if as_json:
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return

    for sname, modes in out.items():
        tbl = Table(title=f"Auth Modes for Source Plugin: {sname}")
        tbl.add_column("Mode", style="cyan")
        tbl.add_column("Fields")
        tbl.add_column("Description")
        for m, mdata in modes.items():
            f_str = ", ".join(
                f"{f['name']}{'*' if f['required'] else ''}" for f in mdata["fields"]
            )
            tbl.add_row(m, f_str, mdata["description"])
        console.print(tbl)


@auth_app.command("add")
def cmd_auth_add(
    source: str = typer.Argument(..., help="Discovered source plugin name (e.g. microsoft)"),
    mode: str = typer.Option(..., "--mode", "-m", help="Plugin auth mode (run `sera auth modes` to inspect)"),
    profile: str = typer.Option("default", "--profile", "-p", help="Profile alias inside .sera/creds/"),
    opt: Optional[list[str]] = typer.Option(
        None,
        "--opt",
        "-o",
        help="Credential field as KEY=VALUE (repeatable; missing required fields prompt hidden/interactively)",
    ),
    options_json: str = typer.Option("{}", "--options-json", help="Credential fields as JSON object"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Configure workspace-isolated credentials for any source plugin (never enters LLM chat)."""
    ws = _ws(workspace)
    svc = SeraService(ws)
    connector = svc.get_connector(source.strip())
    modes = connector.auth_modes()
    if mode not in modes:
        console.print(f"[red]Unknown mode '{mode}' for source '{source}'. Valid: {', '.join(sorted(modes))}[/red]")
        raise typer.Exit(code=1)

    raw_vals = json.loads(options_json)
    if not isinstance(raw_vals, dict):
        raise typer.BadParameter("--options-json must decode to a JSON object")
    raw_vals.update(_parse_kv_pairs(opt))
    values: dict[str, str] = {str(k): str(v) for k, v in raw_vals.items()}

    for fspec in modes[mode].fields:
        if not values.get(fspec.name, "").strip():
            if fspec.required:
                values[fspec.name] = typer.prompt(
                    f"{fspec.description} ({fspec.name})",
                    default=fspec.default or None,
                    hide_input=fspec.secret,
                ).strip()
            elif fspec.default:
                values[fspec.name] = fspec.default

    receipt = svc.configure_source_auth(
        source_name=source.strip(),
        profile=profile.strip(),
        mode=mode.strip(),
        values=values,
        on_message=lambda msg: console.print(Panel(msg, title=f"{source} Authentication")),
    )
    if as_json:
        sys.stdout.write(json.dumps(receipt, indent=2) + "\n")
    else:
        console.print(
            f"[green]Configured [bold]{source}[/bold] profile '[bold]{profile}[/bold]' (mode={receipt['auth_mode']}).[/green]"
        )


@auth_app.command("status")
def cmd_auth_status(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Display authentication readiness across source plugins without exposing secrets."""
    svc = SeraService(_ws(workspace))
    sources = svc.list_sources()
    if as_json:
        sys.stdout.write(json.dumps(sources, indent=2) + "\n")
        return

    tbl = Table(title="SERA Source Plugin Authentication Status")
    tbl.add_column("Source", style="cyan")
    tbl.add_column("Profile", style="bold")
    tbl.add_column("Configured")
    tbl.add_column("Auth Mode")
    tbl.add_column("Details")
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
    source: str = typer.Option(..., "--source", help="Registered source plugin name (e.g. microsoft)"),
    sub_source: str = typer.Option(..., "--sub-source", help="Plugin sub_source identifier"),
    target: str = typer.Option(..., "--target", "--table", help="Endpoint, table, index, or host identifier"),
    start_time: str = typer.Option(..., "--start", help="UTC start ISO-8601 timestamp"),
    end_time: str = typer.Option(..., "--end", help="UTC end ISO-8601 timestamp"),
    params_json: str = typer.Option("{}", "--params", help="Optional JSON object of typed filter parameters"),
    profile: str = typer.Option("default", "--profile", "-p", help="Auth profile name"),
    target_id: str = typer.Option("", "--target-id", help="Optional container/tenant resource ID"),
    destination: str = typer.Option("", "--destination", "-d", help="Destination override name"),
    chunk_hours: Optional[float] = typer.Option(None, "--chunk-hours", help="Override initial slice duration in hours"),
    background: bool = typer.Option(False, "--background", "-b", help="Submit non-blocking background worker and return job_id immediately"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Submit and execute a forensic extraction job (foreground Rich progress or `--background`)."""
    ws = _ws(workspace)
    params = json.loads(params_json)
    if not isinstance(params, dict):
        raise typer.BadParameter("--params must decode to a JSON object")

    svc = SeraService(ws)
    spec = JobSpec(
        source=source.strip(),
        sub_source=sub_source.strip(),
        table_or_endpoint=target.strip(),
        start_time=start_time.strip(),
        end_time=end_time.strip(),
        template="canonical",
        params=params,
        profile=profile.strip(),
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
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Check recent extraction jobs and uploaded event totals (mirrors MCP `jobs`)."""
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
