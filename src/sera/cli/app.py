"""SERA Rich + Typer CLI — primary human interface with 100% MCP parity."""

from __future__ import annotations

import asyncio
import json
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
from sera.plugin_packager import build_plugin_release
from sera.service import SeraService, initialize_workspace
from sera.sources.microsoft.auth import DEFAULT_GRAPH_POWERSHELL_CLIENT_ID, MicrosoftAuthManager


console = Console()
app = typer.Typer(
    name="sera",
    help=f"{__app_name__} (v{__version__})",
    no_args_is_help=True,
    add_completion=False,
)
auth_app = typer.Typer(help="Manage workspace-isolated authentication profiles in .sera/creds/")
dest_app = typer.Typer(help="Configure customizable destination sinks in .sera/config.toml")
app.add_typer(auth_app, name="auth")
app.add_typer(dest_app, name="destination")


def _ws(workspace: Optional[Path]) -> Path:
    return workspace.resolve() if workspace else Path.cwd().resolve()


@app.command("version")
def cmd_version() -> None:
    """Print SERA version."""
    console.print(f"[bold cyan]{__app_name__}[/bold cyan] v{__version__}")


@app.command("init")
def cmd_init(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w", help="Engagement workspace directory"),
    dest_name: str = typer.Option("default", "--dest-name", help="Default destination profile name"),
    dest_type: str = typer.Option("bigquery", "--dest-type", help="Destination type: bigquery | jsonl | http"),
    bq_project: str = typer.Option("", "--bq-project", help="GCP CASE project_id (when dest-type=bigquery)"),
    bq_dataset: str = typer.Option("sera_raw", "--bq-dataset", help="BigQuery dataset_id"),
    bq_events_table: str = typer.Option("events", "--bq-events-table", help="BigQuery events table name"),
    bq_jobs_table: str = typer.Option("collection_jobs", "--bq-jobs-table", help="BigQuery jobs summary table name"),
    bq_location: str = typer.Option("US", "--bq-location", help="BigQuery dataset location"),
    bq_credentials_file: str = typer.Option("", "--bq-credentials", help="Optional GCP SA JSON key path"),
    output_dir: str = typer.Option("", "--output-dir", help="External target directory (when dest-type=jsonl)"),
    http_url: str = typer.Option("", "--http-url", help="Target HTTPS ingest URL (when dest-type=http)"),
    http_format: str = typer.Option("ndjson", "--http-format", help="HTTP payload format: ndjson | json_array | splunk_hec"),
    proxy: str = typer.Option("", "--proxy", help="Optional HTTP/HTTPS/SOCKS5 proxy URL"),
    ca_bundle: str = typer.Option("", "--ca-bundle", help="Optional custom CA certificate PEM path"),
    default_workspace_id: str = typer.Option("", "--law-workspace-id", help="Default Log Analytics workspace GUID"),
    default_subscription_id: str = typer.Option("", "--subscription-id", help="Default Azure subscription GUID"),
    skip_uv: bool = typer.Option(False, "--skip-uv", help="Skip upfront `uv pip install` sync"),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON output"),
) -> None:
    """Initialize `<workspace>/.sera/` and ensure all upfront libraries are installed in `.venv` via `uv`."""
    ws = _ws(workspace)
    opts: dict[str, Any] = {}
    if dest_type == "bigquery":
        project = bq_project.strip() or typer.prompt("GCP CASE project_id for BigQuery")
        opts = {
            "project_id": project.strip(),
            "dataset_id": bq_dataset.strip(),
            "events_table": bq_events_table.strip(),
            "jobs_table": bq_jobs_table.strip(),
            "location": bq_location.strip(),
            "partition_field": "event_timestamp",
            "cluster_fields": ["source", "sub_source", "table_or_endpoint"],
        }
        if bq_credentials_file.strip():
            opts["credentials_file"] = bq_credentials_file.strip()
    elif dest_type == "jsonl":
        target_out = output_dir.strip() or typer.prompt("External JSONL output directory")
        opts = {"output_dir": target_out.strip()}
    elif dest_type == "http":
        url = http_url.strip() or typer.prompt("HTTPS ingest endpoint URL")
        opts = {"url": url.strip(), "format": http_format.strip()}
    else:
        console.print(f"[red]Unsupported --dest-type '{dest_type}'. Expected bigquery, jsonl, or http.[/red]")
        raise typer.Exit(code=1)

    result = initialize_workspace(
        ws,
        destination_name=dest_name,
        destination_type=dest_type,
        destination_options=opts,
        proxy_url=proxy,
        ca_bundle=ca_bundle,
        default_workspace_id=default_workspace_id,
        default_subscription_id=default_subscription_id,
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
            f"Default Destination: [bold]{dest_name}[/bold] ({dest_type})\n"
            f"uv Upfront Sync: {result['uv'].get('synced')}",
            title=__app_name__,
        )
    )


@dest_app.command("add")
def cmd_dest_add(
    name: str = typer.Argument(..., help="Destination profile name (e.g. case_bq, archive_jsonl, siem_hec)"),
    dest_type: str = typer.Option("bigquery", "--type", "-t", help="bigquery | jsonl | http"),
    options_json: str = typer.Option("{}", "--options-json", help="JSON object of destination options"),
    set_default: bool = typer.Option(False, "--set-default", help="Make this destination the workspace default"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Add or update a customizable destination profile in `.sera/config.toml`."""
    ws = _ws(workspace)
    cfg = load_workspace_config(ws)
    opts = json.loads(options_json)
    if not isinstance(opts, dict):
        raise typer.BadParameter("--options-json must decode to a JSON object")
    cfg.destinations[name] = DestinationConfig(name=name, type=dest_type.strip(), options=opts)
    if set_default:
        cfg.default_destination = name
    # Validate instantiation immediately
    svc = SeraService(ws)
    svc.config = cfg
    sink = svc.destinations.create(cfg.destinations[name], cfg.network)
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
    """List configured destinations and target coordinates (mirrors MCP `list_destinations`)."""
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


@auth_app.command("add")
def cmd_auth_add(
    source: str = typer.Argument(..., help="Source connector: microsoft | microsoft-portal"),
    profile: str = typer.Option("default", "--profile", "-p", help="Profile alias inside .sera/creds/"),
    mode: str = typer.Option(
        "secret",
        "--mode",
        "-m",
        help="For microsoft: secret | cert | device-code | browser | static-bearer",
    ),
    tenant_id: str = typer.Option("", "--tenant-id", help="Entra ID tenant GUID or domain"),
    client_id: str = typer.Option("", "--client-id", help="App Registration client_id"),
    client_secret: str = typer.Option("", "--client-secret", help="Client secret (prompted hidden if omitted)"),
    private_key_path: str = typer.Option("", "--private-key-path", help="PEM private key path (when mode=cert)"),
    thumbprint: str = typer.Option("", "--thumbprint", help="Certificate SHA-1 thumbprint (when mode=cert)"),
    access_token: str = typer.Option("", "--access-token", help="Bearer token (when mode=static-bearer)"),
    cookie: str = typer.Option("", "--cookie", help="MDE portal Cookie header containing sccauth"),
    xsrf_token: str = typer.Option("", "--xsrf-token", help="MDE portal X-XSRF-TOKEN header"),
    portal_url: str = typer.Option("https://security.microsoft.com", "--portal-url"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Configure workspace-isolated authentication in `<workspace>/.sera/creds/` (never enters LLM chat)."""
    ws = _ws(workspace)
    svc = SeraService(ws)
    mgr = MicrosoftAuthManager(ws, svc.config.network)

    if source == "microsoft-portal":
        ck = cookie.strip() or typer.prompt("MDE Portal Cookie header (sccauth=...)", hide_input=True)
        xs = xsrf_token.strip() or typer.prompt("MDE Portal X-XSRF-TOKEN", hide_input=True)
        path = mgr.save_profile(
            profile,
            {
                "auth_mode": "portal_session",
                "tenant_id": tenant_id.strip(),
                "cookie": ck,
                "xsrf_token": xs,
                "base_url": portal_url.strip(),
            },
        )
        svc.db.upsert_auth_profile("microsoft", profile, "portal_session", tenant_id=tenant_id.strip())
        console.print(f"[green]Saved MDE 180-day portal session profile '[bold]{profile}[/bold]' -> {path}[/green]")
        return

    if source != "microsoft":
        console.print(f"[red]Unsupported source '{source}'. Expected 'microsoft' or 'microsoft-portal'.[/red]")
        raise typer.Exit(code=1)

    if mode == "static-bearer":
        tok = access_token.strip() or typer.prompt("Bearer access_token", hide_input=True)
        path = mgr.save_profile(profile, {"auth_mode": "static_bearer", "tenant_id": tenant_id.strip(), "access_token": tok})
        svc.db.upsert_auth_profile("microsoft", profile, "static_bearer", tenant_id=tenant_id.strip())
        console.print(f"[green]Saved static bearer profile '[bold]{profile}[/bold]' -> {path}[/green]")
        return

    tid = tenant_id.strip() or typer.prompt("Microsoft Tenant ID")
    if mode == "secret":
        cid = client_id.strip() or typer.prompt("App Registration Client ID")
        sec = client_secret.strip() or typer.prompt("App Registration Client Secret", hide_input=True)
        path = mgr.save_profile(
            profile,
            {
                "auth_mode": "service_principal_secret",
                "tenant_id": tid,
                "client_id": cid,
                "client_secret": sec,
            },
        )
        svc.db.upsert_auth_profile("microsoft", profile, "service_principal_secret", tenant_id=tid, client_id=cid)
        console.print(f"[green]Saved Service Principal (secret) profile '[bold]{profile}[/bold]' -> {path}[/green]")
    elif mode == "cert":
        cid = client_id.strip() or typer.prompt("App Registration Client ID")
        kp = private_key_path.strip() or typer.prompt("PEM Private Key file path")
        tp = thumbprint.strip() or typer.prompt("Certificate SHA-1 Thumbprint")
        path = mgr.save_profile(
            profile,
            {
                "auth_mode": "service_principal_cert",
                "tenant_id": tid,
                "client_id": cid,
                "private_key_path": kp,
                "thumbprint": tp,
            },
        )
        svc.db.upsert_auth_profile("microsoft", profile, "service_principal_cert", tenant_id=tid, client_id=cid)
        console.print(f"[green]Saved Service Principal (cert) profile '[bold]{profile}[/bold]' -> {path}[/green]")
    elif mode == "device-code":
        cid = client_id.strip() or DEFAULT_GRAPH_POWERSHELL_CLIENT_ID
        mgr.interactive_device_code_login(
            profile=profile,
            tenant_id=tid,
            client_id=cid,
            on_prompt=lambda msg: console.print(Panel(msg, title="Microsoft Device Login")),
        )
        svc.db.upsert_auth_profile("microsoft", profile, "delegated", tenant_id=tid, client_id=cid)
        console.print(f"[green]Authenticated delegated Device-Code profile '[bold]{profile}[/bold]'.[/green]")
    elif mode == "browser":
        cid = client_id.strip() or DEFAULT_GRAPH_POWERSHELL_CLIENT_ID
        mgr.interactive_browser_login(profile=profile, tenant_id=tid, client_id=cid)
        svc.db.upsert_auth_profile("microsoft", profile, "delegated", tenant_id=tid, client_id=cid)
        console.print(f"[green]Authenticated delegated Browser profile '[bold]{profile}[/bold]'.[/green]")
    else:
        console.print(f"[red]Unsupported --mode '{mode}'.[/red]")
        raise typer.Exit(code=1)


@auth_app.command("status")
def cmd_auth_status(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Display authentication readiness across profiles without exposing secrets."""
    svc = SeraService(_ws(workspace))
    sources = svc.list_sources()
    if as_json:
        sys.stdout.write(json.dumps(sources, indent=2) + "\n")
        return

    tbl = Table(title="SERA Authentication Profiles")
    tbl.add_column("Source", style="cyan")
    tbl.add_column("Profile", style="bold")
    tbl.add_column("Configured")
    tbl.add_column("Auth Mode")
    tbl.add_column("Tenant ID")
    for sname, sdata in sources.items():
        for prof in sdata["profiles"]:
            ok = "[green]yes[/green]" if prof.get("configured") else "[yellow]no[/yellow]"
            tbl.add_row(
                sname,
                str(prof.get("profile", "")),
                ok,
                str(prof.get("auth_mode") or "-"),
                str(prof.get("tenant_id") or "-"),
            )
    console.print(tbl)


@app.command("sources")
def cmd_sources(
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List registered sources, supported `sub_source`s, and auth readiness (mirrors MCP `list_sources`)."""
    svc = SeraService(_ws(workspace))
    data = svc.list_sources()
    if as_json:
        sys.stdout.write(json.dumps(data, indent=2) + "\n")
        return

    for sname, sinfo in data.items():
        tbl = Table(title=f"Source: {sname}")
        tbl.add_column("Sub-Source", style="cyan", no_wrap=True)
        tbl.add_column("Chunk Hours", justify="right")
        tbl.add_column("Auth Requirement")
        tbl.add_column("Description")
        for sub_name, spec in sinfo["sub_sources"].items():
            tbl.add_row(
                sub_name,
                str(spec["default_chunk_hours"]),
                str(spec["auth"]),
                str(spec["description"]),
            )
        console.print(tbl)


@app.command("templates")
def cmd_templates(
    sub_source: str = typer.Option("", "--sub-source", "-s", help="Filter templates by sub_source"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List allowlisted parameterized query templates (mirrors MCP `list_templates`)."""
    svc = SeraService(_ws(workspace))
    items = svc.list_templates(sub_source=sub_source.strip())
    if as_json:
        sys.stdout.write(json.dumps(items, indent=2) + "\n")
        return

    tbl = Table(title="SERA Canonical Query Template Per Sub-Source")
    tbl.add_column("Sub-Source", style="cyan", no_wrap=True)
    tbl.add_column("Dialect", style="magenta")
    tbl.add_column("Allowed Filter Params")
    tbl.add_column("Canonical Full-Event Template")
    for item in items:
        tbl.add_row(
            item["sub_source"],
            item["dialect"],
            json.dumps(item["params"]) if item["params"] else "{}",
            item["template_preview"],
        )
    console.print(tbl)


@app.command("collect")
def cmd_collect(
    source: str = typer.Option("microsoft", "--source", help="Source connector name"),
    sub_source: str = typer.Option(..., "--sub-source", help="Sub-source (entra, purview_ual, log_analytics, defender_hunting, defender_timeline, arm_activity)"),
    target: str = typer.Option(..., "--target", "--table", help="Endpoint, table name, or MDE machine_id"),
    start_time: str = typer.Option(..., "--start", help="UTC start ISO-8601 timestamp"),
    end_time: str = typer.Option(..., "--end", help="UTC end ISO-8601 timestamp"),
    params_json: str = typer.Option("{}", "--params", help="Optional JSON object of typed filter parameters"),
    profile: str = typer.Option("default", "--profile", "-p", help="Auth profile name"),
    target_id: str = typer.Option("", "--target-id", help="Workspace GUID (LAW) or Subscription GUID (ARM)"),
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
    """Check recent extraction jobs and uploaded event totals (mirrors MCP `check_jobs`)."""
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
    job_id: str = typer.Argument(..., help="Job ID returned by collect / submit_job"),
    slices: bool = typer.Option(False, "--slices", help="Include per-slice interval breakdown"),
    workspace: Optional[Path] = typer.Option(None, "--workspace", "-w"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Inspect detailed progress or final summary for a single `job_id` (mirrors MCP `check_jobs(job_id)`)."""
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
    """Resume uncommitted slices of an interrupted/failed job (mirrors MCP `resume_job`)."""
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
