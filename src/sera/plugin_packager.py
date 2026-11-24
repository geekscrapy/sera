"""Antigravity Plugin packager producing versioned `dist/sera-<version>.zip` and unpacked `dist-latest/`."""

from __future__ import annotations

import inspect
import json
import os
import shutil
import stat
import zipfile
from pathlib import Path
from typing import Any

from sera import __version__
from sera.hooks import guard_dot_sera
from sera.service import collect_required_uv_packages


SERA_RULE_MD = """# SERA — Secure Extraction for Response Agents (`sera.md`)

When acquiring raw telemetry or forensic logs for an engagement:

1. **Use SERA Exclusively for Log Acquisition**: Submit downloads through SERA's MCP tools (`submit_job`, `check_jobs`, `resume_job`, `list_sources`, `list_destinations`, `list_templates`) or guide the analyst to use the `sera` CLI.
2. **Single Canonical Full-Event Template**: Each `sub_source` uses one fixed canonical full-event template (accepting optional typed filter `params`) so 100% of every event is preserved verbatim without summarization or field projection. Schema sampling is intentionally disabled.
3. **Never Access `.sera/` Directly**: `<workspace>/.sera/` holds engagement credentials, the `sera.sqlite` ledger, and `AES-256-GCM` encrypted spool chunks. Never attempt to read, modify, or delete `.sera/` via file or shell tools.
4. **Never Ask for Secrets in Chat**: Authentication (MSAL Service Principal, Interactive/Device-Code, or MDE Portal Session cookies) must always be configured out-of-band by the analyst via `sera auth add ...`.
5. **Concise User Communication**: Give the user crisp summaries and exact next-step setup commands; handle template selection, typed parameter construction, and job tracking under the hood.
"""

SERA_SKILL_MD = """---
name: sera
description: >-
  SERA (Secure Extraction for Response Agents) — forensic-grade log acquisition plugin and workflow guide.
  Activate whenever the user asks what SERA or this plugin does, asks how to set up or use SERA, or wants
  to extract/download/upload telemetry logs (Microsoft Entra ID, Purview M365 UAL, Log Analytics/Sentinel,
  Defender XDR Hunting, Defender 180-day Host Timeline, Azure ARM Activity Logs) into BigQuery or custom
  destinations.
---

# SERA — Secure Extraction for Response Agents

## 1. User-Facing Intro & Guided Walkthrough (Keep Concise for the User!)

> **Communication Rule:** Whenever the user asks what SERA does, how its workflow operates, or how to get started, give them a **short, high-level summary** and guide them step-by-step from their current state. **Do NOT overwhelm the user** with internal template schemas, JSON parameter structures, encryption internals, or SQLite mechanics unless they explicitly ask for deep technical details—keep all of Section 2 as your internal agent knowledge.

### What to Tell the User (Summary View)
**SERA (Secure Extraction for Response Agents)** is a forensic log extraction engine that downloads **100% full, unsummarized events** from external telemetry sources and uploads them directly into your engagement's destination (such as BigQuery—which automatically uses your ambient GCP Application Default Credentials and environment project) without passing raw logs through LLM context or allowing post-download tampering.

### How to Guide the User Through SERA's 4-Stage Workflow
Before instructing the user, silently call `list_sources` and `list_destinations` (if `.sera/` is already initialized) to see which stage they are on, then walk them cleanly through the next step:

1. **Init Setup (`sera init`) — *One-time per engagement workspace***
   - Initializes `<workspace>/.sera/` (isolated config + SQLite ledger + upfront `uv` dependency check across all discovered source and destination plugins).
   - For BigQuery, GCP auth and target project come automatically from ADC and environment variables—no project ID flags needed:
     `sera init --dest-type bigquery`
2. **Auth (`sera auth add <source> ...`) — *Out-of-band in terminal (secrets never enter chat)***
   - Guides the analyst to authenticate directly into `<workspace>/.sera/creds/` using any discovered source plugin:
     - Microsoft OAuth (App Registration secret/cert, Device-Code, or Browser):
       `sera auth add microsoft --mode device-code --opt tenant_id=<TENANT_ID>` (or `--mode secret`)
     - Microsoft 180-Day MDE Host Timeline (portal session):
       `sera auth add microsoft --mode portal-session --profile mde_portal`
3. **Downloading (Agent MCP `submit_job` or CLI `sera collect`)**
   - Once initialized and authenticated, the user (or an Analysis Agent) simply describes what telemetry and time range are needed.
   - SERA uses safe full-event query templates, automatically splits busy time intervals so API row caps never truncate logs, and stages tamper-proof encrypted batches locally.
4. **Uploading & Tracking (Agent MCP `check_jobs` or CLI `sera jobs` / `sera status`)**
   - SERA atomically uploads verified batches to the destination, records every uploaded `event_id` so overlapping pulls never duplicate data, and returns a `job_id` immediately so events can be queried in BigQuery (`WHERE job_id = '<job_id>'`) as soon as upload completes.

---

## 2. Agent-Only Technical Reference (Internal Knowledge — Do Not Dump Verbatim)

### Parity Between MCP Tools and Human CLI
Every runtime capability works in both MCP and the `sera` CLI (only `init` and `auth add` are strictly terminal-only to keep secrets out of chat):

| Capability | MCP Tool | CLI Equivalent | Notes |
| :--- | :--- | :--- | :--- |
| Check sources & auth | `list_sources()` | `sera sources` / `sera auth status` | Zero schema sampling; never reveals secrets. If `SERA is not initialized` error returns, guide user to Step 1 (`sera init`). |
| Check destinations | `list_destinations()` | `sera destinations` | Shows `default_destination`, `bigquery` table FQN, `jsonl` path, or `http` endpoint. |
| Inspect templates | `list_templates(sub_source="")` | `sera templates` | Lists allowlisted templates and typed parameter schemas (including custom `.sera/templates/*.toml`). |
| Start extraction | `submit_job(...)` | `sera collect ... [--background]` | **Non-blocking in MCP**: returns `job_id` and `lookup_hint` immediately without waiting. Launch multiple jobs in parallel when pulling several surfaces. |
| Track / summarize | `check_jobs(job_id="", include_slices=False)` | `sera jobs` / `sera status <job_id>` | Instant read from `sera.sqlite`. Reports `status`, `events_fetched`, `events_uploaded`, `events_already_uploaded_skipped`, and slice progress. |
| Resume failed/killed | `resume_job(job_id)` | `sera resume <job_id>` | Resets only uncommitted (`in_progress`/`failed`) slices to `pending` and skips any events already in `uploaded_events`. |

### Supported `microsoft` Sub-Sources & Canonical Template `params`
Each `sub_source` uses **one canonical full-event query template** (`params={}` pulls 100% of events in `[start_time, end_time)`; optional typed `params` apply server-side filters):

1. **`entra`** (MS Graph OData; requires MSAL profile; default 24h slices):
   - `table_or_endpoint`: `signIns` | `directoryAudits` | `provisioning` | `riskDetections`
   - Optional `params`: `equals`, `in_list`, `contains`, `startswith`
2. **`purview_ual`** (MS Graph async `/v1.0/security/auditLog/queries`; requires MSAL `AuditLogsQuery.Read.All`; bisects when `isRecordCountLimitExceeded` or near 1M cap):
   - `table_or_endpoint`: `auditLogRecords`
   - Optional `params`: `users`, `ips`, `operations`, `services`, `record_types`, `object_ids`, `keyword`
3. **`log_analytics`** (Azure Monitor / Sentinel KQL; requires `target_id` = Workspace GUID or `default_workspace_id` in `.sera/config.toml`; bisects on `PartialError` / 500k cap):
   - `table_or_endpoint`: Exact table name (e.g. `SigninLogs`, `AuditLogs`, `AzureActivity`, `SecurityEvent`, `Syslog`, `CommonSecurityLog`)
   - Optional `params`: `equals`, `in_list`, `contains`, `startswith`
4. **`defender_hunting`** (Defender XDR 30-day KQL `/v1.0/security/runHuntingQuery`; bisects at 100k row ceiling):
   - `table_or_endpoint`: Exact XDR table (e.g. `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `EmailEvents`, `IdentityLogonEvents`)
   - Optional `params`: `equals`, `in_list`, `contains`, `startswith`
5. **`defender_timeline`** (MDE **180-Day Host Timeline** via `security.microsoft.com`; requires `microsoft-portal` profile with `sccauth` Cookie + `X-XSRF-TOKEN`; default 7d slices):
   - `table_or_endpoint`: Target host's MDE `machine_id` (40-hex DeviceId)
   - Optional `params`: `action_types`, `search_text`
6. **`arm_activity`** (Azure Subscription Activity Logs, 90d lookback; requires `target_id` = Subscription GUID or `default_subscription_id` in `.sera/config.toml`):
   - `table_or_endpoint`: `management`
   - Optional `params`: single `equals` filter on `resourceGroupName`, `resourceUri`, `resourceProvider`, or `correlationId`

### Filter `params` Reference (`entra`, `log_analytics`, `defender_hunting`, `arm_activity`)
```json
{
  "equals": {"userPrincipalName": "alice@contoso.com"},
  "in_list": {"ipAddress": ["198.51.100.10", "203.0.113.42"]},
  "contains": {"ProcessCommandLine": "encodedcommand"},
  "startswith": {"appDisplayName": "Microsoft"}
}
```
Field names are validated identifiers (`^[A-Za-z_][A-Za-z0-9_./-]*$`) and values are safely literal-encoded per dialect—never pass raw SQL/KQL operators (`| project`, `| summarize`, `$select`).

### Customizing Destinations (`sera init` / `sera destination add`)
- **BigQuery (`type="bigquery"`)**: Uses ambient GCP ADC and environment variables for auth and project selection automatically. Optional overrides: `dataset_id` (`sera`), `events_table` (`events`), `jobs_table` (`collection_jobs`), `location`, `partition_field` (`event_timestamp`), `cluster_fields` (`["source", "sub_source", "table_or_endpoint"]`).
- **External JSONL Directory (`type="jsonl"`)**: Options `output_dir`, `events_subdir` (`events`), `jobs_filename` (`collection_jobs.jsonl`).
- **HTTP / SIEM HEC (`type="http"`)**: Options `url`, `format` (`ndjson` | `json_array` | `splunk_hec`), `bearer_token` / `hec_token`, `headers`.
"""

PLUGIN_README_MD = """# SERA — Secure Extraction for Response Agents

Self-contained Antigravity plugin providing tamper-proof, template-driven DFIR telemetry acquisition with full CLI and MCP parity.

## How MCP Launches Locally via `uvx`
`mcp_config.json` executes the bundled local script `${PLUGIN_ROOT}/scripts/sera_mcp.py` via `uvx`, automatically provisioning Python and dependencies from the plugin bundle without remote Git URLs or hardcoded paths.

## Installing the `sera` CLI from the Plugin Bundle
```bash
uv tool install ~/.gemini/config/plugins/sera
```

## Local Development via Symlink
From the `git/` directory, link `dist-latest` directly into your global Antigravity plugins directory:
```bash
ln -s "$(pwd)/dist-latest" ~/.gemini/config/plugins/sera
```
"""


def _render_bundled_pyproject(version: str, dependencies: list[str]) -> str:
    deps_lines = "\n".join(f'    "{dep}",' for dep in dependencies)
    return (
        '[build-system]\n'
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n\n'
        '[project]\n'
        'name = "sera-dfir"\n'
        f'version = "{version}"\n'
        'description = "SERA — Secure Extraction for Response Agents: CLI-first & MCP forensic log acquisition engine."\n'
        'readme = "README.md"\n'
        'requires-python = ">=3.11"\n'
        'dependencies = [\n'
        f'{deps_lines}\n'
        ']\n\n'
        '[project.scripts]\n'
        'sera = "sera.cli.app:main"\n'
        'sera-mcp = "sera.mcp_server.server:main"\n\n'
        '[tool.hatch.build.targets.wheel]\n'
        'packages = ["src/sera"]\n'
    )


def _render_entrypoint_script(
    *,
    dependencies: list[str],
    module_path: str,
    description: str,
) -> str:
    dep_comments = "\n".join(f'#     "{dep}",' for dep in dependencies)
    return (
        "#!/usr/bin/env -S uv run --script\n"
        "# /// script\n"
        '# requires-python = ">=3.11"\n'
        "# dependencies = [\n"
        f"{dep_comments}\n"
        "# ]\n"
        "# ///\n"
        f'"""{description}"""\n\n'
        "from __future__ import annotations\n\n"
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n\n"
        'os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")\n'
        "sys.dont_write_bytecode = True\n\n"
        '_SRC_DIR = Path(__file__).resolve().parents[1] / "src"\n'
        "if str(_SRC_DIR) not in sys.path:\n"
        "    sys.path.insert(0, str(_SRC_DIR))\n\n"
        f"from {module_path} import main\n\n"
        'if __name__ == "__main__":\n'
        "    main()\n"
    )


def _chmod_executable(path: Path) -> None:
    os.chmod(
        path,
        stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH,
    )


def build_plugin_release(
    repo_git_dir: Path,
    *,
    version: str = __version__,
) -> dict[str, Any]:
    """Build self-contained unpacked `dist-latest/` and versioned `dist/sera-<version>.zip` inside `repo_git_dir`."""
    git_root = repo_git_dir.resolve()
    dist_dir = git_root / "dist"
    dist_latest = git_root / "dist-latest"

    dist_dir.mkdir(parents=True, exist_ok=True)
    if dist_latest.exists() or dist_latest.is_symlink():
        if dist_latest.is_symlink() or dist_latest.is_file():
            dist_latest.unlink()
        else:
            shutil.rmtree(dist_latest)

    (dist_latest / "hooks").mkdir(parents=True, exist_ok=True)
    (dist_latest / "rules").mkdir(parents=True, exist_ok=True)
    (dist_latest / "skills" / "sera").mkdir(parents=True, exist_ok=True)
    (dist_latest / "scripts").mkdir(parents=True, exist_ok=True)
    (dist_latest / "src").mkdir(parents=True, exist_ok=True)

    runtime_deps = collect_required_uv_packages()

    # 1. plugin.json (strictly valid Antigravity manifest fields)
    plugin_manifest = {
        "name": "sera",
        "displayName": "SERA — Secure Extraction for Response Agents",
        "version": version,
        "description": (
            "Forensic-grade DFIR log extraction engine: downloads full unsummarized events via allowlisted "
            "query templates into BigQuery or custom sinks with cryptographic spool verification."
        ),
        "suggestedPrompts": [
            "What does SERA do and how do I set it up for this engagement?",
            "Submit a SERA extraction job for Entra signIns and Purview UAL over the last 7 days",
            "Check progress and uploaded event counts for active SERA jobs",
        ],
    }
    (dist_latest / "plugin.json").write_text(
        json.dumps(plugin_manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    # 2. README.md & bundled pyproject.toml
    (dist_latest / "README.md").write_text(PLUGIN_README_MD, encoding="utf-8")
    (dist_latest / "pyproject.toml").write_text(
        _render_bundled_pyproject(version=version, dependencies=runtime_deps),
        encoding="utf-8",
    )

    # 3. Copy full local `src/sera/` runtime & plugins into the plugin bundle (excluding bytecode/OS artifacts)
    candidate_sera_pkg = git_root / "src" / "sera"
    source_sera_pkg = candidate_sera_pkg if candidate_sera_pkg.is_dir() else Path(__file__).resolve().parent
    shutil.copytree(
        source_sera_pkg,
        dist_latest / "src" / "sera",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".DS_Store"),
    )

    # 4. Local plugin entrypoint scripts (`scripts/sera_mcp.py` & `scripts/sera_cli.py`) with PEP 723 metadata
    mcp_script_path = dist_latest / "scripts" / "sera_mcp.py"
    mcp_script_path.write_text(
        _render_entrypoint_script(
            dependencies=runtime_deps,
            module_path="sera.mcp_server.server",
            description="Self-contained local plugin MCP server entrypoint for SERA.",
        ),
        encoding="utf-8",
    )
    _chmod_executable(mcp_script_path)

    cli_script_path = dist_latest / "scripts" / "sera_cli.py"
    cli_script_path.write_text(
        _render_entrypoint_script(
            dependencies=runtime_deps,
            module_path="sera.cli.app",
            description="Self-contained local plugin CLI entrypoint for SERA.",
        ),
        encoding="utf-8",
    )
    _chmod_executable(cli_script_path)

    # 5. mcp_config.json — `uvx` runs directly from the local plugin directory script `${PLUGIN_ROOT}/scripts/sera_mcp.py`
    mcp_config = {
        "mcpServers": {
            "sera": {
                "command": "uvx",
                "args": [
                    "--quiet",
                    "--with-requirements",
                    "${PLUGIN_ROOT}/scripts/sera_mcp.py",
                    "python",
                    "-B",
                    "${PLUGIN_ROOT}/scripts/sera_mcp.py",
                ],
            }
        }
    }
    (dist_latest / "mcp_config.json").write_text(
        json.dumps(mcp_config, indent=2) + "\n",
        encoding="utf-8",
    )

    # 6. Standalone executable hook script + root hooks.json
    hook_source = inspect.getsource(guard_dot_sera)
    hook_script_path = dist_latest / "hooks" / "pre_tool_guard.py"
    hook_script_path.write_text("#!/usr/bin/env python3\n" + hook_source, encoding="utf-8")
    _chmod_executable(hook_script_path)

    hooks_json = {
        "sera-forensic-guard": {
            "enabled": True,
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python3 -B ./hooks/pre_tool_guard.py",
                            "timeout": 10,
                        }
                    ],
                }
            ],
        }
    }
    (dist_latest / "hooks.json").write_text(
        json.dumps(hooks_json, indent=2) + "\n",
        encoding="utf-8",
    )

    # 7. rules/sera.md & skills/sera/SKILL.md
    (dist_latest / "rules" / "sera.md").write_text(SERA_RULE_MD, encoding="utf-8")
    (dist_latest / "skills" / "sera" / "SKILL.md").write_text(SERA_SKILL_MD, encoding="utf-8")

    # 8. Versioned zip archive in dist/sera-<version>.zip
    zip_path = dist_dir / f"sera-{version}.zip"
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(dist_latest.rglob("*")):
            if file_path.is_file():
                rel = file_path.relative_to(dist_latest)
                arcname = str(Path("sera") / rel)
                zf.write(file_path, arcname=arcname)

    return {
        "version": version,
        "dist_latest_dir": str(dist_latest),
        "zip_path": str(zip_path),
    }
