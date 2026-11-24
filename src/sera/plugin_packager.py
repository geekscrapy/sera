"""Antigravity Plugin packager producing versioned `dist/sera-<version>.zip` and unpacked `dist-latest/`."""

from __future__ import annotations

import inspect
import json
import os
import shutil
import stat
import sys
import zipfile
from pathlib import Path
from typing import Any

from sera import __version__
from sera.hooks import guard_dot_sera


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
**SERA (Secure Extraction for Response Agents)** is a forensic log extraction engine that downloads **100% full, unsummarized events** from external telemetry sources and uploads them directly into your engagement's destination (such as your GCP `CASE` BigQuery project) without passing raw logs through LLM context or allowing post-download tampering.

### How to Guide the User Through SERA's 4-Stage Workflow
Before instructing the user, silently call `list_sources` and `list_destinations` (if `.sera/` is already initialized) to see which stage they are on, then walk them cleanly through the next step:

1. **Init Setup (`sera init`) — *One-time per engagement workspace***
   - Initializes `<workspace>/.sera/` (isolated config + SQLite ledger + upfront `uv` dependency check) and configures where logs will land (e.g., your GCP `CASE` BigQuery project, external JSONL mount, or HTTP/HEC endpoint).
   - Give the user a ready-to-run command tailored to their target, e.g.:
     `sera init --bq-project <CASE_GCP_PROJECT> --bq-dataset sera_raw`
2. **Auth (`sera auth add ...`) — *Out-of-band in terminal (secrets never enter chat)***
   - Guides the analyst to authenticate directly into `<workspace>/.sera/creds/`:
     - Microsoft OAuth (App Registration secret/cert, Device-Code, or Browser):
       `sera auth add microsoft --mode device-code --tenant-id <TENANT_ID>` (or `--mode secret`)
     - Microsoft 180-Day MDE Host Timeline (portal session):
       `sera auth add microsoft-portal`
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
2. **`purview_ual`** (MS Graph async `/beta/security/auditLog/queries`; requires MSAL `AuditLogsQuery.Read.All`; bisects near 1M cap):
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
   - Optional `params`: `equals` on `caller`, `resourceGroupName`, `resourceType`, `resourceId`, `status`

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
- **BigQuery (`type="bigquery"`)**: Options `project_id`, `dataset_id` (`sera_raw`), `events_table` (`events`), `jobs_table` (`collection_jobs`), `location` (`US`), `partition_field` (`event_timestamp`), `cluster_fields` (`["source", "sub_source", "table_or_endpoint"]`), optional `credentials_file`.
- **External JSONL Directory (`type="jsonl"`)**: Options `output_dir`, `events_subdir` (`events`), `jobs_filename` (`collection_jobs.jsonl`).
- **HTTP / SIEM HEC (`type="http"`)**: Options `url`, `format` (`ndjson` | `json_array` | `splunk_hec`), `bearer_token` / `hec_token`, `headers`.
"""

PLUGIN_README_MD = """# SERA — Secure Extraction for Response Agents

Antigravity plugin providing tamper-proof, template-driven DFIR telemetry acquisition with full CLI and MCP parity.

## Testing via Symlink
Link `dist-latest` directly into your global Antigravity plugins directory:
```bash
ln -s /Users/matt/Documents/sera/git/dist-latest ~/.gemini/config/plugins/sera
```
"""


def build_plugin_release(
    repo_git_dir: Path,
    *,
    version: str = __version__,
    python_executable: str | None = None,
) -> dict[str, Any]:
    """Build unpacked `dist-latest/` and versioned `dist/sera-<version>.zip` inside `repo_git_dir`."""
    git_root = repo_git_dir.resolve()
    dist_dir = git_root / "dist"
    dist_latest = git_root / "dist-latest"
    py_exe = python_executable or sys.executable
    src_dir = str((git_root / "src").resolve())

    dist_dir.mkdir(parents=True, exist_ok=True)
    if dist_latest.exists() or dist_latest.is_symlink():
        if dist_latest.is_symlink() or dist_latest.is_file():
            dist_latest.unlink()
        else:
            shutil.rmtree(dist_latest)

    (dist_latest / "hooks").mkdir(parents=True, exist_ok=True)
    (dist_latest / "rules").mkdir(parents=True, exist_ok=True)
    (dist_latest / "skills" / "sera").mkdir(parents=True, exist_ok=True)

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

    # 2. README.md
    (dist_latest / "README.md").write_text(PLUGIN_README_MD, encoding="utf-8")

    # 3. mcp_config.json
    mcp_config = {
        "mcpServers": {
            "sera": {
                "command": py_exe,
                "args": ["-m", "sera.mcp_server.server"],
                "env": {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": src_dir,
                },
            }
        }
    }
    (dist_latest / "mcp_config.json").write_text(
        json.dumps(mcp_config, indent=2) + "\n",
        encoding="utf-8",
    )

    # 4. Standalone executable hook script + root hooks.json
    hook_source = inspect.getsource(guard_dot_sera)
    hook_script_path = dist_latest / "hooks" / "pre_tool_guard.py"
    hook_script_path.write_text("#!/usr/bin/env python3\n" + hook_source, encoding="utf-8")
    os.chmod(
        hook_script_path,
        stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH,
    )

    hooks_json = {
        "sera-forensic-guard": {
            "enabled": True,
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"\"{py_exe}\" -B ./hooks/pre_tool_guard.py",
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

    # 5. rules/sera.md
    (dist_latest / "rules" / "sera.md").write_text(SERA_RULE_MD, encoding="utf-8")

    # 6. skills/sera/SKILL.md
    (dist_latest / "skills" / "sera" / "SKILL.md").write_text(SERA_SKILL_MD, encoding="utf-8")

    # 7. Versioned zip archive in dist/sera-<version>.zip
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
