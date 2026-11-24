---
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
- **BigQuery (`type="bigquery"`)**: Uses ambient GCP ADC and environment variables for auth and project selection automatically. Optional overrides: `dataset_id` (`sera`), `events_table` (`events`), `jobs_table` (`collection_jobs`), `location`, `partition_field` (`event_timestamp`), `cluster_fields` (`["source", "sub_source", "table_or_endpoint"]`).
- **External JSONL Directory (`type="jsonl"`)**: Options `output_dir`, `events_subdir` (`events`), `jobs_filename` (`collection_jobs.jsonl`).
- **HTTP / SIEM HEC (`type="http"`)**: Options `url`, `format` (`ndjson` | `json_array` | `splunk_hec`), `bearer_token` / `hec_token`, `headers`.
