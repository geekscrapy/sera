---
name: sera
description: >-
  SERA (Secure Extraction for Response Agents) — forensic-grade DFIR log acquisition plugin and workflow guide.
  Activate whenever the user asks what SERA or this plugin does, asks how to initialize or set up SERA in their
  .venv, or wants to extract, download, upload, track, or resume raw telemetry logs from any source into a destination sink.
---

# SERA — Secure Extraction for Response Agents

## 1. User-Facing Intro & Guided Setup Workflow (Keep Concise for the User!)

> **Communication Rule:** Whenever the user asks what SERA does, how its workflow operates, or how to get started, give them a **short, high-level summary** and guide them step-by-step from their current state. **Do NOT overwhelm the user** with internal template schemas, JSON parameter structures, encryption internals, or SQLite mechanics unless they explicitly ask for deep technical details—keep Section 2 and `./resources/` as your internal agent knowledge.

### What to Tell the User (Summary View)
**SERA (Secure Extraction for Response Agents)** is a forensic log extraction engine that downloads **100% full, unsummarized events** from external telemetry source plugins and uploads them directly into your engagement's destination sink without passing raw logs through LLM context or allowing post-download tampering.

### Installing `sera` into the Current `.venv` (Never Require Global Install)
SERA does **not** require global installation (`uv tool install` is never required). While the MCP server runs automatically from the plugin directory via `uvx`, the analyst installs the `sera` CLI directly into their project's currently defined `.venv`:
```bash
uv pip install ~/.gemini/config/plugins/sera
```
*(If a `.venv` is not active yet: `uv venv .venv && source .venv/bin/activate && uv pip install ~/.gemini/config/plugins/sera`.)*

### SERA's Guided Setup & Collection Workflow
Before instructing the user, silently call `sources` and `destinations` (if `.sera/` is already initialized) to detect which step they are on, and read only the relevant `./resources/` file below for their chosen source or destination:

1. **Initialize Workspace (`sera init`) — *One-time per engagement workspace***
   - Creates `<workspace>/.sera/` (`config.toml`, `sera.sqlite`, `creds/`, `spool/`) and verifies dependencies in the active `.venv`:
     ```bash
     sera init
     ```
2. **Add a Source & Auth (`sera source add <type> ...`) — *Out-of-band in terminal***
   - Configures source-specific settings (such as `proxy_url`, `ca_bundle`, default workspace/subscription IDs) and authentication credentials together in one step (secrets stay strictly inside `<workspace>/.sera/creds/`):
     ```bash
     sera source add <source_type> [--name default] [--auth-mode <mode>] [--opt KEY=VALUE ...]
     ```
   - Consult `./resources/sources/<source_type>.md` (or `sera source types <source_type>`) for exact options and auth modes.
3. **Add a Destination & Auth (`sera dest add <type> ...`) — *Out-of-band in terminal***
   - Configures destination-specific settings (such as dataset/table names, output file paths, or HTTP URLs/proxies) and destination auth together in one step:
     ```bash
     sera dest add <dest_type> [--name default] [--auth-mode <mode>] [--opt KEY=VALUE ...]
     ```
   - Consult `./resources/destinations/<dest_type>.md` (or `sera dest types <dest_type>`) for exact options and auth modes.
4. **Collect & Track (Agent MCP `collect` / `jobs` / `status` ↔ CLI `sera collect` / `sera jobs` / `sera status`)**
   - Submit non-blocking full-event extraction jobs via MCP `collect` or CLI `sera collect`; SERA adaptively splits capped intervals, verifies `AES-256-GCM` spool batches, deduplicates via `uploaded_events`, and returns a `job_id` immediately for destination lookup.

---

## 2. Agent-Only Technical Reference (Internal Knowledge — Do Not Dump Verbatim)

### 1-to-1 Parity Between MCP Tools and `sera` CLI
Every runtime MCP tool shares the exact command name and parameter model of the `sera` CLI (`init`, `source add`, and `dest add` remain terminal-only so secrets never enter chat):

| Capability | MCP Tool | CLI Equivalent | Notes |
| :--- | :--- | :--- | :--- |
| Check sources & auth | `sources()` | `sera sources` / `sera source list` | Zero schema sampling; never reveals secrets. If `SERA is not initialized` error returns, guide user to `sera init` -> `sera source add` -> `sera dest add`. |
| Check destinations | `destinations()` | `sera destinations` / `sera dest list` | Shows `default_destination`, configured target coordinates, and registered sink plugin types. |
| Inspect templates | `templates(source="", sub_source="")` | `sera templates` | Lists the canonical full-event template and allowed typed filter `params` per `sub_source`. |
| Start extraction | `collect(source, sub_source, target, start, end, ...)` | `sera collect ... [--background]` | **Non-blocking in MCP**: returns `job_id` and `lookup_hint` immediately without waiting. Launch multiple jobs in parallel when pulling several surfaces. |
| List recent jobs | `jobs(limit=25)` | `sera jobs` | Instant read from `sera.sqlite` returning recent jobs and workspace uploaded event totals. |
| Inspect job status | `status(job_id, slices=False)` | `sera status <job_id> [--slices]` | Reports `status`, `events_fetched`, `events_uploaded`, `events_already_uploaded_skipped`, and optional per-slice breakdown. |
| Resume failed/killed | `resume(job_id)` | `sera resume <job_id>` | Resets only uncommitted (`in_progress`/`failed`) slices to `pending` and skips any events already recorded in `uploaded_events`. |

---

## 3. Source & Destination Plugin Reference (`./resources/`)

Source- and sink-specific options, proxies, authentication modes, `sub_source`s, `target` identifiers, filter `params`, and destination schemas live in `./resources/`. Read **only** the resource file relevant to the user's request:

### Source Plugins
- **Source `microsoft`**: [microsoft.md](./resources/sources/microsoft.md) — `sera source add microsoft` options (e.g. proxies), auth modes, sub-sources, targets, and filter `params`

### Destination Sink Plugins
- **Destination `bigquery`**: [bigquery.md](./resources/destinations/bigquery.md) — `sera dest add bigquery` options (e.g. file paths, dataset, HTTP proxy), auth modes, and schema
- **Destination `http`**: [http.md](./resources/destinations/http.md) — `sera dest add http` options (e.g. file paths, dataset, HTTP proxy), auth modes, and schema
- **Destination `jsonl`**: [jsonl.md](./resources/destinations/jsonl.md) — `sera dest add jsonl` options (e.g. file paths, dataset, HTTP proxy), auth modes, and schema
