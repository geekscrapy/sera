---
name: sera
description: >-
  SERA (Secure Extraction for Response Agents) — forensic-grade DFIR log acquisition plugin and workflow guide.
  Activate whenever the user asks what SERA or this plugin does, asks how to initialize or authenticate SERA,
  or wants to extract, download, upload, track, or resume raw telemetry logs from any source into a destination sink.
---

# SERA — Secure Extraction for Response Agents

## 1. User-Facing Intro & Guided Walkthrough (Keep Concise for the User!)

> **Communication Rule:** Whenever the user asks what SERA does, how its workflow operates, or how to get started, give them a **short, high-level summary** and guide them step-by-step from their current state. **Do NOT overwhelm the user** with internal template schemas, JSON parameter structures, encryption internals, or SQLite mechanics unless they explicitly ask for deep technical details—keep Section 2 and `./resources/` as your internal agent knowledge.

### What to Tell the User (Summary View)
**SERA (Secure Extraction for Response Agents)** is a forensic log extraction engine that downloads **100% full, unsummarized events** from external telemetry source plugins and uploads them directly into your engagement's destination sink without passing raw logs through LLM context or allowing post-download tampering.

### How to Guide the User Through SERA's 4-Stage Workflow
Before instructing the user, silently call `sources` and `destinations` (if `.sera/` is already initialized) to see which stage they are on, and read only the relevant `./resources/` file below for the user's chosen source or destination:

1. **Init Setup (`sera init`) — *One-time per engagement workspace***
   - Initializes `<workspace>/.sera/` (isolated config + SQLite ledger + upfront `uv` dependency sync across discovered source and destination plugins):
     `sera init --dest-type <destination_type> [--dest-opt KEY=VALUE ...]`
   - Consult `./resources/destinations/<destination_type>.md` for exact `sera init` options (zero required options are prompted when defaults/ambient credentials apply).
2. **Auth (`sera auth add <source> ...`) — *Out-of-band in terminal (secrets never enter chat)***
   - Guides the analyst to authenticate directly into `<workspace>/.sera/creds/`:
     `sera auth add <source> --mode <auth_mode> [--profile default] [--opt KEY=VALUE ...]`
   - Consult `./resources/sources/<source>.md` (or `sera auth modes <source>`) for exact authentication modes and flags.
3. **Downloading (Agent MCP `collect` or CLI `sera collect`)**
   - Once initialized and authenticated, the user (or an Analysis Agent) describes what telemetry surface and time window are needed.
   - SERA uses canonical full-event query templates, adaptively splits busy time intervals so upstream API row caps never truncate logs, and stages tamper-proof `AES-256-GCM` encrypted batches locally.
4. **Uploading & Tracking (Agent MCP `jobs` / `status` or CLI `sera jobs` / `sera status`)**
   - SERA atomically uploads verified batches to the destination, records every uploaded `event_id` so overlapping pulls never duplicate data, and returns a `job_id` immediately so uploaded events can be queried by `job_id` as soon as upload completes.

---

## 2. Agent-Only Technical Reference (Internal Knowledge — Do Not Dump Verbatim)

### 1-to-1 Parity Between MCP Tools and `sera` CLI
Every runtime MCP tool shares the exact command name and parameter model of the `sera` CLI (`init` and `auth add` remain terminal-only so secrets never enter chat):

| Capability | MCP Tool | CLI Equivalent | Notes |
| :--- | :--- | :--- | :--- |
| Check sources & auth | `sources()` | `sera sources` / `sera auth status` | Zero schema sampling; never reveals secrets. If `SERA is not initialized` error returns, guide user to Step 1 (`sera init`). |
| Check destinations | `destinations()` | `sera destinations` | Shows `default_destination`, configured target coordinates, and registered sink plugin types. |
| Inspect templates | `templates(source="", sub_source="")` | `sera templates` | Lists the canonical full-event template and allowed typed filter `params` per `sub_source`. |
| Start extraction | `collect(source, sub_source, target, start, end, ...)` | `sera collect ... [--background]` | **Non-blocking in MCP**: returns `job_id` and `lookup_hint` immediately without waiting. Launch multiple jobs in parallel when pulling several surfaces. |
| List recent jobs | `jobs(limit=25)` | `sera jobs` | Instant read from `sera.sqlite` returning recent jobs and workspace uploaded event totals. |
| Inspect job status | `status(job_id, slices=False)` | `sera status <job_id> [--slices]` | Reports `status`, `events_fetched`, `events_uploaded`, `events_already_uploaded_skipped`, and optional per-slice breakdown. |
| Resume failed/killed | `resume(job_id)` | `sera resume <job_id>` | Resets only uncommitted (`in_progress`/`failed`) slices to `pending` and skips any events already recorded in `uploaded_events`. |

---

## 3. Source & Destination Plugin Reference (`./resources/`)

Source- and sink-specific authentication modes, `sub_source`s, `target` identifiers, filter `params`, destination schemas, and options live in `./resources/`. Read **only** the resource file relevant to the user's request:

### Source Plugins
- **Source `microsoft`**: [microsoft.md](./resources/sources/microsoft.md) — auth modes, sub-sources, targets, and filter `params`

### Destination Sink Plugins
- **Destination `bigquery`**: [bigquery.md](./resources/destinations/bigquery.md) — `sera init --dest-type bigquery` setup, schema, and options
- **Destination `http`**: [http.md](./resources/destinations/http.md) — `sera init --dest-type http` setup, schema, and options
- **Destination `jsonl`**: [jsonl.md](./resources/destinations/jsonl.md) — `sera init --dest-type jsonl` setup, schema, and options
