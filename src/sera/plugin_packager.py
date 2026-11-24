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
from sera.core.registry import DestinationRegistry, SourceRegistry
from sera.hooks import guard_dot_sera
from sera.service import collect_required_uv_packages


SERA_RULE_MD = """# SERA — Secure Extraction for Response Agents (`sera.md`)

When acquiring raw telemetry or forensic logs for an engagement:

1. **Use SERA Exclusively for Log Acquisition**: Submit downloads through SERA's MCP tools (`collect`, `jobs`, `status`, `resume`, `sources`, `destinations`, `templates`) or guide the analyst to use the identical `sera` CLI commands (`sera collect`, `sera jobs`, `sera status`, `sera resume`, `sera sources`, `sera destinations`, `sera templates`).
2. **Never Require Global Installation**: Never tell the user to install SERA globally (`uv tool install`). Always install `sera` into the project's currently defined `.venv` via `uv pip install ~/.gemini/config/plugins/sera` (or `--python .venv/bin/python`).
3. **Single Canonical Full-Event Template**: Each `sub_source` uses one fixed canonical full-event template (accepting optional typed filter `params`) so 100% of every event is preserved verbatim without summarization or field projection. Schema sampling is intentionally disabled.
4. **Never Access `.sera/` Directly**: `<workspace>/.sera/` holds engagement credentials, the `sera.sqlite` ledger, and `AES-256-GCM` encrypted spool chunks. Never attempt to read, modify, or delete `.sera/` via file or shell tools.
5. **Never Ask for Secrets in Chat**: Source and destination onboarding (`sera init`, `sera source add ...`, `sera dest add ...`) must be run out-of-band in the analyst's terminal so credentials never enter chat.
6. **Concise User Communication**: Give the user crisp summaries and exact next-step setup commands; consult the `sera` skill's `./resources/` files for vendor- or sink-specific flags, proxies, sub-sources, and parameters under the hood.
"""


def _render_skill_md(source_names: list[str], dest_names: list[str]) -> str:
    src_links = "\n".join(
        f"- **Source `{name}`**: [{name}.md](./resources/sources/{name}.md) — `sera source add {name}` options (e.g. proxies), auth modes, sub-sources, targets, and filter `params`"
        for name in source_names
    )
    dst_links = "\n".join(
        f"- **Destination `{dtype}`**: [{dtype}.md](./resources/destinations/{dtype}.md) — `sera dest add {dtype}` options (e.g. file paths, dataset, HTTP proxy), auth modes, and schema"
        for dtype in dest_names
    )
    return f"""---
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
{src_links}

### Destination Sink Plugins
{dst_links}
"""


PLUGIN_README_MD = """# SERA — Secure Extraction for Response Agents

Self-contained Antigravity plugin providing tamper-proof, template-driven DFIR telemetry acquisition with 1-to-1 CLI and MCP parity (`sources`, `destinations`, `templates`, `collect`, `jobs`, `status`, `resume`).

## How MCP Launches Locally via `uvx`
`mcp_config.json` executes the bundled local script `${PLUGIN_ROOT}/scripts/sera_mcp.py` via `uvx`, automatically provisioning Python and dependencies from the plugin bundle without remote Git URLs or hardcoded paths.

## Installing `sera` into Your Current `.venv` (No Global Install Required)
Activate (or create) your engagement's `.venv`, then install `sera` directly into that virtual environment from the plugin directory:
```bash
uv venv .venv
source .venv/bin/activate
uv pip install ~/.gemini/config/plugins/sera
```

## Engagement Setup Workflow
```bash
# 1. Initialize .sera/ in your engagement workspace
sera init

# 2. Add a source (source-specific options like proxy + auth credentials)
sera source add <source_type>

# 3. Add a destination (destination-specific options like file paths / HTTP proxy + auth)
sera dest add <dest_type>
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
    source_registry: SourceRegistry | None = None,
    destination_registry: DestinationRegistry | None = None,
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

    src_reg = source_registry or SourceRegistry()
    dst_reg = destination_registry or DestinationRegistry()

    (dist_latest / "hooks").mkdir(parents=True, exist_ok=True)
    (dist_latest / "rules").mkdir(parents=True, exist_ok=True)
    (dist_latest / "skills" / "sera" / "resources" / "sources").mkdir(parents=True, exist_ok=True)
    (dist_latest / "skills" / "sera" / "resources" / "destinations").mkdir(parents=True, exist_ok=True)
    (dist_latest / "scripts").mkdir(parents=True, exist_ok=True)
    (dist_latest / "src").mkdir(parents=True, exist_ok=True)

    runtime_deps = collect_required_uv_packages(src_reg, dst_reg)

    # 1. plugin.json (strictly valid Antigravity manifest fields; vendor- & sink-agnostic)
    plugin_manifest = {
        "name": "sera",
        "displayName": "SERA — Secure Extraction for Response Agents",
        "version": version,
        "description": (
            "Forensic-grade DFIR log extraction engine: downloads full unsummarized events via canonical "
            "query templates into configured destination sinks with cryptographic spool verification."
        ),
        "suggestedPrompts": [
            "What does SERA do and how do I set it up in my .venv for this engagement?",
            "Show available SERA telemetry sources, templates, and configured destinations",
            "Check status and uploaded event counts for active SERA collection jobs",
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

    # 7. rules/sera.md, generic skills/sera/SKILL.md, and per-plugin skills/sera/resources/{sources,destinations}/*.md
    (dist_latest / "rules" / "sera.md").write_text(SERA_RULE_MD, encoding="utf-8")

    src_names = src_reg.names()
    dst_names = dst_reg.types()
    for sname in src_names:
        s_cls = src_reg.get_class(sname)
        (dist_latest / "skills" / "sera" / "resources" / "sources" / f"{sname}.md").write_text(
            s_cls.skill_resource_markdown(),
            encoding="utf-8",
        )
    for dtype in dst_names:
        d_cls = dst_reg.get_class(dtype)
        (dist_latest / "skills" / "sera" / "resources" / "destinations" / f"{dtype}.md").write_text(
            d_cls.skill_resource_markdown(),
            encoding="utf-8",
        )

    (dist_latest / "skills" / "sera" / "SKILL.md").write_text(
        _render_skill_md(src_names, dst_names),
        encoding="utf-8",
    )

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
