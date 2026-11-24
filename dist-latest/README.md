# SERA — Secure Extraction for Response Agents

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

# 4. Watch live job & slice progress bars in terminal (optional --bell audio alerts)
sera watch --bell
```

## Local Development via Symlink
From the `git/` directory, link `dist-latest` directly into your global Antigravity plugins directory:
```bash
ln -s "$(pwd)/dist-latest" ~/.gemini/config/plugins/sera
```
