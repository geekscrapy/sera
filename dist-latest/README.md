# SERA — Secure Extraction for Response Agents

Self-contained Antigravity plugin providing tamper-proof, template-driven DFIR telemetry acquisition with 1-to-1 CLI and MCP parity (`sources`, `destinations`, `templates`, `collect`, `jobs`, `status`, `resume`).

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
