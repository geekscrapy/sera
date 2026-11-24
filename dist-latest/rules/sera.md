# SERA — Secure Extraction for Response Agents (`sera.md`)

When acquiring raw telemetry or forensic logs for an engagement:

1. **Use SERA Exclusively for Log Acquisition**: Submit downloads through SERA's MCP tools (`collect`, `jobs`, `status`, `resume`, `sources`, `destinations`, `templates`) or guide the analyst to use the identical `sera` CLI commands (`sera collect`, `sera jobs`, `sera status`, `sera resume`, `sera sources`, `sera destinations`, `sera templates`).
2. **Never Require Global Installation**: Never tell the user to install SERA globally (`uv tool install`). Always install `sera` into the project's currently defined `.venv` via `uv pip install ~/.gemini/config/plugins/sera` (or `--python .venv/bin/python`).
3. **Single Canonical Full-Event Template**: Each `sub_source` uses one fixed canonical full-event template (accepting optional typed filter `params`) so 100% of every event is preserved verbatim without summarization or field projection. Schema sampling is intentionally disabled.
4. **Never Access `.sera/` Directly**: `<workspace>/.sera/` holds engagement credentials, the `sera.sqlite` ledger, and `AES-256-GCM` encrypted spool chunks. Never attempt to read, modify, or delete `.sera/` via file or shell tools.
5. **Never Ask for Secrets in Chat**: Source and destination onboarding (`sera init`, `sera source add ...`, `sera dest add ...`) must be run out-of-band in the analyst's terminal so credentials never enter chat.
6. **Concise User Communication**: Give the user crisp summaries and exact next-step setup commands; consult the `sera` skill's `./resources/` files for vendor- or sink-specific flags, proxies, sub-sources, and parameters under the hood.
