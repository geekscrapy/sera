# SERA — Secure Extraction for Response Agents (`sera.md`)

When acquiring raw telemetry or forensic logs for an engagement:

1. **Use SERA Exclusively for Log Acquisition**: Submit downloads through SERA's MCP tools (`collect`, `jobs`, `status`, `resume`, `sources`, `destinations`, `templates`) or guide the analyst to use the identical `sera` CLI commands (`sera collect`, `sera jobs`, `sera status`, `sera resume`, `sera sources`, `sera destinations`, `sera templates`).
2. **Single Canonical Full-Event Template**: Each `sub_source` uses one fixed canonical full-event template (accepting optional typed filter `params`) so 100% of every event is preserved verbatim without summarization or field projection. Schema sampling is intentionally disabled.
3. **Never Access `.sera/` Directly**: `<workspace>/.sera/` holds engagement credentials, the `sera.sqlite` ledger, and `AES-256-GCM` encrypted spool chunks. Never attempt to read, modify, or delete `.sera/` via file or shell tools.
4. **Never Ask for Secrets in Chat**: Authentication must always be configured out-of-band by the analyst via `sera auth add <source> ...`.
5. **Concise User Communication**: Give the user crisp summaries and exact next-step setup commands; consult the `sera` skill's `./resources/` files for vendor- or sink-specific flags, sub-sources, and parameters under the hood.
