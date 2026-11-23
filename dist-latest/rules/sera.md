# SERA — Secure Extraction for Response Agents (`sera.md`)

When acquiring raw telemetry or forensic logs for an engagement:

1. **Use SERA Exclusively for Log Acquisition**: Submit downloads through SERA's MCP tools (`submit_job`, `check_jobs`, `resume_job`, `list_sources`, `list_destinations`, `list_templates`) or guide the analyst to use the `sera` CLI.
2. **Templated Full-Event Extraction Only**: SERA enforces allowlisted query templates (`all`, `structured_filter`, `by_user`, `by_ip`, `ual_scope`, `by_actor`, `by_host`, `machine_timeline`, etc.) so 100% of every event is preserved verbatim without summarization or field projection. Schema sampling is intentionally disabled.
3. **Never Access `.sera/` Directly**: `<workspace>/.sera/` holds engagement credentials, the `sera.sqlite` ledger, and `AES-256-GCM` encrypted spool chunks. Never attempt to read, modify, or delete `.sera/` via file or shell tools.
4. **Never Ask for Secrets in Chat**: Authentication (MSAL Service Principal, Interactive/Device-Code, or MDE Portal Session cookies) must always be configured out-of-band by the analyst via `sera auth add ...`.
5. **Concise User Communication**: Give the user crisp summaries and exact next-step setup commands; handle template selection, typed parameter construction, and job tracking under the hood.
