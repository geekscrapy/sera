# SERA — Secure Extraction for Response Agents

Forensic-grade, CLI-first & MCP log acquisition engine for DFIR response teams.

## Key Guarantees
- **Full Event Fidelity (Zero Summarization / Zero Schema Sampling)**: Uses allowlisted, parameterized query templates and raw wire JSON streaming (`httpx`).
- **Cryptographic Spool Protection**: Batches in `<workspace>/.sera/spool/` are encrypted and authenticated with an ephemeral in-memory `AES-256-GCM` key (`os.urandom(32)`) and verified via `SHA-256` before atomic BigQuery Batch Load.
- **Single Engagement SQLite Ledger (`<workspace>/.sera/sera.sqlite`)**: Tracks `jobs`, `job_slices` (adaptive per-interval tree bisection), `uploaded_events` (committed strictly post-BigQuery upload), and `auth_profiles`.
- **CLI-First + MCP Parity**: Every workflow works identically from `sera` CLI and `sera-mcp`.
- **Antigravity Plugin Distribution**: Packaged into versioned archives under `dist/sera-<version>.zip` and unpacked under `dist-latest/` for immediate symlinking into `~/.gemini/config/plugins/sera`.
