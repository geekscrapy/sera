# HTTP / SIEM HEC Destination Plugin (`type="http"`)

## Adding the Destination & Auth (`sera dest add http`)
Streams verified `RawEventEnvelope` batches over HTTPS to a SIEM collector, webhook, or Splunk HEC endpoint, storing secret tokens inside `<workspace>/.sera/creds/`:

```bash
sera dest add http --auth-mode splunk-hec --opt url=https://siem.example.com/services/collector --opt format=splunk_hec
```

## Auth Modes (`--auth-mode`)
- `none`: Unauthenticated HTTPS endpoint
- `bearer`: Prompts/accepts secret `bearer_token` (`Authorization: Bearer <token>`)
- `splunk-hec`: Prompts/accepts secret `hec_token` (`Authorization: Splunk <token>`)

## Destination Options (`--opt KEY=VALUE`)
| Option | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `url` | Yes | — | HTTPS ingestion endpoint URL |
| `format` | No | `ndjson` | Payload wire format: `ndjson` \| `json_array` \| `splunk_hec` |
| `jobs_url` | No | `""` | Optional URL to POST job completion manifests |
| `proxy_url` | No | `""` | Optional HTTP/HTTPS/SOCKS5 proxy URL scoped strictly to this HTTP destination |
| `ca_bundle` | No | `""` | Optional custom CA certificate PEM path for this HTTP destination |
