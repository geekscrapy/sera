# HTTP / SIEM HEC Destination Plugin (`type="http"`)

## Initialization
Streams verified `RawEventEnvelope` batches over HTTPS to a SIEM collector, webhook, or Splunk HEC endpoint:

```bash
sera init --dest-type http --dest-opt url=https://siem.example.com/services/collector --dest-opt format=splunk_hec --dest-opt hec_token=<TOKEN>
```

## Options (`--dest-opt KEY=VALUE`)
| Option | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `url` | Yes | — | HTTPS ingestion endpoint URL |
| `format` | No | `ndjson` | Payload wire format: `ndjson` \| `json_array` \| `splunk_hec` |
| `bearer_token` | No | `""` | Optional `Authorization: Bearer <token>` |
| `hec_token` | No | `""` | Optional `Authorization: Splunk <token>` |
| `headers` | No | `{}` | Optional JSON object of additional HTTP headers |
