# JSONL Directory Destination Plugin (`type="jsonl"`)

## Adding the Destination (`sera dest add jsonl`)
Writes verified `NEWLINE_DELIMITED_JSON` batches and job manifests to an external local or mounted forensic directory (outside `.sera/`):

```bash
sera dest add jsonl --opt output_dir=/cases/engagement/exports
```

## Options (`--opt KEY=VALUE`) & Auth (`--auth-mode none`)
| Option | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `output_dir` | Yes | — | Target file directory for exported NDJSON event batches |
| `events_subdir` | No | `events` | Subdirectory under `output_dir` partitioned by `<source>/<sub_source>/` |
| `jobs_filename` | No | `collection_jobs.jsonl` | Job audit manifest filename inside `output_dir` |
