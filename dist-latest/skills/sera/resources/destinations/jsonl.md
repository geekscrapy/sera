# JSONL Directory Destination Plugin (`type="jsonl"`)

## Initialization
Writes verified `NEWLINE_DELIMITED_JSON` batches and job manifests to an external local or mounted forensic directory (outside `.sera/`):

```bash
sera init --dest-type jsonl --dest-opt output_dir=/cases/engagement/exports
```

## Options (`--dest-opt KEY=VALUE`)
| Option | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `output_dir` | Yes | — | Target directory for exported NDJSON event batches |
| `events_subdir` | No | `events` | Subdirectory under `output_dir` partitioned by `<source>/<sub_source>/<job_id>/` |
| `jobs_filename` | No | `collection_jobs.jsonl` | Job audit manifest filename inside `output_dir` |
