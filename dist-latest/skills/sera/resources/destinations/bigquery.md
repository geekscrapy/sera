# BigQuery Destination Plugin (`type="bigquery"`)

## 1. Adding the Destination (`sera dest add bigquery`)
BigQuery relies exclusively on ambient Google Cloud **Application Default Credentials (`auth_mode="adc"`)** and environment variables (`GOOGLE_CLOUD_PROJECT` / `GCLOUD_PROJECT` / `CLOUDSDK_CORE_PROJECT`) for authentication and project selection—no `project_id`, credential file, or proxy flags are used:

```bash
sera dest add bigquery
```

---

## 2. Auto-Provisioned Dataset & Tables
Before uploading the first batch, `BigQueryDestination` automatically creates the dataset and tables (`exists_ok=True`) if they do not exist:

- **Dataset:** `<ambient_project>.sera` (default `dataset_id="sera"`)
- **Events Table (`<ambient_project>.sera.events`):**
  - Partitioned by `DAY(event_timestamp)`
  - Clustered on `["source", "sub_source", "table_or_endpoint"]`
  - Columns: `event_id` (`STRING`), `job_id` (`STRING`), `ingested_at` (`TIMESTAMP`), `event_timestamp` (`TIMESTAMP`), `source` (`STRING`), `sub_source` (`STRING`), `table_or_endpoint` (`STRING`), `raw_sha256` (`STRING`), `raw_payload` (`STRING`), `event_data` (`JSON`)
- **Jobs Manifest Table (`<ambient_project>.sera.collection_jobs`):**
  - Records final audit metadata and uploaded event counts per `job_id`.
- **Upload Mechanism:** Atomic BigQuery Batch Load jobs (`NEWLINE_DELIMITED_JSON`).

---

## 3. Querying Uploaded Events by `job_id`
Every `collect` call returns a `job_id` and `lookup_hint` immediately:
```sql
SELECT * FROM `<project>.sera.events` WHERE job_id = '<job_id>'
```

---

## 4. Optional Destination Overrides (`--opt KEY=VALUE`)
| Option | Default | Description |
| :--- | :--- | :--- |
| `dataset_id` | `sera` | Target BigQuery dataset ID |
| `events_table` | `events` | Raw full-event table name |
| `jobs_table` | `collection_jobs` | Job audit manifest table name |
| `location` | `""` (project default) | Optional dataset/job location (e.g. `US`, `EU`) |
| `partition_field` | `event_timestamp` | `TIMESTAMP` column for `DAY` partitioning |
| `cluster_fields` | `["source", "sub_source", "table_or_endpoint"]` | Up to 4 clustering columns |
