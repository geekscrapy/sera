"""BigQuery destination plugin package."""

from sera.destinations.bigquery.sink import BigQueryDestination, EVENTS_SCHEMA, JOBS_SCHEMA

PLUGIN_CLASS = BigQueryDestination

__all__ = ["BigQueryDestination", "EVENTS_SCHEMA", "JOBS_SCHEMA", "PLUGIN_CLASS"]
