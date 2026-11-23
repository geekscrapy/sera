"""Destination sink exports."""

from sera.destinations.base import BaseDestinationSink
from sera.destinations.bigquery import BigQueryDestination
from sera.destinations.http_sink import HttpIngestDestination
from sera.destinations.jsonl import JsonlDirectoryDestination

__all__ = [
    "BaseDestinationSink",
    "BigQueryDestination",
    "HttpIngestDestination",
    "JsonlDirectoryDestination",
]
