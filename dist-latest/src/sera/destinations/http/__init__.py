"""HTTP destination plugin package."""

from sera.destinations.http.sink import HttpIngestDestination

PLUGIN_CLASS = HttpIngestDestination

__all__ = ["HttpIngestDestination", "PLUGIN_CLASS"]
