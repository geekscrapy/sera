"""JSONL directory destination plugin package."""

from sera.destinations.jsonl.sink import JsonlDirectoryDestination

PLUGIN_CLASS = JsonlDirectoryDestination

__all__ = ["JsonlDirectoryDestination", "PLUGIN_CLASS"]
