"""Namespace root for SERA destination sink plugins (discovered dynamically by `DestinationRegistry`)."""

from sera.destinations.base import BaseDestinationSink, SinkOptionSpec

__all__ = ["BaseDestinationSink", "SinkOptionSpec"]
