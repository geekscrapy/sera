"""Pluggable Source and Destination registries for SERA."""

from __future__ import annotations

from pathlib import Path
from typing import Type

from sera.config import DestinationConfig, NetworkConfig, WorkspaceConfig
from sera.destinations.base import BaseDestinationSink
from sera.destinations.bigquery import BigQueryDestination
from sera.destinations.http_sink import HttpIngestDestination
from sera.destinations.jsonl import JsonlDirectoryDestination
from sera.sources.base import BaseSourceConnector


class SourceRegistry:
    """Registry of telemetry source connectors (`microsoft`, future `splunk`, `wiz`, `crowdstrike`, etc.)."""

    def __init__(self) -> None:
        self._connectors: dict[str, Type[BaseSourceConnector]] = {}

    def register(self, connector_cls: Type[BaseSourceConnector]) -> None:
        if not connector_cls.source_name:
            raise ValueError(f"Connector class {connector_cls.__name__} must define 'source_name'")
        self._connectors[connector_cls.source_name] = connector_cls

    def names(self) -> list[str]:
        return sorted(self._connectors)

    def create(self, source_name: str, workspace_dir: Path, config: WorkspaceConfig) -> BaseSourceConnector:
        if source_name not in self._connectors:
            available = ", ".join(self.names()) or "<none>"
            raise KeyError(f"Unknown source '{source_name}'. Registered sources: {available}")
        return self._connectors[source_name](workspace_dir=workspace_dir, config=config)


class DestinationRegistry:
    """Registry of customizable destination sinks (`bigquery`, `jsonl`, `http`, or custom drop-ins)."""

    def __init__(self) -> None:
        self._sinks: dict[str, Type[BaseDestinationSink]] = {}
        self.register(BigQueryDestination)
        self.register(JsonlDirectoryDestination)
        self.register(HttpIngestDestination)

    def register(self, sink_cls: Type[BaseDestinationSink]) -> None:
        if not sink_cls.sink_type:
            raise ValueError(f"Destination class {sink_cls.__name__} must define 'sink_type'")
        self._sinks[sink_cls.sink_type] = sink_cls

    def types(self) -> list[str]:
        return sorted(self._sinks)

    def create(self, dest_config: DestinationConfig, network: NetworkConfig) -> BaseDestinationSink:
        if dest_config.type not in self._sinks:
            available = ", ".join(self.types())
            raise KeyError(
                f"Unknown destination type '{dest_config.type}' for '{dest_config.name}'. "
                f"Registered types: {available}"
            )
        return self._sinks[dest_config.type](dest_config=dest_config, network=network)
