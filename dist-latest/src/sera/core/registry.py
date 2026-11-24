"""Dynamic plugin discovery registries for SERA source evidence and destination sink plugins.

Core never imports concrete source or destination modules directly. Instead, plugins are
auto-discovered from `sera.sources.*` / `sera.destinations.*` subpackages and standard
Python entry points (`sera.sources` and `sera.destinations`).
"""

from __future__ import annotations

import importlib
import importlib.metadata
import pkgutil
from pathlib import Path
from typing import Type

import sera.destinations as destinations_pkg
import sera.sources as sources_pkg
from sera.config import DestinationConfig, NetworkConfig, WorkspaceConfig
from sera.destinations.base import BaseDestinationSink
from sera.sources.base import BaseSourceConnector


class SourceRegistry:
    """Discovers and instantiates self-contained telemetry source plugins."""

    def __init__(self, auto_discover: bool = True) -> None:
        self._connectors: dict[str, Type[BaseSourceConnector]] = {}
        if auto_discover:
            self.discover()

    def discover(self) -> None:
        for mod_info in pkgutil.iter_modules(sources_pkg.__path__):
            if mod_info.name == "base" or mod_info.name.startswith("_"):
                continue
            module = importlib.import_module(f"{sources_pkg.__name__}.{mod_info.name}")
            plugin_cls = getattr(module, "PLUGIN_CLASS", None)
            if isinstance(plugin_cls, type) and issubclass(plugin_cls, BaseSourceConnector):
                self.register(plugin_cls)

        for ep in importlib.metadata.entry_points(group="sera.sources"):
            loaded = ep.load()
            if isinstance(loaded, type) and issubclass(loaded, BaseSourceConnector):
                self.register(loaded)

    def register(self, connector_cls: Type[BaseSourceConnector]) -> None:
        if not connector_cls.source_name:
            raise ValueError(f"Source plugin {connector_cls.__name__} must define 'source_name'")
        self._connectors[connector_cls.source_name] = connector_cls

    def names(self) -> list[str]:
        return sorted(self._connectors)

    def get_class(self, source_name: str) -> Type[BaseSourceConnector]:
        if source_name not in self._connectors:
            available = ", ".join(self.names()) or "<none>"
            raise KeyError(f"Unknown source plugin '{source_name}'. Registered sources: {available}")
        return self._connectors[source_name]

    def create(self, source_name: str, workspace_dir: Path, config: WorkspaceConfig) -> BaseSourceConnector:
        cls = self.get_class(source_name)
        return cls(workspace_dir=workspace_dir, config=config)

    def required_packages(self) -> list[str]:
        pkgs: set[str] = set()
        for cls in self._connectors.values():
            pkgs.update(cls.required_packages)
        return sorted(pkgs)


class DestinationRegistry:
    """Discovers and instantiates self-contained destination sink plugins."""

    def __init__(self, auto_discover: bool = True) -> None:
        self._sinks: dict[str, Type[BaseDestinationSink]] = {}
        if auto_discover:
            self.discover()

    def discover(self) -> None:
        for mod_info in pkgutil.iter_modules(destinations_pkg.__path__):
            if mod_info.name == "base" or mod_info.name.startswith("_"):
                continue
            module = importlib.import_module(f"{destinations_pkg.__name__}.{mod_info.name}")
            plugin_cls = getattr(module, "PLUGIN_CLASS", None)
            if isinstance(plugin_cls, type) and issubclass(plugin_cls, BaseDestinationSink):
                self.register(plugin_cls)

        for ep in importlib.metadata.entry_points(group="sera.destinations"):
            loaded = ep.load()
            if isinstance(loaded, type) and issubclass(loaded, BaseDestinationSink):
                self.register(loaded)

    def register(self, sink_cls: Type[BaseDestinationSink]) -> None:
        if not sink_cls.sink_type:
            raise ValueError(f"Destination plugin {sink_cls.__name__} must define 'sink_type'")
        self._sinks[sink_cls.sink_type] = sink_cls

    def types(self) -> list[str]:
        return sorted(self._sinks)

    def get_class(self, sink_type: str) -> Type[BaseDestinationSink]:
        if sink_type not in self._sinks:
            available = ", ".join(self.types()) or "<none>"
            raise KeyError(f"Unknown destination plugin '{sink_type}'. Registered types: {available}")
        return self._sinks[sink_type]

    def create(self, dest_config: DestinationConfig, network: NetworkConfig) -> BaseDestinationSink:
        cls = self.get_class(dest_config.type)
        normalized_cfg = DestinationConfig(
            name=dest_config.name,
            type=dest_config.type,
            options=cls.apply_defaults(dest_config.options),
        )
        return cls(dest_config=normalized_cfg, network=network)

    def required_packages(self) -> list[str]:
        pkgs: set[str] = set()
        for cls in self._sinks.values():
            pkgs.update(cls.required_packages)
        return sorted(pkgs)
