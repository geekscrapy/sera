"""Self-contained Microsoft / Azure source evidence plugin package."""

from sera.sources.microsoft.auth import MicrosoftAuthError, MicrosoftAuthManager
from sera.sources.microsoft.connector import MicrosoftSourceConnector, SUB_SOURCE_SPECS
from sera.sources.microsoft.templates import MicrosoftTemplateEngine

PLUGIN_CLASS = MicrosoftSourceConnector

__all__ = [
    "MicrosoftAuthError",
    "MicrosoftAuthManager",
    "MicrosoftSourceConnector",
    "MicrosoftTemplateEngine",
    "PLUGIN_CLASS",
    "SUB_SOURCE_SPECS",
]
