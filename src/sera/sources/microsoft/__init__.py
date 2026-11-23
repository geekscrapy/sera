"""Microsoft / Azure source connector package."""

from sera.sources.microsoft.auth import MicrosoftAuthError, MicrosoftAuthManager
from sera.sources.microsoft.connector import MicrosoftSourceConnector, SUB_SOURCE_SPECS

__all__ = [
    "MicrosoftAuthError",
    "MicrosoftAuthManager",
    "MicrosoftSourceConnector",
    "SUB_SOURCE_SPECS",
]
