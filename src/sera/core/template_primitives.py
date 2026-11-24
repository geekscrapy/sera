"""Vendor-agnostic identifier validation primitives for SERA source plugins."""

from __future__ import annotations

import re


FIELD_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_./-]{0,127}$")
TABLE_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,127}$")


class TemplateValidationError(ValueError):
    """Raised by a source plugin when target identifiers or typed filter parameters are invalid."""


def validate_field_ident(name: str) -> str:
    cleaned = name.strip()
    if not FIELD_IDENT_RE.match(cleaned):
        raise TemplateValidationError(
            f"Invalid field identifier '{name}'. Only alphanumeric, '_', '.', '/', '-' characters are allowed."
        )
    return cleaned


def validate_table_ident(name: str) -> str:
    cleaned = name.strip()
    if not TABLE_IDENT_RE.match(cleaned):
        raise TemplateValidationError(
            f"Invalid table/endpoint identifier '{name}'. Only alphanumeric, '_', '-' characters are allowed."
        )
    return cleaned
