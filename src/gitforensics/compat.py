"""Compatibility helpers for the supported Python 3.10+ runtime range."""

import sys
from datetime import datetime, timezone
from enum import Enum

__all__ = ["StrEnum", "UTC", "parse_iso_datetime"]

UTC = timezone.utc


def parse_iso_datetime(value: object) -> datetime:
    """Parse ISO 8601 consistently on Python 3.10+, returning a safe UTC epoch fallback."""
    fallback = datetime(1970, 1, 1, tzinfo=UTC)
    if not isinstance(value, str) or not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, OverflowError):
        return fallback
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


if sys.version_info >= (3, 11):  # pragma: no cover - exercised on Python 3.11+
    from enum import StrEnum
else:  # pragma: no cover - exercised on Python 3.10

    class StrEnum(str, Enum):
        """Small backport of :class:`enum.StrEnum` used by project models."""

        def __str__(self) -> str:
            return str.__str__(self.value)
