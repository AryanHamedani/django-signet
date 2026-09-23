"""Helpers every check module shares: reading ``SIGNET`` without raising."""

from __future__ import annotations

from typing import Any

from django.conf import settings


def _raw_signet() -> Any:
    return getattr(settings, "SIGNET", None)


def _signet() -> dict[str, Any]:
    raw = _raw_signet()
    return raw if isinstance(raw, dict) else {}


def _as_str(value: Any, default: str) -> str:
    """``dict.get(key, default)`` only substitutes ``default`` when the key
    is *absent* - a key present with the wrong type, or an explicit
    ``None`` (several ``DEFAULTS`` entries use ``None`` as a "derive this"
    sentinel), still comes through unchanged and would otherwise reach
    ``.startswith()`` and raise. Treating anything that isn't already a
    ``str`` as absent keeps every caller crash-proof without silently
    hiding a *correctly-typed* misconfiguration.
    """
    return value if isinstance(value, str) else default
