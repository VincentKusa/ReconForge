"""Small defensive helpers shared by the analysis stages."""

from __future__ import annotations

from typing import Any


def safe_dict(value: Any) -> dict[str, Any]:
    """Return *value* if it is a dict, otherwise an empty dict."""
    return value if isinstance(value, dict) else {}


def safe_list(value: Any) -> list[Any]:
    """Return *value* if it is a list, otherwise an empty list."""
    return value if isinstance(value, list) else []


def get_path(data: dict[str, Any], *keys: str) -> Any:
    """Walk *data* along *keys*, returning ``None`` on any missing branch."""
    current: Any = data

    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)

    return current
