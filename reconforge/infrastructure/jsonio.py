"""JSON file reading and writing with consistent formatting and errors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: str | Path, required: bool = True) -> dict[str, Any] | None:
    """Load a JSON object from *path*.

    Raises ``FileNotFoundError`` when *required* and the file is missing,
    and ``ValueError`` for malformed JSON or non-object documents.
    """
    path = Path(path)

    if not path.exists():
        if required:
            raise FileNotFoundError(f"Required input not found: {path}")
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object in {path}")

    return data


def write_json(path: str | Path, data: dict[str, Any], trailing_newline: bool = False) -> Path:
    """Write *data* to *path* as formatted UTF-8 JSON and return the path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    text = json.dumps(data, indent=2, ensure_ascii=False)
    if trailing_newline:
        text += "\n"

    path.write_text(text, encoding="utf-8")
    return path


class JsonArtifactStore:
    """ArtifactStore adapter backed by this module's JSON helpers."""

    def load(self, path: str | Path, required: bool = True) -> dict[str, Any] | None:
        return load_json(path, required=required)

    def write(
        self, path: str | Path, data: dict[str, Any], trailing_newline: bool = False
    ) -> Path:
        return write_json(path, data, trailing_newline)
