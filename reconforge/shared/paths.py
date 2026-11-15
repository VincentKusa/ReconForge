"""Project filesystem anchors and path resolution helpers.

Stage entry points previously re-derived the project root and repeated the
same "make this CLI path absolute" logic; use these helpers instead.
"""

from __future__ import annotations

from pathlib import Path

#: Repository root (the directory that contains the ``reconforge/`` package).
PROJECT_ROOT = Path(__file__).resolve().parents[2]

#: Default SQLite database path, relative to :data:`PROJECT_ROOT`.
DEFAULT_DATABASE = "output/reconforge.sqlite3"

#: Root directory for engagement evidence and reports.
DEFAULT_OUTPUT_ROOT = "output"


def resolve_path(path: str | Path, root: Path = PROJECT_ROOT) -> Path:
    """Return *path* as an absolute path, anchored at *root* when relative."""
    candidate = Path(path)
    return candidate if candidate.is_absolute() else root / candidate
