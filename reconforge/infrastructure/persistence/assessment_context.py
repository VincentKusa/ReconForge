"""Read-only access to engagement database context and input provenance.

Extracted from the assessment domain module: SQLite reads and file
hashing are infrastructure concerns, while assessment assembly stays pure.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import quote

from reconforge.shared.paths import PROJECT_ROOT


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_entry(path: Path, base: Path, kind: str) -> dict[str, Any]:
    stat = path.stat()
    return {
        "path": path.relative_to(base).as_posix(),
        "kind": kind,
        "size_bytes": stat.st_size,
        "sha256": _sha256(path),
    }


class AssessmentContextReader:
    """Read-only engagement metadata and provenance for the assessment step."""

    def database_context(self, database: Path, engagement_id: int) -> dict[str, Any]:
        """Read registration and collection metadata without mutation."""
        if not database.exists():
            return {
                "available": False,
                "database_path": str(database),
                "reason": "SQLite database was not present; registration metadata unavailable.",
                "engagement": None,
                "lead_count": 0,
                "lead_sources": {},
                "module_runs": [],
            }

        uri = f"file:{quote(str(database.resolve()))}?mode=ro"
        try:
            connection = sqlite3.connect(uri, uri=True)
            connection.row_factory = sqlite3.Row

            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }

            engagement = None
            lead_count = 0
            lead_sources: dict[str, int] = {}
            module_runs: list[dict[str, Any]] = []

            if "engagements" in tables:
                row = connection.execute(
                    "SELECT id, target, target_type, mode, authorization_reference, "
                    "owner, created_at, status FROM engagements WHERE id=?",
                    (engagement_id,),
                ).fetchone()
                engagement = dict(row) if row else None

            if "leads" in tables:
                lead_count = connection.execute(
                    "SELECT COUNT(*) FROM leads WHERE engagement_id=?",
                    (engagement_id,),
                ).fetchone()[0]
                lead_sources = {
                    str(row[0]): int(row[1])
                    for row in connection.execute(
                        "SELECT source, COUNT(*) FROM leads WHERE engagement_id=? "
                        "GROUP BY source ORDER BY source",
                        (engagement_id,),
                    ).fetchall()
                }

            if "module_runs" in tables:
                module_runs = [
                    dict(row)
                    for row in connection.execute(
                        "SELECT module, status, started_at, finished_at, detail "
                        "FROM module_runs WHERE engagement_id=? ORDER BY id",
                        (engagement_id,),
                    ).fetchall()
                ]

            connection.close()
        except sqlite3.Error as exc:
            raise ValueError(
                f"Could not read engagement database {database}: {exc}"
            ) from exc

        return {
            "available": True,
            "database_path": str(database),
            "engagement": engagement,
            "lead_count": lead_count,
            "lead_sources": lead_sources,
            "module_runs": module_runs,
        }

    def source_manifest(
        self,
        engagement_dir: Path,
        database: Path,
        input_paths: list[Path],
    ) -> dict[str, Any]:
        """Hash all engagement inputs, evidence and Nmap artifacts."""
        entries: list[dict[str, Any]] = []
        seen: set[Path] = set()

        for path in input_paths:
            if path.exists() and path.is_file() and path not in seen:
                entries.append(_manifest_entry(path, engagement_dir, "stage_input"))
                seen.add(path)

        for subdir, kind in (
            ("evidence", "evidence"),
            (Path("discover") / "nmap", "nmap_artifact"),
        ):
            directory = engagement_dir / subdir
            if directory.exists():
                for path in sorted(directory.rglob("*")):
                    if path.is_file() and path not in seen:
                        entries.append(_manifest_entry(path, engagement_dir, kind))
                        seen.add(path)

        if database.exists():
            try:
                database_label = database.resolve().relative_to(
                    PROJECT_ROOT.resolve()
                ).as_posix()
            except ValueError:
                database_label = str(database)
            entries.append(
                {
                    "path": database_label,
                    "kind": "sqlite_database",
                    "size_bytes": database.stat().st_size,
                    "sha256": _sha256(database),
                }
            )

        counts = Counter(item["kind"] for item in entries)
        return {
            "file_count": len(entries),
            "counts_by_kind": dict(counts),
            "files": entries,
            "hash_algorithm": "SHA-256",
        }
