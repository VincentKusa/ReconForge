"""SQLite persistence for engagements, leads, and module runs.

All engagement-row SQL lives here so the CLI, correlation and inventory
code share one implementation instead of repeating queries.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from reconforge.shared.clock import utcnow

SCHEMA = """
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    target_type TEXT NOT NULL,
    mode TEXT NOT NULL,
    authorization_reference TEXT NOT NULL,
    owner TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'registered'
);

CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    lead_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 0
        CHECK(confidence BETWEEN 0 AND 100),
    relevance INTEGER NOT NULL DEFAULT 0
        CHECK(relevance BETWEEN 0 AND 100),
    status TEXT NOT NULL DEFAULT 'unverified',
    evidence_path TEXT,
    collected_at TEXT NOT NULL,
    UNIQUE(engagement_id, lead_type, value, source)
);

CREATE TABLE IF NOT EXISTS module_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id),
    module TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    detail TEXT
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    """Open a database and ensure the schema exists."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    db = sqlite3.connect(target)
    db.executescript(SCHEMA)

    return db


def fetch_engagement(db: sqlite3.Connection, engagement_id: int) -> dict[str, Any] | None:
    """Return the engagement row as a dict, or None when it does not exist."""
    row = db.execute(
        """
        SELECT target, target_type, mode
        FROM engagements
        WHERE id=?
        """,
        (engagement_id,),
    ).fetchone()

    if not row:
        return None

    return {
        "target": row[0],
        "target_type": row[1],
        "mode": row[2],
    }


def get_engagement(db_path: str | Path, engagement_id: int) -> dict[str, Any] | None:
    """Open *db_path*, fetch one engagement, and close the connection."""
    db = connect(db_path)
    try:
        return fetch_engagement(db, engagement_id)
    finally:
        db.close()


def register_engagement(
    db_path: str | Path,
    target: str,
    target_type: str,
    mode: str,
    authorization_reference: str,
    owner: str,
) -> int:
    """Insert an authorized engagement and return its generated ID."""
    db = connect(db_path)
    try:
        cursor = db.execute(
            """
            INSERT INTO engagements
                (target, target_type, mode,
                 authorization_reference, owner, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (target, target_type, mode, authorization_reference, owner, utcnow()),
        )
        db.commit()
        return int(cursor.lastrowid)
    finally:
        db.close()


def list_engagements(db_path: str | Path) -> list[dict[str, Any]]:
    """Return registered engagements, newest first."""
    db = connect(db_path)
    try:
        rows = db.execute(
            """
            SELECT id, target, target_type, mode, owner, status, created_at
            FROM engagements
            ORDER BY id DESC
            """
        ).fetchall()
    finally:
        db.close()

    keys = ("id", "target", "target_type", "mode", "owner", "status", "created_at")
    return [dict(zip(keys, row, strict=True)) for row in rows]
