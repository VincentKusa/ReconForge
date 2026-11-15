"""Evidence and lead persistence (SQLite + JSON evidence files)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconforge.domain.leads import extract_leads
from reconforge.infrastructure.persistence.database import connect
from reconforge.shared.clock import utcnow


def save_json_evidence(
    engagement_id: int,
    source: str,
    data: Any,
    db_path: str | Path = "",
    output_root: str | Path = "output",
) -> str:
    """Write raw connector output to the engagement evidence directory."""
    root = (
        Path(output_root)
        / f"engagement-{engagement_id}"
        / "evidence"
    )

    root.mkdir(parents=True, exist_ok=True)

    safe = "".join(
        c if c.isalnum() or c in "-_" else "_"
        for c in source.lower()
    )

    timestamp = utcnow().replace(":", "").replace("+", "_")
    path = root / f"{safe}-{timestamp}.json"

    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return str(path)


def _insert_leads(
    db: Any,
    engagement_id: int,
    leads: list[dict[str, Any]],
    evidence_path: str | None,
) -> None:
    db.executemany(
        """
        INSERT OR IGNORE INTO leads
            (engagement_id, lead_type, value, source,
             confidence, relevance, status, evidence_path, collected_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                engagement_id,
                lead["lead_type"],
                lead["value"],
                lead["source"],
                int(lead.get("confidence", 50)),
                int(lead.get("relevance", 50)),
                lead.get("status", "unverified"),
                lead.get("evidence_path", evidence_path),
                utcnow(),
            )
            for lead in leads
        ],
    )
    db.commit()


def add_leads(
    db_path: str | Path,
    engagement_id: int,
    leads: list[dict[str, Any]],
    evidence_path: str | None = None,
) -> None:
    """Insert many leads in one transaction (duplicates are ignored)."""
    if not leads:
        return

    db = connect(db_path)
    try:
        _insert_leads(db, engagement_id, leads, evidence_path)
    finally:
        db.close()


def add_lead(
    db_path: str | Path,
    engagement_id: int,
    lead_type: str,
    value: str,
    source: str,
    confidence: int = 50,
    relevance: int = 50,
    status: str = "unverified",
    evidence_path: str | None = None,
) -> None:
    """Insert a single lead; duplicates (same type/value/source) are ignored."""
    add_leads(
        db_path,
        engagement_id,
        [
            {
                "lead_type": lead_type,
                "value": value,
                "source": source,
                "confidence": confidence,
                "relevance": relevance,
                "status": status,
            }
        ],
        evidence_path=evidence_path,
    )


class EvidenceStore:
    """Lead/evidence adapter bound to one database and output root."""

    def __init__(self, database_path: str | Path, output_root: str | Path):
        self._database_path = database_path
        self._output_root = Path(output_root)

    # -- LeadRepository port ---------------------------------------------

    def add(
        self,
        engagement_id: int,
        leads: list[dict[str, Any]],
        evidence_path: str | None = None,
    ) -> None:
        add_leads(self._database_path, engagement_id, leads, evidence_path)

    def record_connector(
        self,
        engagement_id: int,
        connector: str,
        data: Any,
        evidence_path: str | None = None,
    ) -> int:
        """Derive and persist the leads of one connector payload; return count."""
        leads = list(extract_leads(connector, data))

        if leads:
            add_leads(
                self._database_path,
                engagement_id,
                leads,
                evidence_path=evidence_path,
            )

        return len(leads)

    def save_evidence(self, engagement_id: int, source: str, data: Any) -> str:
        return save_json_evidence(
            engagement_id,
            source,
            data,
            output_root=self._output_root,
        )
