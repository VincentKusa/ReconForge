import sys
import tempfile
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1]),
)

import unittest

from reconforge.infrastructure.persistence.database import connect
from reconforge.infrastructure.persistence.evidence_store import add_lead


class Phase2Tests(unittest.TestCase):

    def test_schema_and_lead_dedup(self):

        with tempfile.TemporaryDirectory() as directory:

            db_path = str(
                Path(directory) / "test.db"
            )

            db = connect(db_path)

            cursor = db.execute(
                """
                INSERT INTO engagements
                (
                    target,
                    target_type,
                    mode,
                    authorization_reference,
                    owner,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "example.com",
                    "domain",
                    "external",
                    "ticket-1",
                    "tester",
                    "2026-01-01T00:00:00Z",
                ),
            )

            engagement_id = cursor.lastrowid

            db.commit()
            db.close()

            add_lead(
                db_path,
                engagement_id,
                "hostname",
                "api.example.com",
                "crt.sh",
            )

            add_lead(
                db_path,
                engagement_id,
                "hostname",
                "api.example.com",
                "crt.sh",
            )

            db = connect(db_path)

            count = db.execute(
                "SELECT COUNT(*) FROM leads"
            ).fetchone()[0]

            db.close()

            self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
