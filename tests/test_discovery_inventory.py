import json
import tempfile
import unittest
from pathlib import Path

from reconforge.application.services.asset_inventory import build_inventory
from reconforge.infrastructure.persistence.database import connect
from reconforge.infrastructure.persistence.evidence_store import add_lead


class Stage4InventoryTests(unittest.TestCase):

    def test_wayback_url_inventory_and_exclusion(self):

        with tempfile.TemporaryDirectory() as directory:

            root = Path(directory)

            database = root / "test.db"
            policy = root / "scope.json"
            exclusions = root / "exclusions.txt"

            policy.write_text(
                json.dumps({
                    "allow": {
                        "domains": [],
                        "ips": [],
                        "cidrs": [],
                        "assets": [],
                    },
                    "exclude": {
                        "domains": [],
                        "ips": [],
                        "cidrs": [],
                        "assets": [],
                    },
                }),
                encoding="utf-8",
            )

            exclusions.write_text(
                "private.example.com\n",
                encoding="utf-8",
            )

            db = connect(str(database))

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
                    "2026-11-12T00:00:00Z",
                ),
            )

            engagement_id = cursor.lastrowid

            db.commit()
            db.close()

            add_lead(
                str(database),
                engagement_id,
                "historical_url",
                "https://api.example.com/login",
                "wayback_machine",
            )

            add_lead(
                str(database),
                engagement_id,
                "historical_url",
                "https://private.example.com/admin",
                "wayback_machine",
            )

            result = build_inventory(
                str(database),
                engagement_id,
                str(policy),
                str(exclusions),
            )

            hosts = {
                item["hostname"]
                for item in result["assets"]
            }

            self.assertIn("example.com", hosts)
            self.assertIn("api.example.com", hosts)

            self.assertEqual(
                result["summary"]["excluded_observations"],
                1,
            )

            self.assertNotIn(
                "private.example.com",
                hosts,
            )


if __name__ == "__main__":
    unittest.main()
