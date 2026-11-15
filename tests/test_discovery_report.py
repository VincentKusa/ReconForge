
import tempfile
import unittest
from pathlib import Path

from reconforge.infrastructure.reporting.discovery_report import generate


class Stage4ReportTests(unittest.TestCase):

    def _data(self, nmap_status, reason=None):
        return {
            "engagement_id": 2,
            "target": "example.test",
            "mode": "external",
            "inventory": {
                "summary": {
                    "in_scope_hosts": 1,
                    "excluded_observations": 0,
                },
                "assets": [
                    {
                        "hostname": "example.test",
                        "sources": ["registered_engagement"],
                    }
                ],
                "excluded": [],
            },
            "passive": {},
            "active": {
                "example.test": {
                    "nmap": {
                        "status": nmap_status,
                        "reason": reason,
                    },
                    "http_tls": {"status": "completed"},
                }
            },
            "assessment": {
                "port_inventory": [],
                "findings": [],
                "decision_tree": [],
            },
        }

    def _render(self, data):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.md"
            generate(data, path)
            return path.read_text(encoding="utf-8")

    def test_skipped_nmap_is_not_reported_as_empty_scan(self):
        report = self._render(
            self._data("skipped", "No IP address authorized")
        )

        self.assertIn(
            "Nmap was not executed",
            report,
        )
        self.assertIn(
            "must not be interpreted as evidence",
            report,
        )
        self.assertIn(
            "No IP address authorized",
            report,
        )

    def test_completed_nmap_with_no_records_is_distinguished(self):
        report = self._render(self._data("completed"))

        self.assertIn(
            "Nmap completed but returned no individual port records",
            report,
        )

    def test_failed_nmap_is_reported_as_incomplete(self):
        report = self._render(
            self._data("error", "Nmap process timed out")
        )

        self.assertIn(
            "Inventory status: The port inventory is incomplete",
            report,
        )
        self.assertIn(
            "Nmap process timed out",
            report,
        )


if __name__ == "__main__":
    unittest.main()

