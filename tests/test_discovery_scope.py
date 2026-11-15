import json
import tempfile
import unittest
from pathlib import Path

from reconforge.domain.scope_policy import is_in_scope


class Stage4ScopeTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)

        self.policy = root / "scope.json"
        self.exclusions = root / "exclusions.txt"

        self.policy.write_text(
            json.dumps({
                "allow": {
                    "domains": [],
                    "ips": [],
                    "cidrs": [],
                    "assets": [],
                    "repositories": [],
                    "cloud_accounts": [],
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

        self.exclusions.write_text(
            "private.example.com\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def check(self, value):
        return is_in_scope(
            value,
            "example.com",
            "domain",
            str(self.policy),
            str(self.exclusions),
        )

    def test_root_domain(self):
        self.assertTrue(self.check("example.com")[0])

    def test_subdomain(self):
        self.assertTrue(self.check("api.example.com")[0])

    def test_excluded_subdomain(self):
        self.assertFalse(
            self.check("private.example.com")[0]
        )

    def test_suffix_spoof(self):
        self.assertFalse(
            self.check("example.com.attacker.org")[0]
        )

    def test_ip_not_in_domain_scope(self):
        self.assertFalse(
            self.check("192.0.2.10")[0]
        )

    def test_unrelated_domain(self):
        self.assertFalse(
            self.check("example.org")[0]
        )


if __name__ == "__main__":
    unittest.main()
