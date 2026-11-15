import json
import tempfile
import unittest
from pathlib import Path

from reconforge.domain.scope_policy import is_in_scope


class ScopePolicyTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        self.policy = self.root / "scope.json"
        self.exclusions = self.root / "exclusions.txt"

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
            "# no exclusions\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def check(self, value, target, target_type):
        return is_in_scope(
            value,
            target,
            target_type,
            str(self.policy),
            str(self.exclusions),
        )

    def test_domain_subdomain_allowed(self):
        allowed, _ = self.check(
            "api.example.com",
            "example.com",
            "domain",
        )
        self.assertTrue(allowed)

    def test_unrelated_domain_rejected(self):
        allowed, _ = self.check(
            "example.org",
            "example.com",
            "domain",
        )
        self.assertFalse(allowed)

    def test_domain_suffix_attack_rejected(self):
        allowed, _ = self.check(
            "example.com.attacker.org",
            "example.com",
            "domain",
        )
        self.assertFalse(allowed)

    def test_ip_not_implicitly_in_domain_scope(self):
        allowed, _ = self.check(
            "192.0.2.10",
            "example.com",
            "domain",
        )
        self.assertFalse(allowed)

    def test_network_containment(self):
        allowed, _ = self.check(
            "192.168.1.25",
            "192.168.1.0/24",
            "network",
        )
        self.assertTrue(allowed)

    def test_exclusion_overrides_domain(self):
        self.exclusions.write_text(
            "private.example.com\n",
            encoding="utf-8",
        )

        allowed, _ = self.check(
            "private.example.com",
            "example.com",
            "domain",
        )
        self.assertFalse(allowed)

    def test_domain_engagement_requires_explicit_resolved_ip_allowlist(self):
        allowed, reason = is_in_scope(
            "192.0.2.10", "example.com", "domain",
            self.policy, self.exclusions,
        )
        self.assertFalse(allowed)
        self.assertIn("not explicitly allowlisted", reason)

    def test_domain_engagement_accepts_explicit_ip_allowlist(self):
        self.policy.write_text(json.dumps({
            "allow": {"ips": ["192.0.2.10"]}, "exclude": {}
        }))
        allowed, reason = is_in_scope(
            "192.0.2.10", "example.com", "domain",
            self.policy, self.exclusions,
        )
        self.assertTrue(allowed)
        self.assertIn("explicitly allowlisted", reason)


if __name__ == "__main__":
    unittest.main()
