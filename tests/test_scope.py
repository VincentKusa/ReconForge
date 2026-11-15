import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1]),
)

import unittest

from reconforge.domain.scope import validate_target


class ScopeTests(unittest.TestCase):

    def test_domain(self):
        self.assertTrue(
            validate_target(
                "Example.COM",
                "domain",
                "external",
            ).ok
        )

    def test_bad_domain(self):
        self.assertFalse(
            validate_target(
                "https://example.com",
                "domain",
                "external",
            ).ok
        )

    def test_network(self):

        result = validate_target(
            "192.168.1.7/24",
            "network",
            "internal",
        )

        self.assertTrue(result.ok)

        self.assertEqual(
            result.normalized,
            "192.168.1.0/24",
        )

    def test_person_disabled(self):
        self.assertFalse(
            validate_target(
                "alice",
                "username",
                "external",
            ).ok
        )

    def test_person_enabled(self):
        self.assertTrue(
            validate_target(
                "alice",
                "username",
                "external",
                True,
            ).ok
        )

    def test_cloud_account(self):
        self.assertTrue(
            validate_target(
                "aws:123456789012",
                "cloud-account",
                "cloud",
            ).ok
        )


if __name__ == "__main__":
    unittest.main()
