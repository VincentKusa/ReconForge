import unittest

from reconforge.application.services.correlation import canonical_value
from reconforge.domain.prioritization import score_correlated_lead


class CorrelationTests(unittest.TestCase):

    def test_hostname_normalization(self):
        self.assertEqual(
            canonical_value(
                "hostname",
                "API.EXAMPLE.COM.",
            ),
            "api.example.com",
        )

    def test_repository_normalization(self):
        self.assertEqual(
            canonical_value(
                "repository",
                "Owner/Project/",
            ),
            "owner/project",
        )

    def test_independent_sources_increase_score(self):

        one_source = {
            "observations": [
                {
                    "source": "crt.sh",
                    "confidence": 70,
                    "relevance": 70,
                    "collected_at": "2026-11-12T00:00:00+00:00",
                }
            ]
        }

        two_sources = {
            "observations": [
                {
                    "source": "crt.sh",
                    "confidence": 70,
                    "relevance": 70,
                    "collected_at": "2026-11-12T00:00:00+00:00",
                },
                {
                    "source": "another-source",
                    "confidence": 70,
                    "relevance": 70,
                    "collected_at": "2026-11-12T00:00:00+00:00",
                },
            ]
        }

        self.assertGreater(
            score_correlated_lead(two_sources)["score"],
            score_correlated_lead(one_source)["score"],
        )


if __name__ == "__main__":
    unittest.main()
