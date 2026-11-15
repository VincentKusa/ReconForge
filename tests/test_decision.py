import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1]),
)

import unittest

from reconforge.domain.triage import (
    next_action,
    score_lead,
)


class DecisionTests(unittest.TestCase):

    def test_high_score(self):
        self.assertEqual(
            score_lead(
                True,
                True,
                True,
                True,
                True,
            )["priority"],
            "high",
        )

    def test_out_of_scope_stops(self):
        self.assertEqual(
            next_action(
                {"confidence": 99},
                False,
            ),
            "exclude",
        )

    def test_low_confidence_corroborates(self):
        self.assertEqual(
            next_action(
                {"confidence": 20},
                True,
            ),
            "seek_corroboration",
        )


if __name__ == "__main__":
    unittest.main()
