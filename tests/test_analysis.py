
import unittest

from reconforge.domain.evidence_analysis import (
    analyse_intel,
    analyse_nmap,
    analyse_tcp,
    build_analysis,
)


class Stage5Tests(unittest.TestCase):

    def test_empty_assessment_is_not_vulnerability_free_claim(self):
        discover = {
            "engagement_id": 2,
            "target": "example.org",
            "target_type": "domain",
            "mode": "external",
            "assessment": {
                "findings": [],
                "port_inventory": [],
                "summary": {"severity_counts": {}},
            },
            "active": {},
        }

        result = build_analysis(discover)

        self.assertEqual(
            result["summary"]["technical_findings_recorded"], 0
        )
        self.assertTrue(
            any(
                gap["area"] == "technical_assessment"
                for gap in result["evidence_gaps"]
            )
        )
        self.assertTrue(
            any(
                "not proof" in rule
                for rule in result["interpretation_rules"]
            )
        )

    def test_nmap_timeout_is_partial(self):
        nmap = {
            "status": "completed",
            "tcp": {
                "scans": [
                    {
                        "timed_out": True,
                        "parsed": {
                            "hosts": [],
                            "parse_error": "incomplete XML",
                        },
                    }
                ],
                "parsed": {"hosts": []},
            },
        }

        result = analyse_nmap(nmap)

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["timed_out_scans"], 1)

    def test_nmap_route_failure_is_not_completed_coverage(self):
        nmap = {
            "status": "completed",
            "tcp": {
                "scans": [
                    {
                        "returncode": 0,
                        "stderr": "setup_target: failed to determine route",
                        "parsed": {"hosts": []},
                    }
                ],
                "parsed": {"hosts": []},
            },
        }

        result = analyse_nmap(nmap)

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["failed_scans"], 1)

    def test_tcp_open_is_observation_not_vulnerability(self):
        active = {
            "example.org": {
                "tcp": [
                    {
                        "connected_ip": "192.0.2.10",
                        "result": {
                            "results": [
                                {
                                    "host": "192.0.2.10",
                                    "port": 443,
                                    "state": "open",
                                }
                            ]
                        },
                    }
                ]
            }
        }

        result = analyse_tcp(active)

        self.assertEqual(result["state_counts"]["open"], 1)
        self.assertIn(
            "Connectivity observation only",
            result["observations"][0]["interpretation"],
        )

    def test_stage3_leads_remain_intelligence(self):
        intel = {
            "correlated_leads": [
                {"canonical_value": "api.example.org"}
            ],
            "prioritized_leads": [
                {
                    "lead_type": "hostname",
                    "canonical_value": "api.example.org",
                    "assessment": {
                        "score": 80,
                        "priority": "investigate",
                    },
                    "observations": [],
                }
            ],
        }

        result = analyse_intel(intel)

        self.assertEqual(result["correlated_leads"], 1)
        self.assertEqual(result["prioritized_leads"], 1)
        self.assertEqual(
            result["top_leads"][0]["classification"],
            "reconnaissance_lead_not_vulnerability",
        )

    def test_tcp_errors_are_counted(self):
        active = {
            "example.org": {
                "tcp": [
                    {
                        "connected_ip": "2001:db8::1",
                        "result": {
                            "results": [
                                {
                                    "host": "2001:db8::1",
                                    "port": 443,
                                    "state": "error",
                                    "error": "Network is unreachable",
                                }
                            ]
                        },
                    }
                ]
            }
        }

        result = analyse_tcp(active)

        self.assertEqual(result["state_counts"]["error"], 1)
        self.assertEqual(len(result["errors"]), 1)


if __name__ == "__main__":
    unittest.main()
