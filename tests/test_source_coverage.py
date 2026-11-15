"""Tests for evidence source coverage and the full-port override."""

from __future__ import annotations

import unittest

from reconforge.application.use_cases.discover_assets import (
    apply_full_port_override,
)
from reconforge.domain.evidence_analysis import (
    analyse_source_coverage,
    build_analysis,
)


class SourceCoverageTests(unittest.TestCase):
    """Per-source coverage across passive, intel and active evidence."""

    def test_passive_rows_count_payloads_and_errors(self):
        discover = {
            "passive": {
                "crtsh": {"subdomains": ["a.example.org", "b.example.org"]},
                "dns": {"records": {"A": ["1.2.3.4"], "MX": ["mail.example.org"]}},
                "github": {"error": "rate limited"},
                "wayback": {},
            }
        }

        coverage = analyse_source_coverage(discover)
        rows = {row["source"]: row for row in coverage["rows"]}

        self.assertEqual(rows["crtsh"]["observations"], 2)
        self.assertEqual(rows["crtsh"]["status"], "ok")
        self.assertEqual(rows["crtsh"]["category"], "passive")
        # Two list-valued record fields -> 2 observations.
        self.assertEqual(rows["dns"]["observations"], 2)
        self.assertEqual(rows["github"]["status"], "error")
        self.assertIn("rate limited", rows["github"]["detail"])
        self.assertEqual(rows["wayback"]["observations"], 0)
        self.assertEqual(
            coverage["summary"]["sources_with_errors"], 1
        )

    def test_intel_rows_aggregate_observation_counts_per_source(self):
        intel = {
            "correlated_leads": [
                {
                    "observations": [
                        {"source": "wayback"},
                        {"source": "crtsh"},
                        {"source": "wayback"},
                    ]
                },
                {"observations": [{"source": "crtsh"}]},
            ]
        }

        coverage = analyse_source_coverage({}, intel)
        rows = {row["source"]: row for row in coverage["rows"]}

        self.assertEqual(rows["wayback"]["observations"], 2)
        self.assertEqual(rows["crtsh"]["observations"], 2)
        self.assertEqual(rows["wayback"]["category"], "intel")

    def test_active_probe_rows_only_when_active_evidence_exists(self):
        no_active = analyse_source_coverage({})
        self.assertEqual(
            [row["source"] for row in no_active["rows"]], []
        )

        discover = {
            "passive": {"crtsh": {"subdomains": ["a.example.org"]}},
            "active": {
                "203.0.113.10": {
                    "tcp": {"observations": [{"port": 443}, {"port": 8443}]},
                    "http": {"status_code": 200},
                    "tls": {"protocol": "TLSv1.3"},
                    "nmap": {
                        "tcp": {
                            "parsed": {"hosts": [{"ports": [80, 443, 8443]}]},
                            "scans": [{"returncode": 0}],
                        },
                        "udp": {
                            "parsed": {"hosts": [{"ports": [53, 161]}]},
                            "scans": [{"returncode": 0}],
                        },
                    },
                }
            },
        }

        coverage = analyse_source_coverage(discover)
        rows = {row["source"]: row for row in coverage["rows"]}

        self.assertEqual(rows["tcp_connect"]["observations"], 2)
        self.assertEqual(rows["http_tls"]["observations"], 1)
        self.assertEqual(rows["nmap_tcp_full_range"]["observations"], 3)
        self.assertIn("1 scan(s)", rows["nmap_tcp_full_range"]["detail"])
        self.assertEqual(rows["nmap_udp"]["observations"], 2)

    def test_build_analysis_embeds_coverage_and_summary_counts(self):
        discover = {
            "engagement_id": 1,
            "target": "example.org",
            "target_type": "domain",
            "mode": "external",
            "passive": {"crtsh": {"subdomains": ["a.example.org"]}},
            "assessment": {"findings": [], "port_inventory": []},
            "active": {},
        }

        result = build_analysis(discover)

        self.assertEqual(
            result["summary"]["evidence_sources_reported"], 1
        )
        self.assertEqual(
            result["source_coverage"]["rows"][0]["source"], "crtsh"
        )


class FullPortOverrideTests(unittest.TestCase):
    """``--all-ports`` switches the UDP sweep to the full port range."""

    def test_override_enables_udp_all_ports(self):
        config = {"nmap": {"udp": {"enabled": False, "top_ports": 1000}}}

        apply_full_port_override(config)

        udp = config["nmap"]["udp"]
        self.assertTrue(udp["all_ports"])
        self.assertTrue(udp["enabled"])

    def test_override_creates_missing_nmap_block(self):
        config: dict = {}

        apply_full_port_override(config)

        self.assertTrue(config["nmap"]["udp"]["all_ports"])
        self.assertTrue(config["nmap"]["udp"]["enabled"])

    def test_nmap_tcp_scan_is_always_full_range(self):
        """The TCP inventory command sweeps 1-65535 regardless of config."""
        from reconforge.infrastructure.probes.nmap_recon import _scan_command

        command = _scan_command(
            "nmap", {"timing_template": 2}, "203.0.113.10", 4
        )

        self.assertIn("-p-", command)


if __name__ == "__main__":
    unittest.main()
