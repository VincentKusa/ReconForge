"""Tests for url targets, resolved-IP probing and CVE/CWE/CVSS3 highlighting."""

from __future__ import annotations

import unittest

from reconforge.application.services.discovery import ActiveCheckRunner
from reconforge.domain import cvss3
from reconforge.domain.assessment import (
    _apply_computed_cvss,
    _cvss_validation,
    build_review_template,
)
from reconforge.domain.cvss3 import CvssError
from reconforge.domain.scope import validate_target
from reconforge.domain.scope_policy import is_in_scope
from reconforge.infrastructure.reporting.analysis_report import (
    _findings_section,
    generate_markdown,
)


class UrlTargetTests(unittest.TestCase):
    """The ``url`` target type: validation and scope behavior."""

    def test_https_url_is_accepted_and_normalized(self):
        result = validate_target(
            "https://App.Example.com/login", "url", "external"
        )

        self.assertTrue(result.ok)
        self.assertEqual(result.normalized, "https://app.example.com/login")

    def test_url_without_scheme_or_host_is_rejected(self):
        for raw in ("app.example.com/login", "https://", "ftp://x.example.com"):
            with self.subTest(raw=raw):
                self.assertFalse(validate_target(raw, "url", "external").ok)

    def test_ip_literal_url_is_accepted(self):
        self.assertTrue(
            validate_target("http://203.0.113.10/", "url", "external").ok
        )

    def test_url_scope_follows_the_url_hostname(self):
        allowed, _ = is_in_scope(
            "app.example.com", "https://app.example.com/login", "url",
            policy={"allow": {}, "exclude": {}}, exclusions=[],
        )
        self.assertTrue(allowed)

        allowed, _ = is_in_scope(
            "cdn.app.example.com", "https://app.example.com", "url",
            policy={"allow": {}, "exclude": {}}, exclusions=[],
        )
        self.assertTrue(allowed)

        allowed, reason = is_in_scope(
            "example.com", "https://app.example.com", "url",
            policy={"allow": {}, "exclude": {}}, exclusions=[],
        )
        self.assertFalse(allowed)
        self.assertIn("outside", reason)

    def test_probe_resolved_authorizes_target_addresses_only(self):
        resolved = {"203.0.113.10"}

        allowed, reason = is_in_scope(
            "203.0.113.10", "https://app.example.com", "url",
            policy={"allow": {}, "exclude": {}}, exclusions=[],
            extra_allow=resolved,
        )
        self.assertTrue(allowed)
        self.assertIn("--probe-resolved", reason)

        allowed, _ = is_in_scope(
            "198.51.100.7", "https://app.example.com", "url",
            policy={"allow": {}, "exclude": {}}, exclusions=[],
            extra_allow=resolved,
        )
        self.assertFalse(allowed)

    def test_exclusions_override_probe_resolved(self):
        allowed, reason = is_in_scope(
            "203.0.113.10", "https://app.example.com", "url",
            policy={"allow": {}, "exclude": {"ips": ["203.0.113.10"]}},
            exclusions=[],
            extra_allow={"203.0.113.10"},
        )
        self.assertFalse(allowed)
        self.assertIn("exclusion", reason)


class ProbeResolvedRunnerTests(unittest.TestCase):
    """Asset selection and address classification with --probe-resolved."""

    def test_probe_host_is_selected_even_without_inventory(self):
        runner = ActiveCheckRunner()

        selected = runner._select_assets(
            [], {"assets": []}, probe_host="app.example.com"
        )

        self.assertEqual(selected, ["app.example.com"])

    def test_select_assets_intersects_and_adds_probe_host(self):
        runner = ActiveCheckRunner()
        inventory = {
            "assets": [
                {"hostname": "app.example.com"},
                {"hostname": "www.example.com"},
            ]
        }

        selected = runner._select_assets(
            ["app.example.com"], inventory, probe_host="app.example.com"
        )

        self.assertEqual(selected, ["app.example.com"])

    def test_classify_addresses_splits_groups_with_extra_allow(self):
        runner = ActiveCheckRunner()
        inventory = {"target": "https://app.example.com", "target_type": "url"}

        approved, excluded, unauthorized = runner._classify_addresses(
            ["203.0.113.10", "203.0.113.99"],
            inventory,
            {"allow": {}, "exclude": {}},
            [],
            extra_allow={"203.0.113.10"},
        )

        self.assertEqual(approved, ["203.0.113.10"])
        self.assertEqual(excluded, [])
        self.assertEqual(
            [item["address"] for item in unauthorized], ["203.0.113.99"]
        )


class CvssCalculatorTests(unittest.TestCase):
    """CVSS v3.1 base-score math against known spec scores."""

    def test_known_spec_scores(self):
        vectors = {
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N": 6.4,
            "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
        }
        for vector, expected in vectors.items():
            with self.subTest(vector=vector):
                self.assertEqual(cvss3.base_score(vector), expected)

    def test_severity_bands(self):
        self.assertEqual(cvss3.severity(0.0), "Informational")
        self.assertEqual(cvss3.severity(3.9), "Low")
        self.assertEqual(cvss3.severity(4.0), "Medium")
        self.assertEqual(cvss3.severity(6.9), "Medium")
        self.assertEqual(cvss3.severity(7.0), "High")
        self.assertEqual(cvss3.severity(8.9), "High")
        self.assertEqual(cvss3.severity(9.0), "Critical")
        self.assertEqual(cvss3.severity(10.0), "Critical")

    def test_invalid_vectors_raise(self):
        for vector in (
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # missing prefix
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H",  # missing I/A
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # bad value
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L",  # duplicate
        ):
            with self.subTest(vector=vector):
                with self.assertRaises(CvssError):
                    cvss3.base_score(vector)

    def test_assess_block_shape(self):
        block = cvss3.assess("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

        self.assertEqual(block["score"], 9.8)
        self.assertEqual(block["severity"], "Critical")
        self.assertEqual(block["version"], "3.1")
        self.assertIn("vector", block)
        self.assertIn("source", block)


class AssessmentCvssIntegrationTests(unittest.TestCase):
    """Vector-only review items get computed score/severity; the discovery
    finding's CWE is prefilled into the worksheet."""

    def test_vector_only_item_gets_computed_score(self):
        item = {
            "item_id": "S4-F-0001",
            "cvss_v3_1": {
                "version": "3.1",
                "score": None,
                "severity": None,
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "source": None,
            },
        }

        _apply_computed_cvss(item)

        self.assertEqual(item["cvss_v3_1"]["score"], 9.8)
        self.assertEqual(item["cvss_v3_1"]["severity"], "Critical")
        self.assertIn("calculator", str(item["cvss_v3_1"]["source"]))
        self.assertEqual(_cvss_validation(item), [])

    def test_supplied_score_mismatch_is_flagged(self):
        item = {
            "item_id": "S4-F-0002",
            "cvss_v3_1": {
                "version": "3.1",
                "score": 5.0,
                "severity": "Medium",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "source": "manual",
            },
        }

        issues = _cvss_validation(item)

        self.assertTrue(
            any("does not match the vector-derived score 9.8" in i for i in issues)
        )

    def test_review_template_prefills_cwe_from_finding(self):
        discover = {
            "engagement_id": 1,
            "target": "example.org",
            "assessment": {
                "findings": [
                    {
                        "title": "FTP service exposed",
                        "severity": "Medium",
                        "cwe": "CWE-319",
                        "description": "FTP reachable",
                    }
                ]
            },
        }

        template = build_review_template(discover, {})

        self.assertEqual(template["items"][0]["cwe"], "CWE-319")
        self.assertEqual(template["items"][0]["source_severity"], "Medium")


class ReportHighlightingTests(unittest.TestCase):
    """The analysis report highlights severity, CWE, CVE and CVSS v3.1."""

    def _analysis(self):
        return {
            "engagement_id": 1,
            "target": "example.org",
            "target_type": "domain",
            "mode": "external",
            "technical_assessment": {
                "findings": [
                    {
                        "title": "FTP service exposed",
                        "severity": "Medium",
                        "cwe": "CWE-319",
                        "cvss": "Not assigned: exposure alone is insufficient.",
                        "description": "FTP reachable",
                        "evidence": "Nmap reported open on tcp/21.",
                    }
                ]
            },
            "observations": {"tcp": {}, "http_tls": {}},
            "nmap": {},
            "evidence_gaps": [],
        }

    def test_findings_section_highlights_identifiers(self):
        lines: list[str] = []
        _findings_section(self._analysis(), lines)
        text = "\n".join(lines)

        self.assertIn("**Severity roll-up:** Medium 1", text)
        self.assertIn("**Severity:** **MEDIUM**", text)
        self.assertIn("**CWE:** CWE-319", text)
        self.assertIn("**CVE:** No applicable CVE established", text)
        self.assertIn("Not assigned: exposure alone is insufficient.", text)

    def test_findings_section_renders_cvss_block_when_present(self):
        analysis = self._analysis()
        analysis["technical_assessment"]["findings"][0]["cvss_v3_1"] = {
            "version": "3.1",
            "score": 5.3,
            "severity": "Medium",
            "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
            "source": "reviewer",
        }

        lines: list[str] = []
        _findings_section(analysis, lines)
        text = "\n".join(lines)

        self.assertIn("**CVSS v3.1:** **5.3 (Medium)**", text)
        self.assertIn("AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L", text)

    def test_full_markdown_contains_coverage_and_findings(self):
        import tempfile
        from pathlib import Path

        analysis = self._analysis()
        analysis["summary"] = {}
        analysis["source_coverage"] = {"rows": [], "summary": {}}
        analysis["intel"] = {}

        with tempfile.TemporaryDirectory() as tmp:
            path = generate_markdown(analysis, Path(tmp) / "report.md")
            text = Path(path).read_text()

        self.assertIn("## 3. Technical Findings", text)
        self.assertIn("## 8. Evidence Source Coverage", text)
        self.assertIn("**Severity:** **MEDIUM**", text)


if __name__ == "__main__":
    unittest.main()
