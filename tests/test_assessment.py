from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from reconforge.domain.assessment import (
    build_final_assessment,
    build_review_template,
    merge_review_template,
)
from reconforge.interfaces.cli.app import main as recon_main


class Stage6Tests(unittest.TestCase):
    def setUp(self):
        self.discover = {
            "engagement_id": 7,
            "target": "example.org",
            "target_type": "domain",
            "mode": "external",
            "inventory": {"summary": {"in_scope_hosts": 2, "excluded_observations": 1}},
            "assessment": {
                "findings": [{"id": "REC-1", "title": "Exposed service", "severity": "Medium", "evidence": "TCP/8080 open"}],
                "port_inventory": [],
                "summary": {"findings": 1, "ports_recorded": 0},
            },
        }
        self.analyze = {
            "engagement_id": 7,
            "target": "example.org",
            "summary": {
                "tcp_observations": 1,
                "tcp_open_observations": 1,
                "tcp_error_observations": 0,
                "http_tls_results": 1,
                "intel_correlated_leads": 2,
                "intel_prioritized_leads": 2,
            },
            "observations": {
                "tcp": {"observations": [{"asset": "example.org", "connected_ip": "192.0.2.10", "port": 8080, "state": "open", "interpretation": "Reachability only"}]},
                "http_tls": {"missing_header_observations": [{"asset": "example.org", "scheme": "https", "header": "permissions-policy", "note": "Context review required"}]},
            },
            "nmap": {"example.org": {"status": "partial", "scan_count": 1, "completed_scans": 0, "timed_out_scans": 1, "routing_failed_scans": 0, "ports_parsed": 0}},
            "evidence_gaps": [{"area": "nmap_coverage", "status": "partial", "detail": "Scan timed out"}],
            "intel": {"top_leads": [{"lead_type": "hostname", "canonical_value": "api.example.org", "score": 80, "priority": "investigate", "sources": ["crt.sh"]}]},
        }
        self.intel = {
            "engagement_id": 7,
            "target": "example.org",
            "summary": {"observations_reviewed": 5, "excluded_observations": 0},
            "correlated_leads": [{"canonical_value": "api.example.org"}],
            "prioritized_leads": [{"canonical_value": "api.example.org"}],
        }
        self.db_context = {
            "available": True,
            "engagement": {"id": 7, "target": "example.org", "owner": "assessment-team"},
            "lead_count": 2,
            "lead_sources": {"crt.sh": 2},
            "module_runs": [],
        }
        self.manifest = {"file_count": 3, "counts_by_kind": {"evidence": 1}, "files": [], "hash_algorithm": "SHA-256"}

    def test_default_review_candidates_are_never_confirmed(self):
        review = build_review_template(self.discover, self.analyze)
        self.assertEqual(len(review["items"]), 3)
        self.assertTrue(all(item["review_status"] == "pending" for item in review["items"]))
        result = build_final_assessment(self.intel, self.discover, self.analyze, review, self.db_context, self.manifest)
        self.assertEqual(result["summary"]["confirmed_vulnerabilities"], 0)
        self.assertEqual(result["summary"]["pending_review"], 3)

    def test_confirmed_requires_manual_acceptance_and_complete_evidence(self):
        review = build_review_template(self.discover, self.analyze)
        item = review["items"][0]
        item.update({
            "review_status": "accepted",
            "classification": "confirmed_vulnerability",
            "severity": "High",
            "cve": "CVE-2024-12345",
            "cwe": "CWE-79",
            "cvss_v3_1": {
                "version": "3.1",
                "score": 8.2,
                "severity": "High",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
                "source": "Validated with a CVSS v3.1 calculator",
            },
            "rationale": "Reproduction confirmed the security weakness.",
            "impact": "Unauthorized access to protected service data.",
            "remediation": "Restrict access and enforce authentication.",
            "evidence_refs": ["evidence/reproduction.txt"],
            "reviewer": "tester",
        })
        result = build_final_assessment(self.intel, self.discover, self.analyze, review, self.db_context, self.manifest)
        self.assertEqual(result["summary"]["confirmed_vulnerabilities"], 1)
        self.assertEqual(result["final_findings"][0]["severity"], "High")

    def test_incomplete_confirmed_review_is_not_published(self):
        review = build_review_template(self.discover, self.analyze)
        review["items"][0].update({
            "review_status": "accepted",
            "classification": "confirmed_vulnerability",
            "severity": "High",
        })
        result = build_final_assessment(self.intel, self.discover, self.analyze, review, self.db_context, self.manifest)
        self.assertEqual(result["summary"]["confirmed_vulnerabilities"], 0)
        self.assertGreaterEqual(len(result["review"]["validation_issues"]), 4)


    def test_confirmed_finding_requires_valid_cwe_and_cvss31(self):
        review = build_review_template(self.discover, self.analyze)
        item = review["items"][0]
        item.update({
            "review_status": "accepted",
            "classification": "confirmed_vulnerability",
            "severity": "High",
            "cve": "CVE-2024-12345",
            "cwe": "CWE-79",
            "cvss_v3_1": {
                "version": "3.1", "score": 8.2, "severity": "High",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
                "source": "CVSS v3.1 calculator",
            },
            "rationale": "Validated weakness.",
            "impact": "Demonstrated impact.",
            "remediation": "Apply a verified fix.",
            "evidence_refs": ["evidence/reproduction.txt"],
        })
        result = build_final_assessment(self.intel, self.discover, self.analyze, review, self.db_context, self.manifest)
        self.assertEqual(result["summary"]["confirmed_vulnerabilities"], 1)
        item["cvss_v3_1"]["severity"] = "Critical"
        invalid = build_final_assessment(self.intel, self.discover, self.analyze, review, self.db_context, self.manifest)
        self.assertEqual(invalid["summary"]["confirmed_vulnerabilities"], 0)
        self.assertTrue(any("CVSS severity does not match score" in issue for issue in invalid["review"]["validation_issues"]))

    def test_invalid_cve_cwe_and_cvss_vector_are_rejected(self):
        review = build_review_template(self.discover, self.analyze)
        item = review["items"][0]
        item.update({
            "review_status": "accepted",
            "classification": "confirmed_vulnerability",
            "severity": "High",
            "cve": "CVE-NOT-VALID",
            "cwe": "not-a-cwe",
            "cvss_v3_1": {
                "version": "3.1", "score": 8.2, "severity": "High",
                "vector": "CVSS:3.0/invalid", "source": "manual",
            },
            "rationale": "Validated weakness.",
            "impact": "Demonstrated impact.",
            "remediation": "Apply a verified fix.",
            "evidence_refs": ["evidence/reproduction.txt"],
        })
        result = build_final_assessment(self.intel, self.discover, self.analyze, review, self.db_context, self.manifest)
        self.assertEqual(result["summary"]["confirmed_vulnerabilities"], 0)
        issues = "\n".join(result["review"]["validation_issues"])
        self.assertIn("cve must use CVE-YYYY-NNNN format", issues)
        self.assertIn("cwe must use CWE-N format", issues)
        self.assertIn("invalid CVSS:3.1 base vector syntax", issues)


    def test_old_review_worksheet_is_upgraded_without_losing_decisions(self):
        template = build_review_template(self.discover, self.analyze)
        legacy = dict(template)
        legacy["items"] = [dict(template["items"][0], review_status="deferred", reviewer="analyst")]
        legacy["items"][0].pop("cve", None)
        legacy["items"][0].pop("cvss_v3_1", None)
        merged = merge_review_template(legacy, template)
        self.assertEqual(merged["items"][0]["review_status"], "deferred")
        self.assertEqual(merged["items"][0]["reviewer"], "analyst")
        self.assertIn("cve", merged["items"][0])
        self.assertIn("cvss_v3_1", merged["items"][0])

    def test_intel_is_not_promoted(self):
        review = build_review_template(self.discover, self.analyze)
        result = build_final_assessment(self.intel, self.discover, self.analyze, review, self.db_context, self.manifest)
        self.assertEqual(result["summary"]["intel_correlated_leads"], 1)
        self.assertEqual(result["summary"]["confirmed_vulnerabilities"], 0)
        self.assertEqual(result["intel"]["top_leads"][0]["canonical_value"], "api.example.org")

    def test_identity_mismatch_is_rejected(self):
        review = build_review_template(self.discover, self.analyze)
        bad_stage3 = dict(self.intel, target="other.example")
        with self.assertRaisesRegex(ValueError, "Intel target mismatch"):
            build_final_assessment(bad_stage3, self.discover, self.analyze, review, self.db_context, self.manifest)

    def test_review_merge_preserves_decisions_and_appends_new_candidates(self):
        template = build_review_template(self.discover, self.analyze)
        existing = dict(template)
        existing["items"] = [dict(template["items"][0], review_status="deferred", reviewer="analyst")]
        merged = merge_review_template(existing, template)
        self.assertEqual(merged["items"][0]["review_status"], "deferred")
        self.assertEqual(len(merged["items"]), 3)

    def test_cli_generates_json_markdown_pdf_and_review_template(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            engagement_dir = root / "engagement-7"
            for stage in ("intel", "discover", "analyze"):
                (engagement_dir / stage).mkdir(parents=True)
            (engagement_dir / "evidence").mkdir()
            (engagement_dir / "evidence" / "sample.json").write_text("{}", encoding="utf-8")
            (engagement_dir / "intel" / "intel.json").write_text(json.dumps(self.intel), encoding="utf-8")
            (engagement_dir / "discover" / "discover.json").write_text(json.dumps(self.discover), encoding="utf-8")
            (engagement_dir / "analyze" / "analyze.json").write_text(json.dumps(self.analyze), encoding="utf-8")
            db = root / "reconforge.sqlite3"
            connection = sqlite3.connect(db)
            connection.executescript("""
                CREATE TABLE engagements (id INTEGER PRIMARY KEY, target TEXT, target_type TEXT, mode TEXT, authorization_reference TEXT, owner TEXT, created_at TEXT, status TEXT);
                CREATE TABLE leads (id INTEGER PRIMARY KEY, engagement_id INTEGER, lead_type TEXT, value TEXT, source TEXT, confidence INTEGER, relevance INTEGER, status TEXT, evidence_path TEXT, collected_at TEXT);
                CREATE TABLE module_runs (id INTEGER PRIMARY KEY, engagement_id INTEGER, module TEXT, status TEXT, started_at TEXT, finished_at TEXT, detail TEXT);
                INSERT INTO engagements VALUES (7, 'example.org', 'domain', 'external', 'ticket-7', 'assessment-team', '2026-11-01T00:00:00+00:00', 'registered');
                INSERT INTO leads VALUES (1, 7, 'hostname', 'api.example.org', 'crt.sh', 70, 70, 'unverified', NULL, '2026-11-01T00:00:00+00:00');
            """)
            connection.commit()
            connection.close()
            code = recon_main([
                "report",
                "--engagement", "7",
                "--output-root", str(root),
                "--database", str(db),
                "--reviewer", "test-reviewer",
            ])
            self.assertEqual(code, 0)
            out = engagement_dir / "report"
            for name in ("assessment.json", "review-worksheet.json", "assessment.md", "assessment.pdf"):
                self.assertTrue((out / name).is_file(), name)
            generated = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
            self.assertEqual(generated["summary"]["confirmed_vulnerabilities"], 0)
            self.assertGreater(generated["summary"]["provenance_files"], 0)
            report_text = (out / "assessment.md").read_text(encoding="utf-8")
            self.assertIn("CVSS v3.1", report_text)
            self.assertIn("| CVE | CWE | CVSS v3.1 |", report_text)


if __name__ == "__main__":
    unittest.main()
