"""Regression tests for issues fixed during the refactor.

Each test pins behavior that was previously buggy or duplicated so it
stays fixed: TCP port defaults, argument-gate ordering, shared scope
policy loading, lead extraction, JSON I/O, and Assessment identity checks.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reconforge.domain.assessment import build_final_assessment
from reconforge.domain.leads import extract_leads
from reconforge.domain.scope_policy import is_in_scope, load_exclusions, load_policy
from reconforge.infrastructure.jsonio import load_json, write_json
from reconforge.infrastructure.persistence.evidence_store import add_leads
from reconforge.infrastructure.probes import tcp_recon
from reconforge.interfaces.cli.app import main as recon_main


class TcpPortSelectionTests(unittest.TestCase):
    """collect() must not silently substitute a default port set."""

    def test_none_uses_conservative_defaults(self):
        self.assertEqual(
            tcp_recon.collect("192.0.2.10", ports=None, delay_seconds=0)[
                "ports_checked"
            ],
            list(tcp_recon.DEFAULT_PORTS),
        )

    def test_empty_list_checks_nothing(self):
        result = tcp_recon.collect("192.0.2.10", ports=[], delay_seconds=0)
        self.assertEqual(result["ports_checked"], [])
        self.assertEqual(result["results"], [])

    def test_explicit_ports_are_used_verbatim(self):
        result = tcp_recon.collect("192.0.2.10", ports=[8080], delay_seconds=0)
        self.assertEqual(result["ports_checked"], [8080])


class Stage4GateOrderingTests(unittest.TestCase):
    """--nmap without --active is rejected before any collection work."""

    def test_nmap_without_active_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp)

            # A config path that does not exist proves the check happens
            # before any file/network access.
            code = recon_main(
                [
                    "discover",
                    "--engagement",
                    "1",
                    "--nmap",
                    "--config",
                    str(cwd / "missing.json"),
                    "--database",
                    str(cwd / "missing.sqlite3"),
                ]
            )

        self.assertEqual(code, 2)

    @patch("reconforge.application.services.discovery.tcp_recon.collect", return_value={"results": []})
    @patch("reconforge.application.services.discovery.http_recon.collect", return_value={})
    @patch(
        "reconforge.application.services.discovery.nmap_recon.resolve_addresses",
        return_value=["192.0.2.1"],
    )
    @patch("reconforge.application.services.discovery.nmap_recon.collect", return_value={"tcp": {"parsed": {"hosts": []}}})
    def test_missing_tcp_ports_key_uses_default_list(
        self, _nmap, _resolve, _http, tcp
    ):
        from reconforge.application.services.discovery import ActiveCheckRunner

        config = {
            "active": {
                "enabled": True,
                "require_explicit_asset_approval": True,
                "approved_assets": ["example.com"],
                "max_assets": None,
                "http_timeout_seconds": 2,
                "connect_timeout_seconds": 1,
                "delay_seconds": 0,
                # Note: no tcp_ports key at all.
            },
            "nmap": {"enabled": False},
        }
        inventory = {
            "target": "example.com",
            "target_type": "domain",
            "assets": [{"hostname": "example.com"}],
        }

        with tempfile.TemporaryDirectory() as tmp:
            policy = Path(tmp) / "scope.json"
            policy.write_text(json.dumps({"allow": {"ips": ["192.0.2.1"]}, "exclude": {}}))
            exclusions = Path(tmp) / "exclusions.txt"
            exclusions.write_text("")

            ActiveCheckRunner().run(
                inventory,
                config,
                ["example.com"],
                True,
                str(policy),
                str(exclusions),
                output_dir=Path(tmp),
            )

        self.assertEqual(
            tcp.call_args.kwargs["ports"],
            list(tcp_recon.DEFAULT_PORTS),
        )


class ArchitectureTests(unittest.TestCase):
    """Contracts of the layered clean architecture (v0.8.0)."""

    def test_command_registry_is_complete(self):
        from reconforge.interfaces.cli.commands import COMMANDS_BY_NAME

        self.assertEqual(
            set(COMMANDS_BY_NAME),
            {
                "init",
                "validate",
                "register",
                "engagements",
                "passive",
                "intel",
                "discover",
                "analyze",
                "report",
                "run",
            },
        )

    def test_pipeline_services_expose_no_cli(self):
        import reconforge.application.services.discovery as discovery
        import reconforge.domain.assessment as assessment
        import reconforge.domain.evidence_analysis as evidence_analysis

        for module in (discovery, assessment, evidence_analysis):
            self.assertFalse(hasattr(module, "main"), module.__name__)

    def test_domain_and_use_cases_do_not_import_delivery(self):
        """domain/ and application/use_cases/ stay independent of delivery.

        Application *services* (asset inventory, discovery orchestration,
        correlation) may compose infrastructure adapters directly; the use
        cases themselves and everything under domain/ must not.
        """
        import re

        root = Path(__file__).resolve().parents[1] / "reconforge"
        offenders = []
        for scan_dir in ("domain", "application/use_cases"):
            for path in sorted((root / scan_dir).rglob("*.py")):
                text = path.read_text(encoding="utf-8")
                if re.search(
                    r"^\s*(from|import)\s+reconforge\.(infrastructure|interfaces)\b",
                    text,
                    re.MULTILINE,
                ):
                    offenders.append(str(path.relative_to(root)))

        self.assertEqual(offenders, [])


class ScopePolicyPreloadTests(unittest.TestCase):
    """Preloaded policy/exclusions must behave exactly like file-based checks."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)

        self.policy_path = root / "scope.json"
        self.policy_path.write_text(
            json.dumps({"allow": {"ips": ["192.0.2.1"]}, "exclude": {}})
        )
        self.exclusions_path = root / "exclusions.txt"
        self.exclusions_path.write_text("private.example.com\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_preloaded_matches_file_based(self):
        policy = load_policy(self.policy_path)
        exclusions = load_exclusions(self.exclusions_path)

        for value, target, target_type in [
            ("192.0.2.1", "example.com", "domain"),
            ("private.example.com", "example.com", "domain"),
            ("api.example.com", "example.com", "domain"),
        ]:
            from_file = is_in_scope(value, target, target_type, self.policy_path, self.exclusions_path)
            preloaded = is_in_scope(
                value, target, target_type, policy=policy, exclusions=exclusions
            )
            self.assertEqual(from_file, preloaded, value)


class LeadExtractionTests(unittest.TestCase):
    """One shared extractor drives both passive runners."""

    def test_crtsh_string_hostnames(self):
        leads = list(
            extract_leads("crtsh", {"hostnames": ["api.example.com", "www.example.com"]})
        )

        self.assertEqual(
            [(lead["lead_type"], lead["value"]) for lead in leads],
            [("hostname", "api.example.com"), ("hostname", "www.example.com")],
        )
        self.assertTrue(all(lead["source"] == "crt.sh" for lead in leads))

    def test_archive_limit_is_respected(self):
        urls = [{"original": f"https://page{i}.example.com/"} for i in range(150)]

        leads = list(extract_leads("archive", {"urls": urls}))

        self.assertEqual(len(leads), 100)

    def test_github_top_level_list(self):
        leads = list(
            extract_leads(
                "github",
                [{"url": "https://github.com/owner/repo"}, {"name": "no url here"}],
            )
        )

        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["lead_type"], "repository")

    def test_unknown_connector_yields_nothing(self):
        self.assertEqual(list(extract_leads("nope", {"urls": ["x"]})), [])


class JsonIoTests(unittest.TestCase):
    """Shared JSON helpers validate documents consistently."""

    def test_missing_required_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_json("/nonexistent/path/discover.json")

    def test_missing_optional_file_returns_none(self):
        self.assertIsNone(load_json("/nonexistent/path/discover.json", required=False))

    def test_non_object_document_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "list.json"
            path.write_text("[1, 2, 3]", encoding="utf-8")

            with self.assertRaises(ValueError):
                load_json(path)

    def test_write_json_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.json"
            write_json(path, {"engagement_id": 3})

            self.assertEqual(load_json(path), {"engagement_id": 3})


class BulkLeadInsertTests(unittest.TestCase):
    """add_leads inserts many rows in one connection; duplicates ignored."""

    def test_bulk_insert_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            from reconforge.infrastructure.persistence.database import connect

            db_path = str(Path(tmp) / "test.db")
            db = connect(db_path)
            cursor = db.execute(
                """
                INSERT INTO engagements
                    (target, target_type, mode, authorization_reference, owner, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                ("example.com", "domain", "external", "t", "o", "2026-01-01T00:00:00Z"),
            )
            engagement_id = cursor.lastrowid
            db.commit()
            db.close()

            lead = {
                "lead_type": "hostname",
                "value": "api.example.com",
                "source": "crt.sh",
                "confidence": 70,
                "relevance": 80,
            }

            add_leads(db_path, engagement_id, [lead, lead, dict(lead, value="www.example.com")])

            db = connect(db_path)
            count = db.execute("SELECT COUNT(*) FROM leads").fetchone()[0]
            db.close()

            self.assertEqual(count, 2)


class Stage6IdentityGuardTests(unittest.TestCase):
    """A Discovery artifact without engagement_id is a ValueError, not a crash."""

    def test_missing_engagement_id_raises_value_error(self):
        discover = {"target": "example.org", "assessment": {"findings": []}}

        with self.assertRaises(ValueError):
            build_final_assessment(None, discover, {}, {}, {}, {})


class IntelligenceReportSinglePrioritizeTests(unittest.TestCase):
    """generate_report accepts pre-prioritized input without re-scoring."""

    def test_pre_prioritized_input_is_used_as_is(self):
        from reconforge.infrastructure.reporting.intel_report import generate_report

        correlation = {
            "engagement_id": 1,
            "target": "example.com",
            "target_type": "domain",
            "mode": "external",
            "summary": {
                "observations_reviewed": 1,
                "in_scope_groups": 1,
                "excluded_observations": 0,
            },
            "prioritized_leads": [
                {
                    "lead_type": "hostname",
                    "canonical_value": "api.example.com",
                    "sources": ["crt.sh"],
                    "observations": [
                        {
                            "source": "crt.sh",
                            "evidence_path": "evidence/x.json",
                        }
                    ],
                    "assessment": {"score": 55, "priority": "corroborate", "source_count": 1},
                }
            ],
            "excluded_observations": [],
        }

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.md"
            generate_report(correlation, path)
            text = path.read_text(encoding="utf-8")

        self.assertIn("| corroborate | 55 |", text)
        self.assertIn("api.example.com", text)


if __name__ == "__main__":
    unittest.main()
