
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reconforge.application.services.discovery import ActiveCheckRunner


class Stage4NmapGateTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

        self.policy = self.root / "scope.json"
        self.policy.write_text(json.dumps({
            "allow": {"ips": ["192.0.2.1"]},
            "exclude": {},
        }))

        self.exclusions = self.root / "exclusions.txt"
        self.exclusions.write_text("")

        self.output = self.root / "output"

        self.inventory = {
            "target": "example.com",
            "target_type": "domain",
            "assets": [
                {"hostname": "example.com"},
                {"hostname": "outside.example.net"},
            ],
        }

        self.config = {
            "active": {
                "enabled": True,
                "require_explicit_asset_approval": True,
                "approved_assets": [
                    "example.com",
                    "outside.example.net",
                ],
                "max_assets": None,
                "http_timeout_seconds": 2,
                "connect_timeout_seconds": 1,
                "tcp_ports": [],
                "delay_seconds": 0,
            },
            "nmap": {
                "enabled": True,
                "udp": {"enabled": False},
            },
        }

    def tearDown(self):
        self.tmp.cleanup()

    @patch(
        "reconforge.application.services.discovery.nmap_recon.resolve_addresses",
        return_value=["192.0.2.1"],
    )
    @patch(
        "reconforge.application.services.discovery.nmap_recon.collect",
        return_value={"tcp": {"parsed": {"hosts": []}}},
    )
    @patch(
        "reconforge.application.services.discovery.tcp_recon.collect",
        return_value={"results": []},
    )
    @patch(
        "reconforge.application.services.discovery.http_recon.collect",
        return_value={"http": {}, "https": {}, "tls": {}},
    )
    def test_authorized_hostname_and_ip_allow_nmap(
        self, http, tcp, nmap, resolve
    ):
        results = ActiveCheckRunner().run(
            self.inventory,
            self.config,
            ["example.com", "outside.example.net"],
            True,
            str(self.policy),
            str(self.exclusions),
            nmap_requested=True,
            output_dir=self.output,
        )

        self.assertEqual(
            results["example.com"]["hostname_approval"],
            "approved",
        )
        self.assertEqual(
            results["example.com"]["approved_addresses"],
            ["192.0.2.1"],
        )
        self.assertEqual(
            results["example.com"]["nmap"]["status"],
            "completed",
        )

        self.assertTrue(results["outside.example.net"]["skipped"])
        http.assert_called_once_with("example.com", timeout=2)
        tcp.assert_called_once()
        nmap.assert_called_once()

        self.assertEqual(
            nmap.call_args.kwargs["scan_targets"],
            ["192.0.2.1"],
        )

    @patch("reconforge.application.services.discovery.nmap_recon.resolve_addresses",
           return_value=["192.0.2.99"])
    @patch("reconforge.application.services.discovery.nmap_recon.collect")
    @patch("reconforge.application.services.discovery.tcp_recon.collect")
    @patch("reconforge.application.services.discovery.http_recon.collect",
           return_value={"http": {}, "https": {}, "tls": {}})
    def test_hostname_checks_run_without_ip_authorization(
        self, http, tcp, nmap, resolve
    ):
        self.policy.write_text(json.dumps({
            "allow": {},
            "exclude": {},
        }))

        results = ActiveCheckRunner().run(
            self.inventory,
            self.config,
            ["example.com"],
            True,
            str(self.policy),
            str(self.exclusions),
            nmap_requested=True,
            output_dir=self.output,
        )

        result = results["example.com"]

        self.assertEqual(result["http_tls"]["status"], "completed")
        self.assertEqual(
            result["http_tls"]["authorization_basis"],
            "explicit_hostname_approval",
        )
        self.assertEqual(
            result["resolved_addresses"],
            ["192.0.2.99"],
        )
        self.assertEqual(result["approved_addresses"], [])
        self.assertEqual(result["tcp"], [])
        self.assertEqual(result["nmap"]["status"], "skipped")

        http.assert_called_once_with("example.com", timeout=2)
        tcp.assert_not_called()
        nmap.assert_not_called()

    @patch("reconforge.application.services.discovery.http_recon.collect")
    @patch("reconforge.application.services.discovery.nmap_recon.resolve_addresses")
    def test_unapproved_hostname_receives_no_active_checks(
        self, resolve, http
    ):
        results = ActiveCheckRunner().run(
            self.inventory,
            self.config,
            [],
            True,
            str(self.policy),
            str(self.exclusions),
            nmap_requested=True,
            output_dir=self.output,
        )

        self.assertEqual(results, {})
        resolve.assert_not_called()
        http.assert_not_called()

    @patch("reconforge.application.services.discovery.http_recon.collect")
    @patch("reconforge.application.services.discovery.nmap_recon.resolve_addresses")
    def test_hostname_exclusion_overrides_approval(
        self, resolve, http
    ):
        self.policy.write_text(json.dumps({
            "allow": {},
            "exclude": {"domains": ["example.com"]},
        }))

        results = ActiveCheckRunner().run(
            self.inventory,
            self.config,
            ["example.com"],
            True,
            str(self.policy),
            str(self.exclusions),
            nmap_requested=True,
            output_dir=self.output,
        )

        self.assertTrue(results["example.com"]["skipped"])
        resolve.assert_not_called()
        http.assert_not_called()

    @patch("reconforge.application.services.discovery.nmap_recon.resolve_addresses",
           return_value=["192.0.2.1"])
    @patch("reconforge.application.services.discovery.nmap_recon.collect")
    @patch("reconforge.application.services.discovery.tcp_recon.collect")
    @patch("reconforge.application.services.discovery.http_recon.collect",
           return_value={"http": {}, "https": {}, "tls": {}})
    def test_ip_exclusion_overrides_ip_allowlist(
        self, http, tcp, nmap, resolve
    ):
        self.policy.write_text(json.dumps({
            "allow": {"ips": ["192.0.2.1"]},
            "exclude": {"ips": ["192.0.2.1"]},
        }))

        results = ActiveCheckRunner().run(
            self.inventory,
            self.config,
            ["example.com"],
            True,
            str(self.policy),
            str(self.exclusions),
            nmap_requested=True,
            output_dir=self.output,
        )

        result = results["example.com"]

        self.assertEqual(result["approved_addresses"], [])
        self.assertEqual(len(result["excluded_addresses"]), 1)
        self.assertEqual(result["nmap"]["status"], "skipped")

        http.assert_called_once()
        tcp.assert_not_called()
        nmap.assert_not_called()

    @patch("reconforge.application.services.discovery.nmap_recon.resolve_addresses",
           return_value=["192.0.2.1"])
    @patch("reconforge.application.services.discovery.nmap_recon.collect",
           return_value={"tcp": {"parsed": {"hosts": []}}})
    @patch("reconforge.application.services.discovery.http_recon.collect",
           side_effect=RuntimeError("HTTP/TLS test failure"))
    def test_http_tls_failure_does_not_suppress_nmap(
        self, http, nmap, resolve
    ):
        results = ActiveCheckRunner().run(
            self.inventory,
            self.config,
            ["example.com"],
            True,
            str(self.policy),
            str(self.exclusions),
            nmap_requested=True,
            output_dir=self.output,
        )

        result = results["example.com"]

        self.assertEqual(result["http_tls"]["status"], "error")
        self.assertEqual(result["nmap"]["status"], "completed")
        nmap.assert_called_once()


if __name__ == "__main__":
    unittest.main()
