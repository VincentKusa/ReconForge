import tempfile
import unittest
from pathlib import Path

from reconforge.infrastructure.reporting.pdf_engine import generate


class PdfReportTests(unittest.TestCase):
    def test_pdf_generated_with_inventory_and_findings(self):
        data = {
            "engagement_id": 1, "target": "example.test", "target_type": "domain", "mode": "external",
            "inventory": {"assets": [], "excluded": [], "summary": {"in_scope_hosts": 0}},
            "passive": {}, "active": {
                "example.test": {
                    "http_tls": [{"connected_ip": "192.0.2.1", "result": {"http": {"status": 200}}}],
                    "tcp": [{"connected_ip": "192.0.2.1", "result": {"results": [{"port": 80, "state": "open"}]}}],
                    "nmap": {
                        "artifacts": [{"target_ip": "192.0.2.1", "tcp_xml": "nmap/example.xml"}],
                        "tcp": {"parsed": {"hosts": [{"status": "up", "addresses": [{"address": "192.0.2.1", "type": "ipv4"}], "hostnames": ["example.test"], "os_matches": [], "extraports": [{"state": "closed", "count": 65533, "reasons": []}]}]}},
                    },
                }
            },
            "assessment": {
                "summary": {"ports_recorded": 1, "open_ports": 1, "findings": 1, "severity_counts": {"High": 1}},
                "port_inventory": [{"asset": "example.test", "scan_type": "tcp", "protocol": "tcp", "port": 23, "state": "open", "reason": "syn-ack", "service_name": "telnet", "product": "BusyBox", "version": "1.36", "cpe": []}],
                "findings": [{"id": "NET-1", "title": "Telnet exposed", "severity": "High", "asset": "example.test", "protocol": "tcp", "port": 23, "service": {"name": "telnet", "product": "BusyBox", "version": "1.36"}, "evidence": "port open", "impact": "cleartext", "recommendation": "disable", "verification": "confirm", "confidence": "Medium", "status": "Requires manual validation", "cwe": "CWE-319", "cvss": "Not assigned"}],
                "decision_tree": ["Check scope", "Scan approved host"],
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.pdf"
            generate(data, path)
            self.assertTrue(path.exists())
            self.assertGreater(path.stat().st_size, 1000)
            self.assertEqual(path.read_bytes()[:4], b"%PDF")


if __name__ == "__main__":
    unittest.main()
