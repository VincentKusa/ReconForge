import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reconforge.domain.exposure_rules import build_assessment
from reconforge.infrastructure.probes import http_recon, nmap_recon

XML = '''<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -p- example.test" start="1" version="7.95" xmloutputversion="1.05">
 <host><status state="up" reason="echo-reply"/><address addr="192.0.2.10" addrtype="ipv4"/>
  <hostnames><hostname name="example.test" type="user"/></hostnames>
  <ports>
   <extraports state="closed" count="65533"><extrareasons reason="conn-refused" count="65533"/></extraports>
   <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.2p1" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.2p1</cpe></service></port>
   <port protocol="tcp" portid="23"><state state="open" reason="syn-ack"/><service name="telnet" product="BusyBox telnetd" method="probed" conf="10"/></port>
  </ports>
  <os><osmatch name="Linux 5.4 - 6.8" accuracy="92"><osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="92"><cpe>cpe:/o:linux:linux_kernel</cpe></osclass></osmatch></os>
  <uptime seconds="12345" lastboot="2026-11-12 00:00:00"/><distance value="1"/>
 </host>
 <runstats><finished time="2" elapsed="1.00"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>'''


class NmapTests(unittest.TestCase):
    def test_parse_all_port_service_and_host_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(XML)
            parsed = nmap_recon.parse_nmap_xml(path)
        host = parsed["hosts"][0]
        self.assertEqual(host["addresses"][0]["address"], "192.0.2.10")
        self.assertEqual(host["os_matches"][0]["accuracy"], "92")
        self.assertEqual(host["ports"][0]["service"]["product"], "OpenSSH")
        self.assertEqual(host["ports"][0]["service"]["version"], "9.2p1")
        self.assertEqual(len(host["ports"]), 2)
        self.assertEqual(host["extraports"][0]["count"], 65533)

    def test_exposure_recommendations_do_not_drop_other_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.xml"
            path.write_text(XML)
            scan = {"tcp": {"parsed": nmap_recon.parse_nmap_xml(path)}}
        result = build_assessment({"example.test": scan})
        self.assertEqual(result["summary"]["ports_recorded"], 2)
        self.assertEqual(len(result["findings"]), 3)
        high = [item for item in result["findings"] if item["severity"] == "High"]
        informational = [item for item in result["findings"] if item["severity"] == "Informational"]
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0]["port"], 23)
        self.assertEqual(len(informational), 2)

    @patch("reconforge.infrastructure.probes.nmap_recon._run_scan")
    @patch("reconforge.infrastructure.probes.nmap_recon.shutil.which", return_value="/usr/bin/nmap")
    def test_collect_uses_full_tcp_range_and_service_os_detection(self, _which, run_scan):
        run_scan.return_value = {"parsed": {"hosts": []}, "returncode": 0}
        with tempfile.TemporaryDirectory() as tmp:
            nmap_recon.collect("example.test", tmp, {"enabled": True, "udp": {"enabled": False}}, scan_targets=["192.0.2.10"])
        command = run_scan.call_args.args[0]
        self.assertIn("-p-", command)
        self.assertIn("-sV", command)
        self.assertIn("-O", command)
        self.assertIn("--reason", command)

    @patch("reconforge.infrastructure.probes.nmap_recon.shutil.which", return_value=None)
    def test_missing_nmap_is_clear_error(self, _which):
        with self.assertRaises(FileNotFoundError):
            nmap_recon.collect("192.0.2.10", "/tmp", {})

    @patch("reconforge.infrastructure.probes.http_recon.http_head")
    @patch("reconforge.infrastructure.probes.http_recon.tls_certificate")
    def test_http_tls_uses_hostname_without_pinned_ip(
            self, tls_mock, http_mock
    ):
        http_mock.return_value = {"status": 200}
        tls_mock.return_value = {"protocol": "TLSv1.3"}

        result = http_recon.collect("example.test")

        self.assertEqual(
            result["authorization_basis"],
            "explicit_hostname_approval",
        )
        self.assertIn("http", result)
        self.assertIn("https", result)
        self.assertIn("tls", result)

        http_mock.assert_any_call(
            "example.test", "http", 10
        )
        http_mock.assert_any_call(
            "example.test", "https", 10
        )
        tls_mock.assert_called_once_with(
            "example.test", 443, 10
        )

    @patch("reconforge.infrastructure.probes.nmap_recon._run_scan")
    @patch("reconforge.infrastructure.probes.nmap_recon.shutil.which", return_value="/usr/bin/nmap")
    def test_udp_full_range_is_opt_in(self, _which, run_scan):
        run_scan.return_value = {"parsed": {"hosts": []}, "returncode": 0}
        with tempfile.TemporaryDirectory() as tmp:
            nmap_recon.collect("example.test", tmp, {
                "udp": {"enabled": True, "all_ports": True},
            }, scan_targets=["192.0.2.10"])
        udp_command = run_scan.call_args_list[1].args[0]
        self.assertIn("-sU", udp_command)
        self.assertIn("-p-", udp_command)


if __name__ == "__main__":
    unittest.main()
