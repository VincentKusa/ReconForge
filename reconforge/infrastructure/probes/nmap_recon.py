"""Nmap inventory for explicitly approved assets.

Runs version detection and OS fingerprinting without NSE vulnerability
scripts. Raw .nmap, .gnmap and .xml outputs are retained alongside
normalized results.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

OUTPUT_TAIL_LIMIT = 20_000


def _safe_name(value: str) -> str:
    """Reduce a host/IP string to a filesystem-safe filename component."""
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return cleaned[:100] or "target"


def resolve_addresses(host: str) -> list[str]:
    """Resolve a hostname once so active checks can be pinned to approved IPs."""
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass

    results: set[str] = set()

    for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        address = item[4][0].split("%", 1)[0]
        try:
            results.add(str(ipaddress.ip_address(address)))
        except ValueError:
            continue

    # IPv4 first, then IPv6, each group sorted lexically.
    return sorted(results, key=lambda value: (":" in value, value))


def _service(port_el: ET.Element) -> dict[str, Any]:
    service = port_el.find("service")

    if service is None:
        return {}

    return {
        "name": service.get("name"),
        "product": service.get("product"),
        "version": service.get("version"),
        "extrainfo": service.get("extrainfo"),
        "tunnel": service.get("tunnel"),
        "method": service.get("method"),
        "conf": service.get("conf"),
        "ostype": service.get("ostype"),
        "device_type": service.get("devicetype"),
        "cpe": [node.text for node in service.findall("cpe") if node.text],
    }


def parse_nmap_xml(xml_path: str | Path) -> dict[str, Any]:
    """Parse one Nmap XML file into a normalized host/port structure."""
    root = ET.parse(xml_path).getroot()

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        addresses = [
            {
                "address": node.get("addr"),
                "type": node.get("addrtype"),
                "vendor": node.get("vendor"),
            }
            for node in host.findall("address")
        ]
        hostnames = [
            node.get("name")
            for node in host.findall("./hostnames/hostname")
            if node.get("name")
        ]

        ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            ports.append(
                {
                    "protocol": port.get("protocol"),
                    "port": int(port.get("portid", "0")),
                    "state": state.get("state") if state is not None else "unknown",
                    "reason": state.get("reason") if state is not None else None,
                    "reason_ttl": state.get("reason_ttl") if state is not None else None,
                    "service": _service(port),
                }
            )

        os_matches = []
        for match in host.findall("./os/osmatch"):
            os_matches.append(
                {
                    "name": match.get("name"),
                    "accuracy": match.get("accuracy"),
                    "line": match.get("line"),
                    "classes": [
                        {
                            "type": c.get("type"),
                            "vendor": c.get("vendor"),
                            "osfamily": c.get("osfamily"),
                            "osgen": c.get("osgen"),
                            "accuracy": c.get("accuracy"),
                            "cpe": [x.text for x in c.findall("cpe") if x.text],
                        }
                        for c in match.findall("./osclass")
                    ],
                }
            )

        extraports = [
            {
                "state": extra.get("state"),
                "count": int(extra.get("count", "0")),
                "reasons": [dict(reason.attrib) for reason in extra.findall("extrareasons")],
            }
            for extra in host.findall("./ports/extraports")
        ]

        uptime = host.find("uptime")
        distance = host.find("distance")

        hosts.append(
            {
                "status": status.get("state") if status is not None else "unknown",
                "status_reason": status.get("reason") if status is not None else None,
                "addresses": addresses,
                "hostnames": hostnames,
                "ports": sorted(ports, key=lambda x: (x["protocol"] or "", x["port"])),
                "extraports": extraports,
                "os_matches": os_matches,
                "uptime_seconds": uptime.get("seconds") if uptime is not None else None,
                "uptime_lastboot": uptime.get("lastboot") if uptime is not None else None,
                "distance_hops": distance.get("value") if distance is not None else None,
            }
        )

    finished = root.find("./runstats/finished")
    stats_hosts = root.find("./runstats/hosts")

    return {
        "scanner": root.get("scanner"),
        "args": root.get("args"),
        "start": root.get("start"),
        "startstr": root.get("startstr"),
        "version": root.get("version"),
        "xmloutputversion": root.get("xmloutputversion"),
        "scan_info": [dict(node.attrib) for node in root.findall("scaninfo")],
        "hosts": hosts,
        "run_stats": {
            "finished": finished.attrib if finished is not None else {},
            "hosts": stats_hosts.attrib if stats_hosts is not None else {},
        },
    }


def _parse_if_present(xml_path: Path) -> dict[str, Any]:
    """Parse the XML when it exists; otherwise record a parse error."""
    if not xml_path.exists() or not xml_path.stat().st_size:
        return {"hosts": [], "parse_error": "Nmap XML output was not created."}

    try:
        return parse_nmap_xml(xml_path)
    except (ET.ParseError, OSError) as exc:
        return {"hosts": [], "parse_error": str(exc)}


def _run_scan(command: list[str], xml_path: Path, timeout: int) -> dict[str, Any]:
    """Run one Nmap process and attach its parsed XML (if any)."""
    started = datetime.now(timezone.utc).isoformat()

    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, check=False
        )

        return {
            "command": command,
            "started_at": started,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "returncode": completed.returncode,
            "stdout": completed.stdout[-OUTPUT_TAIL_LIMIT:],
            "stderr": completed.stderr[-OUTPUT_TAIL_LIMIT:],
            "xml_path": str(xml_path),
            "parsed": _parse_if_present(xml_path),
        }

    except OSError as exc:
        return {
            "command": command,
            "started_at": started,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "execution_error": str(exc),
            "xml_path": str(xml_path),
            "parsed": _parse_if_present(xml_path),
        }

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""

        return {
            "command": command,
            "started_at": started,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "timed_out": True,
            "timeout_seconds": timeout,
            "stdout": stdout[-OUTPUT_TAIL_LIMIT:],
            "stderr": stderr[-OUTPUT_TAIL_LIMIT:],
            "xml_path": str(xml_path),
            "parsed": _parse_if_present(xml_path),
        }


def _scan_command(
    binary: str,
    config: dict[str, Any],
    target_ip: str,
    ip_version: int,
) -> list[str]:
    """Build the full-TCP inventory command for one approved IP."""
    command = [
        binary,
        "-n",
        "-Pn",
        "--reason",
        "-sV",
        "-O",
        f"-T{config.get('timing_template', 2)}",
        "--max-retries",
        str(config.get("max_retries", 2)),
        "--host-timeout",
        str(config.get("host_timeout", "20m")),
    ]

    if ip_version == 6:
        command.append("-6")

    command += ["-p-", "-oA"]

    return command


def _udp_command(
    binary: str,
    config: dict[str, Any],
    udp_config: dict[str, Any],
    target_ip: str,
    ip_version: int,
) -> list[str]:
    """Build the opt-in UDP scan command for one approved IP."""
    udp_ports = (
        ["-p-"]
        if udp_config.get("all_ports", False)
        else ["--top-ports", str(udp_config.get("top_ports", 1000))]
    )

    command = [binary, "-n", "-Pn", "--reason", "-sU", "-sV"]

    if ip_version == 6:
        command.append("-6")

    command += udp_ports + [
        f"-T{config.get('timing_template', 2)}",
        "--max-retries",
        str(config.get("max_retries", 2)),
        "--host-timeout",
        str(config.get("host_timeout", "30m")),
        "-oA",
    ]

    return command


def collect(
    host: str,
    output_dir: str | Path,
    config: dict[str, Any],
    scan_targets: list[str] | None = None,
) -> dict[str, Any]:
    """Run configured scans against explicitly approved, pinned IP addresses.

    TCP full-port inventory is the default. UDP is opt-in because it can be
    substantially slower and less conclusive. No NSE scripts are invoked.
    """
    binary = shutil.which(config.get("binary", "nmap"))
    if not binary:
        raise FileNotFoundError(
            "Nmap was not found. Install it with: sudo apt install nmap"
        )

    if scan_targets is None:
        raise ValueError(
            "scan_targets must contain IPs approved by the engagement scope policy."
        )

    targets = list(dict.fromkeys(scan_targets))
    if not targets:
        raise ValueError("No approved IP addresses were supplied to Nmap.")

    for target_ip in targets:
        ipaddress.ip_address(target_ip)

    out = Path(output_dir) / "nmap"
    out.mkdir(parents=True, exist_ok=True)
    scan_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

    timeout = int(config.get("process_timeout_seconds", 1500))
    udp_config = config.get("udp", {})

    tcp_scans: list[dict[str, Any]] = []
    udp_scans: list[dict[str, Any]] = []
    artifact_sets: list[dict[str, Any]] = []

    for index, target_ip in enumerate(targets, 1):
        ip_obj = ipaddress.ip_address(target_ip)
        prefix = out / f"{_safe_name(host)}-{_safe_name(target_ip)}-{scan_stamp}-{index}"

        tcp_prefix = Path(f"{prefix}-tcp")
        tcp_xml = Path(f"{tcp_prefix}.xml")
        tcp_cmd = _scan_command(binary, config, target_ip, ip_obj.version)
        tcp_cmd += [str(tcp_prefix), target_ip]
        tcp_scans.append(_run_scan(tcp_cmd, tcp_xml, timeout))

        artifacts: dict[str, Any] = {
            "target_ip": target_ip,
            "tcp_xml": str(tcp_xml),
            "tcp_normal": f"{tcp_prefix}.nmap",
            "tcp_grepable": f"{tcp_prefix}.gnmap",
        }

        if udp_config.get("enabled", False):
            udp_prefix = Path(f"{prefix}-udp")
            udp_xml = Path(f"{udp_prefix}.xml")
            udp_cmd = _udp_command(binary, config, udp_config, target_ip, ip_obj.version)
            udp_cmd += [str(udp_prefix), target_ip]
            udp_scans.append(
                _run_scan(
                    udp_cmd,
                    udp_xml,
                    int(udp_config.get("process_timeout_seconds", 2400)),
                )
            )
            artifacts.update(
                {
                    "udp_xml": str(udp_xml),
                    "udp_normal": f"{udp_prefix}.nmap",
                    "udp_grepable": f"{udp_prefix}.gnmap",
                }
            )

        artifact_sets.append(artifacts)

    def aggregate(scans: list[dict[str, Any]]) -> dict[str, Any]:
        hosts: list[dict[str, Any]] = []
        for scan in scans:
            hosts.extend((scan.get("parsed") or {}).get("hosts", []))
        return {"parsed": {"hosts": hosts}, "scans": scans}

    return {
        "target": host,
        "scan_targets": targets,
        "started_at": scan_stamp,
        "scanner": "nmap",
        "profile": (
            "full_tcp_ports_with_service_detection_and_os_fingerprinting"
            "_plus_configured_udp"
        ),
        "tcp": aggregate(tcp_scans),
        "udp": aggregate(udp_scans) if udp_scans else None,
        "artifacts": artifact_sets,
        "limitations": [
            (
                "Only IP addresses explicitly permitted by the engagement scope "
                "policy are scanned."
            ),
            (
                "OS fingerprinting may be unavailable without raw-socket privileges "
                "or sufficient responses."
            ),
            (
                "Service/version results are probe-based identifications and require "
                "validation for high-impact conclusions."
            ),
            (
                "UDP inventory is partial unless a separately authorized full UDP "
                "port range is configured."
            ),
            "No NSE vulnerability scripts or exploitation checks are run.",
        ],
    }
