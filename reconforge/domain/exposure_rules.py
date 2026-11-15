"""Turn technical observations into transparent, reviewable recommendations.

Rules deliberately distinguish exposure from confirmed vulnerability. Every
parsed port is retained in inventory; recommendations never suppress results.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ExposureRule:
    """Provisional recommendation for an open service exposure."""

    severity: str
    title: str
    impact: str
    recommendation: str
    cwe: str | None
    verification: str


RULES: dict[int, ExposureRule] = {
    21: ExposureRule(
        "Medium",
        "FTP service exposed",
        "FTP may transmit credentials and data without encryption.",
        "Disable FTP where unnecessary; otherwise require explicit FTPS/SFTP "
        "and restrict source networks.",
        "CWE-319",
        "Validate whether cleartext authentication is enabled and whether the "
        "service is required.",
    ),
    23: ExposureRule(
        "High",
        "Telnet service exposed",
        "Telnet provides no transport encryption and can expose credentials "
        "and sessions.",
        "Disable Telnet and use SSH or another encrypted management protocol; "
        "restrict management access.",
        "CWE-319",
        "Confirm the service identity and verify Telnet is disabled after "
        "remediation.",
    ),
    445: ExposureRule(
        "High",
        "SMB service reachable",
        "Reachable SMB increases exposure to file-sharing and remote-service "
        "attack paths.",
        "Restrict SMB to trusted internal networks, disable internet ingress, "
        "enforce signing where appropriate, and patch supported systems.",
        "CWE-668",
        "Validate SMB version, signing, share permissions and source-network "
        "restrictions.",
    ),
    139: ExposureRule(
        "Medium",
        "NetBIOS session service reachable",
        "NetBIOS session exposure can disclose or expose legacy file-sharing "
        "functionality.",
        "Disable NetBIOS where not required and restrict ports 137-139 to "
        "trusted networks.",
        "CWE-668",
        "Confirm whether legacy NetBIOS functionality is required.",
    ),
    3389: ExposureRule(
        "High",
        "Remote Desktop service reachable",
        "Exposed RDP increases the remote access attack surface.",
        "Place RDP behind VPN or zero-trust access, restrict source IPs, "
        "enforce MFA and account lockout, and keep the host patched.",
        "CWE-668",
        "Confirm authentication controls, MFA and network-level authentication.",
    ),
    5900: ExposureRule(
        "High",
        "VNC remote desktop reachable",
        "VNC may expose interactive desktop access and implementations vary "
        "in authentication and encryption.",
        "Restrict VNC to trusted management networks or remove it; use an "
        "encrypted access gateway.",
        "CWE-668",
        "Validate authentication strength and transport encryption without "
        "attempting login.",
    ),
    2375: ExposureRule(
        "High",
        "Docker API port reachable",
        "A reachable unauthenticated Docker API can enable control of the "
        "container host; port detection alone does not establish "
        "authentication state.",
        "Do not expose the unauthenticated Docker TCP API. Use a protected "
        "Unix socket or mutually authenticated TLS and firewall restrictions.",
        "CWE-306",
        "Determine whether TLS/client authentication is enforced; do not "
        "send state-changing API requests.",
    ),
    6379: ExposureRule(
        "High",
        "Redis service reachable",
        "A reachable Redis endpoint may expose application data or "
        "administrative operations if access controls are weak.",
        "Bind Redis to trusted interfaces, require ACL authentication and TLS "
        "where supported, and restrict network access.",
        "CWE-668",
        "Validate ACL/authentication and network binding using approved "
        "read-only checks.",
    ),
    27017: ExposureRule(
        "High",
        "MongoDB service reachable",
        "A reachable database listener may expose sensitive records if "
        "authentication or network controls are weak.",
        "Bind MongoDB to private interfaces, enforce authentication and TLS, "
        "and restrict ingress to application hosts.",
        "CWE-668",
        "Validate authentication and network restrictions; do not enumerate "
        "or extract records.",
    ),
    9200: ExposureRule(
        "High",
        "Elasticsearch HTTP endpoint reachable",
        "A reachable search API may expose indices or administrative "
        "functions if access controls are absent.",
        "Require authentication and TLS, restrict access to trusted "
        "application networks, and disable unnecessary public exposure.",
        "CWE-668",
        "Validate authentication using non-invasive metadata checks only.",
    ),
    3306: ExposureRule(
        "Medium",
        "MySQL database listener reachable",
        "Direct database reachability expands the attack surface and may "
        "expose sensitive data if access controls are weak.",
        "Restrict MySQL ingress to application hosts, enforce TLS and "
        "least-privilege accounts, and avoid public exposure.",
        "CWE-668",
        "Confirm network ACLs and authentication configuration.",
    ),
    5432: ExposureRule(
        "Medium",
        "PostgreSQL database listener reachable",
        "Direct database reachability expands the attack surface and may "
        "expose sensitive data if access controls are weak.",
        "Restrict PostgreSQL ingress to application hosts, enforce TLS and "
        "least-privilege roles, and avoid public exposure.",
        "CWE-668",
        "Confirm pg_hba.conf policy, TLS and network restrictions.",
    ),
    161: ExposureRule(
        "Medium",
        "SNMP service reachable",
        "SNMP may disclose device and network-management information; risk "
        "depends on version and community/authentication configuration.",
        "Restrict SNMP to management networks, disable v1/v2c where possible, "
        "and use SNMPv3 with authentication and privacy.",
        "CWE-200",
        "Identify SNMP version and verify community/authentication settings "
        "using approved read-only methods.",
    ),
    11211: ExposureRule(
        "High",
        "Memcached service reachable",
        "A reachable cache service may expose application data or be abused "
        "if it is not isolated and access-controlled.",
        "Bind Memcached to private interfaces, firewall the listener to "
        "application hosts, and disable UDP where it is not required.",
        "CWE-668",
        "Confirm listener binding and network ACLs; do not query or extract "
        "cached application data.",
    ),
}

SEVERITY_RANK = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}

DECISION_TREE = [
    (
        "Is the asset explicitly approved and inside the engagement scope? "
        "If no, do not scan it."
    ),
    (
        "Did Nmap identify an open port? If no, retain the observed state and "
        "evidence; do not infer exposure."
    ),
    (
        "Was a service and version identified? If yes, retain product/version/CPE "
        "and validate against vendor advisories; if no, record service as unknown."
    ),
    (
        "Does the port/service match a risk rule? If yes, create a provisional "
        "recommendation; if no, retain it as an inventory observation."
    ),
    (
        "Can the issue be confirmed safely with authorized read-only evidence? "
        "If no, label it requires validation rather than claiming a vulnerability."
    ),
    (
        "Prioritize remediation by exposure, business criticality, exploitability "
        "and impact; include every observation in the report."
    ),
]


def _iter_hosts(scan_result: dict[str, Any]):
    """Yield (phase, host) for every host parsed from tcp/udp scans."""
    for phase in ("tcp", "udp"):
        scan = scan_result.get(phase) or {}
        parsed = scan.get("parsed") or {}

        for host in parsed.get("hosts", []):
            yield phase, host


def _primary_ip(host: dict[str, Any]) -> str | None:
    addresses = host.get("addresses", [])
    return next(
        (
            a.get("address")
            for a in addresses
            if a.get("type") in {"ipv4", "ipv6"}
        ),
        None,
    )


def _exposure_finding(
    finding_id: str,
    asset: str,
    ip: str | None,
    rule: ExposureRule,
    port_record: dict[str, Any],
    service: dict[str, Any],
) -> dict[str, Any]:
    protocol = port_record.get("protocol")
    port = port_record.get("port")

    return {
        "id": finding_id,
        "title": rule.title,
        "severity": rule.severity,
        "asset": asset,
        "ip": ip,
        "port": port,
        "protocol": protocol,
        "service": service,
        "impact": rule.impact,
        "recommendation": rule.recommendation,
        "verification": rule.verification,
        "cwe": rule.cwe,
        "confidence": "Medium",
        "status": "Requires manual validation",
        "evidence": (
            f"Nmap reported {port_record.get('state')} on "
            f"{protocol}/{port} ({service.get('name') or 'service unknown'})."
        ),
        "cvss": (
            "Not assigned: exposure alone is insufficient for a defensible "
            "CVSS score."
        ),
    }


def _version_finding(
    finding_id: str,
    asset: str,
    ip: str | None,
    port_record: dict[str, Any],
    service: dict[str, Any],
) -> dict[str, Any]:
    protocol = port_record.get("protocol")
    port = port_record.get("port")

    return {
        "id": finding_id,
        "title": "Detected software version requires lifecycle and advisory review",
        "severity": "Informational",
        "asset": asset,
        "ip": ip,
        "port": port,
        "protocol": protocol,
        "service": service,
        "impact": (
            "An identified product/version provides a basis for maintenance "
            "and vulnerability review; the banner alone does not prove that "
            "the installed build is vulnerable or unsupported."
        ),
        "recommendation": (
            "Confirm the exact installed build with the system owner, check "
            "the vendor support lifecycle and security advisories for the "
            "detected product/version/CPE, and apply supported security "
            "updates where required."
        ),
        "verification": (
            "Correlate the detected CPE and version with vendor advisories, "
            "distribution backports and the actual installed package/build "
            "before assigning CVEs or severity."
        ),
        "cwe": None,
        "confidence": "Low to Medium",
        "status": "Version identification; advisory validation pending",
        "evidence": (
            f"Nmap identified {service.get('product') or service.get('name')} "
            f"{service.get('version') or '(version not reported)'} on "
            f"{protocol}/{port}."
        ),
        "cvss": "Not assigned: no CVE applicability has been validated.",
    }


def build_assessment(nmap_results: dict[str, Any]) -> dict[str, Any]:
    """Build the port inventory and provisional findings from Nmap results."""
    inventory: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for asset, scan in nmap_results.items():
        for phase, host in _iter_hosts(scan):
            ip = _primary_ip(host)

            for port_record in host.get("ports", []):
                service = port_record.get("service") or {}

                inventory.append(
                    {
                        "asset": asset,
                        "ip": ip,
                        "scan_type": phase,
                        "protocol": port_record.get("protocol"),
                        "port": port_record.get("port"),
                        "state": port_record.get("state"),
                        "reason": port_record.get("reason"),
                        "service_name": service.get("name"),
                        "product": service.get("product"),
                        "version": service.get("version"),
                        "extrainfo": service.get("extrainfo"),
                        "tunnel": service.get("tunnel"),
                        "cpe": service.get("cpe", []),
                    }
                )

                if port_record.get("state") != "open":
                    continue

                rule = RULES.get(port_record.get("port"))
                if rule:
                    findings.append(
                        _exposure_finding(
                            f"NET-{asset}-{port_record.get('protocol')}-{port_record.get('port')}",
                            asset,
                            ip,
                            rule,
                            port_record,
                            service,
                        )
                    )

                if service.get("product") or service.get("version"):
                    findings.append(
                        _version_finding(
                            f"VER-{asset}-{port_record.get('protocol')}-{port_record.get('port')}",
                            asset,
                            ip,
                            port_record,
                            service,
                        )
                    )

    findings.sort(
        key=lambda item: (
            SEVERITY_RANK.get(item["severity"], len(SEVERITY_RANK)),
            item["asset"],
            item["port"] or 0,
        )
    )

    counts = {
        level: sum(1 for f in findings if f["severity"] == level)
        for level in SEVERITY_RANK
    }

    return {
        "port_inventory": inventory,
        "findings": findings,
        "summary": {
            "ports_recorded": len(inventory),
            "open_ports": sum(1 for p in inventory if p["state"] == "open"),
            "findings": len(findings),
            "severity_counts": counts,
        },
        "decision_tree": DECISION_TREE,
    }
