"""Conservative hostname-level HTTP HEAD and TLS metadata checks.

These checks require explicit hostname approval. They do not authorize
TCP port enumeration or Nmap against the resolved address.

The hostname is used for DNS resolution, HTTP Host, and TLS SNI.
Redirects are not followed and only HTTP HEAD requests are issued.
"""

from __future__ import annotations

import http.client
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from reconforge.infrastructure.http.client import USER_AGENT

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


def _peer_ip(connection: http.client.HTTPConnection | None) -> str | None:
    """Return the actual peer IP when the connection socket is available."""
    if connection is None:
        return None

    try:
        return connection.sock.getpeername()[0]
    except (AttributeError, OSError):
        return None


def http_head(host: str, scheme: str = "https", timeout: int = 10) -> dict[str, Any]:
    """Issue one HEAD request and record status/headers, without redirects."""
    port = 443 if scheme == "https" else 80
    url = f"{scheme}://{host}/"
    connection: http.client.HTTPConnection | None = None

    try:
        if scheme == "https":
            connection = http.client.HTTPSConnection(
                host,
                port=port,
                timeout=timeout,
                context=ssl.create_default_context(),
            )
        else:
            connection = http.client.HTTPConnection(host, port=port, timeout=timeout)

        connection.request(
            "HEAD",
            "/",
            headers={
                "Host": host,
                "User-Agent": USER_AGENT,
                "Connection": "close",
            },
        )

        response = connection.getresponse()
        headers = {
            key.lower(): value for key, value in response.getheaders()
        }

        return {
            "url": url,
            "hostname": host,
            "connected_ip": _peer_ip(connection),
            "method": "HEAD",
            "status": response.status,
            "server_header": headers.get("server"),
            "content_type": headers.get("content-type"),
            "security_headers": {
                name: headers.get(name) for name in SECURITY_HEADERS
            },
            "redirect_location": headers.get("location"),
            "note": (
                "A missing security header is an observation, "
                "not automatically a vulnerability. Redirects "
                "are recorded but not followed."
            ),
        }

    except Exception as exc:
        return {
            "url": url,
            "hostname": host,
            "connected_ip": _peer_ip(connection),
            "method": "HEAD",
            "error": str(exc),
        }

    finally:
        if connection is not None:
            connection.close()


def tls_certificate(host: str, port: int = 443, timeout: int = 10) -> dict[str, Any]:
    """Inspect the TLS certificate presented by the host."""
    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            connected_ip = sock.getpeername()[0]

            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()

                def names(key: str) -> list[str]:
                    return [
                        value
                        for group in cert.get(key, [])
                        for _, value in group
                    ]

                return {
                    "hostname": host,
                    "connected_ip": connected_ip,
                    "port": port,
                    "protocol": tls.version(),
                    "cipher": tls.cipher(),
                    "subject": names("subject"),
                    "issuer": names("issuer"),
                    "subject_alt_names": [
                        value
                        for kind, value in cert.get("subjectAltName", [])
                        if kind == "DNS"
                    ],
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                }

    except Exception as exc:
        return {"hostname": host, "port": port, "error": str(exc)}


def collect(host: str, timeout: int = 10) -> dict[str, Any]:
    """Collect hostname-level HTTP and TLS observations.

    Each check handles its own errors so one failure does not suppress
    the results of the other checks.
    """
    return {
        "hostname": host,
        "authorization_basis": "explicit_hostname_approval",
        "http": http_head(host, "http", timeout),
        "https": http_head(host, "https", timeout),
        "tls": tls_certificate(host, 443, timeout),
    }
