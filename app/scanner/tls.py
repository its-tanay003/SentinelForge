"""TLS/HTTPS basics scanner."""
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
import httpx
from app.config import settings
from app.scanner.headers import ScanFinding


async def scan_tls(url: str) -> list[ScanFinding]:
    """Scan TLS/HTTPS configuration basics."""
    findings: list[ScanFinding] = []
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ""
    port = parsed.port

    # Check if HTTP redirects to HTTPS
    if scheme == "http":
        findings.append(
            ScanFinding(
                finding_id="TLS-001",
                title="Target Not Using HTTPS",
                category="tls",
                severity="High",
                evidence=f"Target URL uses HTTP: {url}",
                remediation=(
                    "Serve the application over HTTPS. "
                    "Obtain a TLS certificate (e.g., Let's Encrypt) and configure your web server."
                ),
            )
        )

        # Check if there's an HTTPS redirect
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=settings.HTTP_TIMEOUT, follow_redirects=False
            ) as client:
                resp = await client.get(url)
                if resp.status_code in (301, 302, 307, 308):
                    location = resp.headers.get("location", "")
                    if location.startswith("https://"):
                        findings.append(
                            ScanFinding(
                                finding_id="TLS-002",
                                title="HTTP Redirects to HTTPS (Good Practice Detected)",
                                category="tls",
                                severity="Info",
                                evidence=f"HTTP {resp.status_code} redirects to: {location}",
                                remediation="Good practice! Ensure HSTS is also configured.",
                            )
                        )
                    else:
                        findings.append(
                            ScanFinding(
                                finding_id="TLS-003",
                                title="HTTP Does Not Redirect to HTTPS",
                                category="tls",
                                severity="High",
                                evidence=f"HTTP response code: {resp.status_code}, Location: {location or 'none'}",
                                remediation="Configure the web server to redirect all HTTP traffic to HTTPS.",
                            )
                        )
        except Exception as e:
            pass

        return findings

    # HTTPS target - check certificate
    if scheme == "https":
        effective_port = port or 443

        # Skip cert check for localhost (self-signed expected in dev)
        is_localhost = hostname in ("localhost", "127.0.0.1", "::1")

        if not is_localhost:
            try:
                ctx = ssl.create_default_context()
                conn = ctx.wrap_socket(
                    socket.socket(socket.AF_INET), server_hostname=hostname
                )
                conn.settimeout(settings.HTTP_TIMEOUT)
                conn.connect((hostname, effective_port))
                cert = conn.getpeercert()
                conn.close()

                # Check expiry
                not_after_str = cert.get("notAfter", "")
                if not_after_str:
                    try:
                        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        not_after = not_after.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_left = (not_after - now).days

                        if days_left < 0:
                            findings.append(
                                ScanFinding(
                                    finding_id="TLS-004",
                                    title="TLS Certificate Has Expired",
                                    category="tls",
                                    severity="Critical",
                                    evidence=f"Certificate expired on: {not_after_str}",
                                    remediation="Renew the TLS certificate immediately.",
                                )
                            )
                        elif days_left < 14:
                            findings.append(
                                ScanFinding(
                                    finding_id="TLS-005",
                                    title=f"TLS Certificate Expires Soon ({days_left} days)",
                                    category="tls",
                                    severity="High",
                                    evidence=f"Certificate expires: {not_after_str} ({days_left} days remaining)",
                                    remediation="Renew the TLS certificate within the next 14 days.",
                                )
                            )
                        elif days_left < 30:
                            findings.append(
                                ScanFinding(
                                    finding_id="TLS-006",
                                    title=f"TLS Certificate Expiring in {days_left} Days",
                                    category="tls",
                                    severity="Medium",
                                    evidence=f"Certificate expires: {not_after_str}",
                                    remediation="Plan to renew the TLS certificate within 30 days.",
                                )
                            )
                    except ValueError:
                        pass

            except ssl.SSLCertVerificationError as e:
                findings.append(
                    ScanFinding(
                        finding_id="TLS-007",
                        title="TLS Certificate Validation Error",
                        category="tls",
                        severity="High",
                        evidence=f"SSL error: {e}",
                        remediation=(
                            "Ensure the TLS certificate is valid, signed by a trusted CA, "
                            "and matches the hostname."
                        ),
                    )
                )
            except ssl.SSLError as e:
                findings.append(
                    ScanFinding(
                        finding_id="TLS-008",
                        title="TLS Configuration Error",
                        category="tls",
                        severity="High",
                        evidence=f"TLS error: {e}",
                        remediation="Review TLS configuration. Disable deprecated protocols (TLS 1.0, 1.1, SSLv3).",
                    )
                )
            except Exception:
                pass  # Could not check cert (firewall, etc.)

        else:
            findings.append(
                ScanFinding(
                    finding_id="TLS-009",
                    title="Self-Signed or Development Certificate (Localhost)",
                    category="tls",
                    severity="Info",
                    evidence=f"Target is localhost ({hostname}). Certificate check skipped.",
                    remediation=(
                        "Use a valid certificate from a trusted CA in production. "
                        "Self-signed certs are acceptable for local development only."
                    ),
                )
            )

    return findings
