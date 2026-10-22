"""CORS misconfiguration scanner."""
import httpx
from app.config import settings
from app.scanner.headers import ScanFinding


EVIL_ORIGIN = "https://evil.attacker.com"
NULL_ORIGIN = "null"


async def scan_cors(url: str) -> list[ScanFinding]:
    """Scan a URL for CORS misconfigurations."""
    findings: list[ScanFinding] = []

    headers_to_test = [
        ("Origin", EVIL_ORIGIN),
        ("Origin", NULL_ORIGIN),
    ]

    for origin_header, origin_value in headers_to_test:
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=settings.HTTP_TIMEOUT, follow_redirects=True
            ) as client:
                resp = await client.get(url, headers={origin_header: origin_value})
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        except Exception as e:
            findings.append(
                ScanFinding(
                    finding_id="CRS-000",
                    title="CORS Scan Connection Failed",
                    category="cors",
                    severity="Info",
                    evidence=str(e),
                    remediation="Ensure target is reachable.",
                )
            )
            return findings

        # Wildcard ACAO
        if acao == "*":
            sev = "High"
            if acac.lower() == "true":
                sev = "Critical"
                findings.append(
                    ScanFinding(
                        finding_id="CRS-001",
                        title="CORS: Wildcard Origin with Credentials Allowed",
                        category="cors",
                        severity="Critical",
                        evidence=(
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}\n"
                            f"Tested with Origin: {origin_value}"
                        ),
                        remediation=(
                            "Never combine Access-Control-Allow-Origin: * with "
                            "Access-Control-Allow-Credentials: true. "
                            "Specify explicit trusted origins."
                        ),
                    )
                )
            else:
                findings.append(
                    ScanFinding(
                        finding_id="CRS-002",
                        title="CORS: Wildcard Origin Allowed",
                        category="cors",
                        severity="High",
                        evidence=(
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Tested with Origin: {origin_value}"
                        ),
                        remediation=(
                            "Restrict Access-Control-Allow-Origin to specific trusted origins. "
                            "Do not use * for APIs that serve sensitive data."
                        ),
                    )
                )

        # Reflected origin (arbitrary origin mirrored back)
        elif acao and acao == origin_value and origin_value == EVIL_ORIGIN:
            sev = "High"
            if acac.lower() == "true":
                sev = "Critical"
            findings.append(
                ScanFinding(
                    finding_id="CRS-003",
                    title="CORS: Arbitrary Origin Reflected (Potential CORS Bypass)",
                    category="cors",
                    severity=sev,
                    evidence=(
                        f"Sent Origin: {origin_value}\n"
                        f"Received Access-Control-Allow-Origin: {acao}\n"
                        f"Access-Control-Allow-Credentials: {acac}"
                    ),
                    remediation=(
                        "Do not reflect the Origin header directly. "
                        "Maintain an allowlist of trusted origins and validate against it."
                    ),
                )
            )

        # null origin accepted
        elif acao and acao == "null" and origin_value == NULL_ORIGIN:
            findings.append(
                ScanFinding(
                    finding_id="CRS-004",
                    title="CORS: Null Origin Accepted",
                    category="cors",
                    severity="Medium",
                    evidence=(
                        f"Sent Origin: null\n"
                        f"Received Access-Control-Allow-Origin: {acao}"
                    ),
                    remediation=(
                        "Do not allow 'null' as a CORS origin. "
                        "Null origin can be spoofed via sandboxed iframes."
                    ),
                )
            )

    # Check OPTIONS preflight
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=settings.HTTP_TIMEOUT, follow_redirects=True
        ) as client:
            resp = await client.options(
                url,
                headers={
                    "Origin": EVIL_ORIGIN,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "X-Custom-Header",
                },
            )
            acam = resp.headers.get("Access-Control-Allow-Methods", "")
            acah = resp.headers.get("Access-Control-Allow-Headers", "")
            acao_pre = resp.headers.get("Access-Control-Allow-Origin", "")

            if acao_pre == EVIL_ORIGIN or acao_pre == "*":
                if "*" in acam or "DELETE" in acam or "PUT" in acam:
                    findings.append(
                        ScanFinding(
                            finding_id="CRS-005",
                            title="CORS: Permissive Preflight Allows Dangerous Methods",
                            category="cors",
                            severity="High",
                            evidence=(
                                f"Preflight response allows Origin: {acao_pre}\n"
                                f"Methods: {acam}\nHeaders: {acah}"
                            ),
                            remediation=(
                                "Restrict Access-Control-Allow-Methods to only necessary HTTP verbs. "
                                "Avoid wildcards in preflight responses."
                            ),
                        )
                    )
    except Exception:
        pass  # OPTIONS not supported, not critical

    return findings
