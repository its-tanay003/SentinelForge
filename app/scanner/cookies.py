"""Cookie security flags scanner."""
import httpx
from app.config import settings
from app.scanner.headers import ScanFinding


async def scan_cookies(url: str) -> list[ScanFinding]:
    """Scan cookies for missing security flags."""
    findings: list[ScanFinding] = []

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=settings.HTTP_TIMEOUT, follow_redirects=True
        ) as client:
            resp = await client.get(url)
    except Exception as e:
        findings.append(
            ScanFinding(
                finding_id="CKI-000",
                title="Cookie Scan Connection Failed",
                category="cookies",
                severity="Info",
                evidence=str(e),
                remediation="Ensure target is reachable.",
            )
        )
        return findings

    set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    # httpx uses a different API - collect all Set-Cookie headers
    raw_headers = [(k, v) for k, v in resp.headers.raw if k.lower() == b"set-cookie"]
    set_cookie_values = [v.decode() for _, v in raw_headers]

    if not set_cookie_values:
        # No cookies set, not necessarily a finding
        return findings

    is_https = url.lower().startswith("https://")

    for i, cookie_str in enumerate(set_cookie_values):
        cookie_name = cookie_str.split("=")[0].strip()
        parts_lower = cookie_str.lower()

        # Check Secure flag
        if "secure" not in parts_lower:
            severity = "Medium" if is_https else "Low"
            findings.append(
                ScanFinding(
                    finding_id=f"CKI-{100 + i * 3 + 1:03d}",
                    title=f"Cookie '{cookie_name}': Missing Secure Flag",
                    category="cookies",
                    severity=severity,
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    remediation=(
                        f"Add the 'Secure' flag to cookie '{cookie_name}'. "
                        "This ensures the cookie is only sent over HTTPS connections."
                    ),
                )
            )

        # Check HttpOnly flag
        if "httponly" not in parts_lower:
            findings.append(
                ScanFinding(
                    finding_id=f"CKI-{100 + i * 3 + 2:03d}",
                    title=f"Cookie '{cookie_name}': Missing HttpOnly Flag",
                    category="cookies",
                    severity="Medium",
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    remediation=(
                        f"Add the 'HttpOnly' flag to cookie '{cookie_name}'. "
                        "This prevents JavaScript from accessing the cookie, mitigating XSS cookie theft."
                    ),
                )
            )

        # Check SameSite flag
        if "samesite" not in parts_lower:
            findings.append(
                ScanFinding(
                    finding_id=f"CKI-{100 + i * 3 + 3:03d}",
                    title=f"Cookie '{cookie_name}': Missing SameSite Flag",
                    category="cookies",
                    severity="Medium",
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    remediation=(
                        f"Add 'SameSite=Strict' or 'SameSite=Lax' to cookie '{cookie_name}'. "
                        "This protects against CSRF attacks."
                    ),
                )
            )
        elif "samesite=none" in parts_lower and "secure" not in parts_lower:
            findings.append(
                ScanFinding(
                    finding_id=f"CKI-{100 + i * 3 + 4:03d}",
                    title=f"Cookie '{cookie_name}': SameSite=None Without Secure Flag",
                    category="cookies",
                    severity="High",
                    evidence=f"Set-Cookie: {cookie_str[:200]}",
                    remediation=(
                        "SameSite=None requires the Secure flag. "
                        "Add Secure attribute or change SameSite to Lax/Strict."
                    ),
                )
            )

        # Check for session cookie without expiry (not a security finding, just informational)
        if "session" in cookie_name.lower() or "sess" in cookie_name.lower():
            if "expires" not in parts_lower and "max-age" not in parts_lower:
                # Session cookie - this is actually OK for session cookies
                pass

    return findings
