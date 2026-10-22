"""BOLA/IDOR vulnerability scanner."""
import httpx
from app.config import settings
from app.scanner.headers import ScanFinding


async def scan_bola(
    base_url: str,
    api_pattern: str = "/api/users/{id}",
    sample_ids: list[str] | None = None,
) -> list[ScanFinding]:
    """
    Check for Broken Object Level Authorization (BOLA/IDOR).
    
    Tests if object IDs are accessible without proper authorization by checking:
    1. Whether the endpoints return data (no auth required)
    2. Sequential ID traversal (ID enumeration)
    3. Whether different IDs return different data (object-level separation)
    """
    findings: list[ScanFinding] = []

    if sample_ids is None:
        sample_ids = ["1", "2", "3"]

    responses = {}
    for obj_id in sample_ids:
        endpoint = api_pattern.replace("{id}", str(obj_id))
        full_url = base_url.rstrip("/") + endpoint

        try:
            async with httpx.AsyncClient(
                verify=False, timeout=settings.HTTP_TIMEOUT, follow_redirects=True
            ) as client:
                resp = await client.get(full_url)
                responses[obj_id] = {
                    "status": resp.status_code,
                    "url": full_url,
                    "body_preview": resp.text[:300],
                    "content_length": len(resp.content),
                }
        except Exception as e:
            responses[obj_id] = {
                "status": -1,
                "url": full_url,
                "body_preview": str(e),
                "content_length": 0,
            }

    # Analyze results
    accessible_ids = [
        oid for oid, r in responses.items()
        if r["status"] == 200
    ]
    error_ids = [
        oid for oid, r in responses.items()
        if r["status"] in (401, 403)
    ]
    not_found_ids = [
        oid for oid, r in responses.items()
        if r["status"] == 404
    ]

    # Finding 1: Unauthenticated access to object resources
    if len(accessible_ids) >= 1:
        evidence_lines = []
        for oid in accessible_ids:
            r = responses[oid]
            evidence_lines.append(f"  GET {r['url']} → HTTP {r['status']} ({r['content_length']} bytes)")
            if r["body_preview"]:
                evidence_lines.append(f"  Response preview: {r['body_preview'][:150]}")
        
        findings.append(
            ScanFinding(
                finding_id="BOL-001",
                title=f"BOLA/IDOR: Object Resources Accessible Without Authentication",
                category="bola",
                severity="High",
                evidence=(
                    f"Pattern: {api_pattern}\n"
                    f"Accessible IDs (no auth required): {accessible_ids}\n"
                    + "\n".join(evidence_lines)
                ),
                remediation=(
                    "Implement proper authorization checks on every object-level endpoint. "
                    "Verify that the authenticated user owns or has permission to access the requested object. "
                    "Use indirect object references (UUIDs instead of sequential IDs) and "
                    "enforce server-side access control, not just client-side hiding."
                ),
            )
        )

    # Finding 2: ID enumeration possible
    if len(accessible_ids) >= 2:
        # Check if different IDs return different content (real data exposure)
        unique_bodies = set(
            responses[oid]["body_preview"] for oid in accessible_ids
        )
        if len(unique_bodies) > 1:
            findings.append(
                ScanFinding(
                    finding_id="BOL-002",
                    title="BOLA/IDOR: Sequential ID Enumeration Returns Different Objects",
                    category="bola",
                    severity="Critical",
                    evidence=(
                        f"Pattern: {api_pattern}\n"
                        f"IDs {accessible_ids} all return HTTP 200 with different content.\n"
                        f"This indicates object-level data is exposed without authorization.\n"
                        f"IDs tested: {', '.join(accessible_ids)}"
                    ),
                    remediation=(
                        "Critical: Enforce object-level authorization. "
                        "Each API endpoint must verify the requesting user's access to the specific object. "
                        "Use non-sequential identifiers (UUIDs/GUIDs) and "
                        "implement a centralized authorization service."
                    ),
                )
            )

    # Finding 3: No protection detected (even 404 responses without auth headers)
    if not error_ids and accessible_ids:
        findings.append(
            ScanFinding(
                finding_id="BOL-003",
                title="BOLA/IDOR: No Authentication/Authorization Headers Required",
                category="bola",
                severity="High",
                evidence=(
                    f"None of the tested endpoints returned 401 (Unauthorized) or 403 (Forbidden).\n"
                    f"Accessible: {accessible_ids}, Not Found: {not_found_ids}"
                ),
                remediation=(
                    "Implement authentication middleware. All API endpoints should require "
                    "a valid authentication token (JWT, session cookie, API key) and "
                    "return 401 when not authenticated."
                ),
            )
        )

    # If all return 401/403, it's a good sign
    if error_ids and not accessible_ids:
        findings.append(
            ScanFinding(
                finding_id="BOL-INFO-001",
                title="BOLA/IDOR: Endpoints Return 401/403 (Authentication Enforced)",
                category="bola",
                severity="Info",
                evidence=(
                    f"Pattern: {api_pattern}\n"
                    f"IDs returning 401/403: {error_ids}"
                ),
                remediation=(
                    "Good practice! Endpoints are protected. "
                    "Also verify that authenticated users cannot access other users' objects."
                ),
            )
        )

    return findings
