"""Risk register builder."""
import json
from datetime import datetime
from sqlalchemy.orm import Session
from app.models import RiskItem, Finding, Scan
from app.risk.stride_map import get_stride_category
from app.risk.nist_map import get_nist_function
from app.risk.scoring import compute_finding_risk_score, SEVERITY_LIKELIHOOD_MAP


TREATMENT_MAP = {
    "Critical": "Remediate",
    "High": "Remediate",
    "Medium": "Mitigate",
    "Low": "Accept",
    "Info": "Accept",
}


def build_risk_register(
    scan: Scan,
    findings: list[Finding],
    intel_risk_score: float = 0.0,
    db: Session = None,
) -> list[RiskItem]:
    """
    Build a risk register from scan findings.
    Each finding becomes a risk item with STRIDE, NIST, likelihood, impact, and score.
    """
    risk_items = []

    # Clear existing risk items for this scan
    if db:
        db.query(RiskItem).filter(RiskItem.scan_id == scan.id).delete()

    for i, finding in enumerate(findings):
        severity = finding.severity
        mapping = SEVERITY_LIKELIHOOD_MAP.get(severity, SEVERITY_LIKELIHOOD_MAP["Medium"])
        likelihood = mapping["base_likelihood"]
        impact = mapping["base_impact"]

        # Adjust impact based on intel risk
        if intel_risk_score > 50 and severity in ("High", "Critical"):
            impact = min(5, impact + 1)

        risk_score = compute_finding_risk_score(
            severity, likelihood, impact, intel_risk_score
        )

        stride = get_stride_category(finding.finding_id, finding.category)
        nist = get_nist_function(finding.finding_id, finding.category)

        # Determine asset name from finding category
        asset_map = {
            "headers": "Web Application - HTTP Headers",
            "cors": "Web Application - CORS Policy",
            "cookies": "Web Application - Session Management",
            "tls": "Web Application - Transport Layer",
            "bola": "Web Application - API Authorization",
        }
        asset = asset_map.get(finding.category, "Web Application")

        risk_item = RiskItem(
            scan_id=scan.id,
            risk_id=f"RISK-{scan.id:03d}-{i+1:03d}",
            asset=asset,
            threat=finding.title,
            stride_category=stride,
            nist_function=nist,
            likelihood=likelihood,
            impact=impact,
            risk_score=risk_score,
            owner="Security Team",
            treatment=TREATMENT_MAP.get(severity, "Mitigate"),
            status="Open",
            finding_id=finding.finding_id,
        )

        risk_items.append(risk_item)

        if db:
            db.add(risk_item)

    if db:
        db.commit()

    return risk_items
