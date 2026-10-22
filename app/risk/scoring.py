"""Risk scoring engine."""
from app.scanner.headers import ScanFinding


SEVERITY_LIKELIHOOD_MAP = {
    "Critical": {"base_likelihood": 5, "base_impact": 5},
    "High": {"base_likelihood": 4, "base_impact": 4},
    "Medium": {"base_likelihood": 3, "base_impact": 3},
    "Low": {"base_likelihood": 2, "base_impact": 2},
    "Info": {"base_likelihood": 1, "base_impact": 1},
}

SEVERITY_WEIGHTS = {
    "Critical": 10.0,
    "High": 7.0,
    "Medium": 4.0,
    "Low": 2.0,
    "Info": 0.5,
}


def compute_finding_risk_score(
    severity: str,
    likelihood: int = None,
    impact: int = None,
    intel_risk_score: float = 0.0,
) -> float:
    """
    Compute a 0-100 risk score for a finding.
    
    Formula: base_score * intel_multiplier
    base_score = (likelihood * impact) / 25 * severity_weight
    intel_multiplier = 1.0 + (intel_risk_score / 100) * 0.5  (up to 50% boost)
    """
    mapping = SEVERITY_LIKELIHOOD_MAP.get(severity, SEVERITY_LIKELIHOOD_MAP["Medium"])
    
    if likelihood is None:
        likelihood = mapping["base_likelihood"]
    if impact is None:
        impact = mapping["base_impact"]

    # Normalize likelihood and impact (1-5) to 0-1 scale
    likelihood = max(1, min(5, likelihood))
    impact = max(1, min(5, impact))

    base_score = (likelihood * impact) / 25.0 * 100.0  # 0-100

    # Apply severity weight as a scaling factor
    severity_factor = SEVERITY_WEIGHTS.get(severity, 4.0) / SEVERITY_WEIGHTS["Critical"]
    base_score *= severity_factor

    # Intel boost: if the domain is known malicious, increase risk
    intel_multiplier = 1.0 + (intel_risk_score / 100.0) * 0.5
    final_score = base_score * intel_multiplier

    return round(min(100.0, final_score), 2)


def compute_scan_risk_score(findings: list, intel_risk_score: float = 0.0) -> float:
    """
    Compute an aggregate risk score for a complete scan.
    
    Uses weighted average with highest-severity findings carrying more weight.
    """
    if not findings:
        return 0.0

    total_weight = 0.0
    weighted_sum = 0.0

    for finding in findings:
        severity = finding.severity if hasattr(finding, "severity") else finding.get("severity", "Info")
        weight = SEVERITY_WEIGHTS.get(severity, 0.5)
        score = compute_finding_risk_score(severity, intel_risk_score=intel_risk_score)
        weighted_sum += score * weight
        total_weight += weight

    if total_weight == 0:
        return 0.0

    raw_score = weighted_sum / total_weight
    return round(min(100.0, raw_score), 2)


def severity_to_risk_level(score: float) -> str:
    """Convert numeric risk score to risk level label."""
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    elif score >= 20:
        return "Low"
    else:
        return "Info"
