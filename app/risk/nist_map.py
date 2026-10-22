"""NIST Cybersecurity Framework 2.0 mapping for security findings."""

# NIST CSF 2.0 Functions:
# GV - Govern: Organizational context, risk management strategy, cybersecurity supply chain
# ID - Identify: Asset management, risk assessment, improvement
# PR - Protect: IAM, awareness, data security, platform security, resilience
# DE - Detect: Monitoring, adverse event analysis
# RS - Respond: Incident management, analysis, mitigation, reporting
# RC - Recover: Incident recovery, communication

NIST_FUNCTION_DESCRIPTIONS = {
    "Govern": "Establish and monitor cybersecurity risk management strategy",
    "Identify": "Understand assets, risks, and vulnerabilities",
    "Protect": "Implement safeguards to prevent or reduce cybersecurity events",
    "Detect": "Identify cybersecurity attacks and compromises",
    "Respond": "Take action to address detected incidents",
    "Recover": "Restore capabilities after a cybersecurity incident",
}

FINDING_NIST_MAP = {
    # Headers - Protect (implementing security controls)
    "HDR-001": "Protect",   # CSP - data security
    "HDR-002": "Protect",   # HSTS - platform security
    "HDR-003": "Protect",   # Clickjacking - platform security
    "HDR-004": "Protect",   # MIME type - data security
    "HDR-005": "Protect",   # Referrer policy
    "HDR-006": "Protect",   # Permissions policy
    "HDR-007": "Protect",   # Weak CSP
    "HDR-008": "Protect",   # Weak HSTS
    "HDR-009": "Protect",   # Short HSTS
    "HDR-010": "Identify",  # Server disclosure - asset identification
    "HDR-011": "Identify",  # Tech disclosure
    # CORS - Protect/Govern
    "CRS-001": "Protect",   # Critical CORS
    "CRS-002": "Protect",   # CORS misconfiguration
    "CRS-003": "Protect",   # Reflected origin
    "CRS-004": "Protect",   # Null origin
    "CRS-005": "Protect",   # Dangerous methods
    # Cookies - Protect
    "CKI-101": "Protect",
    "CKI-102": "Protect",
    "CKI-103": "Protect",
    "CKI-104": "Protect",
    # TLS - Protect/Identify
    "TLS-001": "Protect",   # No HTTPS - platform security
    "TLS-002": "Protect",   # Good redirect (info)
    "TLS-003": "Protect",   # No HTTPS redirect
    "TLS-004": "Identify",  # Expired cert - vulnerability management
    "TLS-005": "Identify",  # Expiring cert
    "TLS-006": "Identify",  # Expiring cert
    "TLS-007": "Protect",   # Invalid cert
    "TLS-008": "Protect",   # TLS config
    "TLS-009": "Identify",  # Dev cert info
    # BOLA - Protect/Govern
    "BOL-001": "Protect",   # Authorization - IAM
    "BOL-002": "Protect",   # IDOR - IAM
    "BOL-003": "Protect",   # No auth - IAM
    "BOL-INFO-001": "Protect",
}

CATEGORY_NIST_MAP = {
    "headers": "Protect",
    "cors": "Protect",
    "cookies": "Protect",
    "tls": "Protect",
    "bola": "Protect",
}


def get_nist_function(finding_id: str, category: str) -> str:
    """Get the NIST CSF 2.0 function for a finding."""
    if finding_id in FINDING_NIST_MAP:
        return FINDING_NIST_MAP[finding_id]
    
    # Try prefix match for dynamic IDs
    for prefix_len in [7, 6, 5, 4, 3]:
        prefix = finding_id[:prefix_len]
        if prefix in FINDING_NIST_MAP:
            return FINDING_NIST_MAP[prefix]
    
    return CATEGORY_NIST_MAP.get(category, "Protect")
