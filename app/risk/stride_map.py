"""STRIDE threat category mapping for security findings."""

# Mapping from finding category/type to STRIDE category
# STRIDE: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege

STRIDE_DESCRIPTIONS = {
    "Spoofing": "Impersonating a user or system component",
    "Tampering": "Modifying data or code",
    "Repudiation": "Denying actions without proof",
    "Information Disclosure": "Exposing information to unauthorized parties",
    "Denial of Service": "Degrading or blocking service availability",
    "Elevation of Privilege": "Gaining unauthorized elevated permissions",
}

# Map finding IDs to STRIDE categories
FINDING_STRIDE_MAP = {
    # Headers
    "HDR-001": "Information Disclosure",   # CSP missing - enables XSS data theft
    "HDR-002": "Tampering",                # HSTS missing - enables MITM/downgrade
    "HDR-003": "Tampering",                # Clickjacking - UI redressing
    "HDR-004": "Tampering",                # MIME sniffing - content injection
    "HDR-005": "Information Disclosure",   # Referrer leaks URLs/tokens
    "HDR-006": "Elevation of Privilege",   # Browser features abuse
    "HDR-007": "Information Disclosure",   # Weak CSP - XSS possible
    "HDR-008": "Tampering",                # Weak HSTS
    "HDR-009": "Tampering",                # Short HSTS
    "HDR-010": "Information Disclosure",   # Server version disclosure
    "HDR-011": "Information Disclosure",   # Tech stack disclosure
    # CORS
    "CRS-001": "Elevation of Privilege",   # Wildcard + credentials
    "CRS-002": "Information Disclosure",   # Wildcard CORS
    "CRS-003": "Elevation of Privilege",   # Reflected origin = full auth bypass
    "CRS-004": "Spoofing",                 # Null origin accepted
    "CRS-005": "Tampering",                # Dangerous methods allowed
    # Cookies
    "CKI-101": "Tampering",                # Missing Secure - cookie theft over HTTP
    "CKI-102": "Information Disclosure",   # Missing HttpOnly - JS access
    "CKI-103": "Spoofing",                 # Missing SameSite - CSRF
    "CKI-104": "Spoofing",                 # SameSite=None without Secure
    # TLS
    "TLS-001": "Tampering",                # No HTTPS - MITM
    "TLS-003": "Tampering",                # No HTTPS redirect
    "TLS-004": "Spoofing",                 # Expired cert
    "TLS-005": "Spoofing",                 # Expiring soon
    "TLS-006": "Spoofing",                 # Expiring cert
    "TLS-007": "Spoofing",                 # Invalid cert
    "TLS-008": "Tampering",                # TLS config error
    "TLS-002": "Information Disclosure",   # Info about good redirect
    "TLS-009": "Information Disclosure",   # Dev cert info
    # BOLA
    "BOL-001": "Elevation of Privilege",   # Unauthenticated access
    "BOL-002": "Information Disclosure",   # ID enumeration
    "BOL-003": "Elevation of Privilege",   # No auth required
    "BOL-INFO-001": "Information Disclosure",  # Info
}

# Category-level fallback mapping
CATEGORY_STRIDE_MAP = {
    "headers": "Information Disclosure",
    "cors": "Information Disclosure",
    "cookies": "Spoofing",
    "tls": "Tampering",
    "bola": "Elevation of Privilege",
}


def get_stride_category(finding_id: str, category: str) -> str:
    """Get the STRIDE category for a finding."""
    # Try exact finding ID match
    if finding_id in FINDING_STRIDE_MAP:
        return FINDING_STRIDE_MAP[finding_id]
    
    # Try prefix match for dynamic finding IDs (e.g., CKI-104, CKI-107)
    for prefix_len in [7, 6, 5, 4, 3]:
        prefix = finding_id[:prefix_len]
        if prefix in FINDING_STRIDE_MAP:
            return FINDING_STRIDE_MAP[prefix]
    
    # Fallback to category
    return CATEGORY_STRIDE_MAP.get(category, "Information Disclosure")
