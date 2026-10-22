"""Tests for the risk scoring engine."""
import pytest
from app.risk.scoring import (
    compute_finding_risk_score,
    compute_scan_risk_score,
    severity_to_risk_level,
    SEVERITY_WEIGHTS,
)
from app.risk.stride_map import get_stride_category
from app.risk.nist_map import get_nist_function


class TestRiskScoring:

    def test_critical_score_higher_than_low(self):
        """Critical severity should always score higher than Low."""
        critical_score = compute_finding_risk_score("Critical")
        low_score = compute_finding_risk_score("Low")
        assert critical_score > low_score

    def test_score_range_0_to_100(self):
        """All computed scores should be between 0 and 100."""
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            score = compute_finding_risk_score(sev)
            assert 0 <= score <= 100, f"Score for {sev} out of range: {score}"

    def test_intel_boost_increases_score(self):
        """Intel risk should increase the final score."""
        base_score = compute_finding_risk_score("High", intel_risk_score=0.0)
        boosted_score = compute_finding_risk_score("High", intel_risk_score=80.0)
        assert boosted_score > base_score, "High intel risk should boost the score"

    def test_intel_boost_capped_at_100(self):
        """Score should never exceed 100 even with max intel."""
        score = compute_finding_risk_score("Critical", intel_risk_score=100.0)
        assert score <= 100.0

    def test_scan_score_empty_findings(self):
        """Empty findings should produce score of 0."""
        score = compute_scan_risk_score([])
        assert score == 0.0

    def test_scan_score_single_critical(self):
        """Single critical finding should produce a high scan score."""
        from unittest.mock import MagicMock
        f = MagicMock()
        f.severity = "Critical"
        score = compute_scan_risk_score([f])
        assert score > 50.0, "Single Critical finding should produce score > 50"

    def test_scan_score_only_info(self):
        """Only Info findings should produce a low score."""
        from unittest.mock import MagicMock
        findings = [MagicMock(severity="Info") for _ in range(5)]
        score = compute_scan_risk_score(findings)
        assert score < 20.0, f"Only Info findings should produce low score, got {score}"

    def test_severity_to_risk_level(self):
        """Risk level labels should map correctly to score ranges."""
        assert severity_to_risk_level(85) == "Critical"
        assert severity_to_risk_level(65) == "High"
        assert severity_to_risk_level(45) == "Medium"
        assert severity_to_risk_level(25) == "Low"
        assert severity_to_risk_level(5) == "Info"

    def test_severity_ordering(self):
        """Severity weights should be in correct order."""
        weights = [SEVERITY_WEIGHTS[s] for s in ["Critical", "High", "Medium", "Low", "Info"]]
        assert weights == sorted(weights, reverse=True), "Weights should be in decreasing order"


class TestSTRIDEMapping:

    def test_known_finding_ids_mapped(self):
        """Known finding IDs should return correct STRIDE categories."""
        assert get_stride_category("HDR-001", "headers") == "Information Disclosure"
        assert get_stride_category("HDR-002", "headers") == "Tampering"
        assert get_stride_category("CRS-001", "cors") == "Elevation of Privilege"
        assert get_stride_category("BOL-001", "bola") == "Elevation of Privilege"

    def test_fallback_to_category(self):
        """Unknown finding IDs should fall back to category mapping."""
        result = get_stride_category("UNKNOWN-999", "bola")
        assert result == "Elevation of Privilege"  # bola category fallback

    def test_all_stride_values_valid(self):
        """All returned STRIDE values should be valid STRIDE categories."""
        valid = {"Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                 "Denial of Service", "Elevation of Privilege"}
        test_cases = [
            ("HDR-001", "headers"), ("CRS-001", "cors"),
            ("BOL-001", "bola"), ("TLS-001", "tls"),
        ]
        for fid, cat in test_cases:
            result = get_stride_category(fid, cat)
            assert result in valid, f"{fid} mapped to invalid STRIDE: {result}"


class TestNISTMapping:

    def test_known_finding_ids_mapped(self):
        """Known finding IDs should return NIST CSF functions."""
        assert get_nist_function("HDR-001", "headers") == "Protect"
        assert get_nist_function("BOL-001", "bola") == "Protect"
        assert get_nist_function("HDR-010", "headers") == "Identify"

    def test_all_nist_values_valid(self):
        """All returned NIST values should be valid CSF 2.0 functions."""
        valid = {"Govern", "Identify", "Protect", "Detect", "Respond", "Recover"}
        test_cases = [
            ("HDR-001", "headers"), ("CRS-001", "cors"),
            ("BOL-001", "bola"), ("TLS-001", "tls"),
        ]
        for fid, cat in test_cases:
            result = get_nist_function(fid, cat)
            assert result in valid, f"{fid} mapped to invalid NIST function: {result}"
