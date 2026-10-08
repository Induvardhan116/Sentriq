import pytest
from app.risk.engine import calculate_finding_risk, calculate_posture_score, map_score_to_grade


def test_calculate_finding_risk():
    """Verify deterministic risk scoring for each severity tier."""
    # Full confidence tests
    assert calculate_finding_risk("critical", 1.0) == 90
    assert calculate_finding_risk("high", 1.0) == 75
    assert calculate_finding_risk("medium", 1.0) == 55
    assert calculate_finding_risk("low", 1.0) == 30
    assert calculate_finding_risk("informational", 1.0) == 10

    # Scaled confidence
    assert calculate_finding_risk("critical", 0.5) == 45
    assert calculate_finding_risk("high", 0.8) == 60


def test_map_score_to_grade():
    """Verify standard grade bracket mapping."""
    assert map_score_to_grade(95) == "Excellent"
    assert map_score_to_grade(85) == "Good"
    assert map_score_to_grade(65) == "Needs Improvement"
    assert map_score_to_grade(40) == "Poor"
    assert map_score_to_grade(15) == "Critical"


def test_posture_score_clean_target():
    """An assessment with no findings should return 100 Excellent."""
    score, grade, counts = calculate_posture_score([])
    assert score == 100
    assert grade == "Excellent"
    assert counts["critical"] == 0


def test_posture_score_critical_ceiling():
    """A single Critical finding must deduct points and be capped at maximum 49 (Poor/Critical)."""
    findings = [{"severity": "critical"}]
    score, grade, counts = calculate_posture_score(findings)
    assert score <= 49
    assert grade in ("Poor", "Critical")
    assert counts["critical"] == 1


def test_posture_score_high_ceiling():
    """A High finding must cap the score at maximum 74 (Needs Improvement)."""
    findings = [{"severity": "high"}]
    score, grade, counts = calculate_posture_score(findings)
    assert score <= 74
    assert grade in ("Needs Improvement", "Poor")
    assert counts["high"] == 1


def test_posture_score_multiple_deductions():
    """Verify multiple medium and low findings calculate deductions deterministically."""
    findings = [
        {"severity": "medium"},  # -8
        {"severity": "medium"},  # -8
        {"severity": "low"},     # -3
        {"severity": "informational"}, # -1
    ]
    # 100 - (16 + 3 + 1) = 80
    score, grade, counts = calculate_posture_score(findings)
    assert score == 80
    assert grade == "Good"
    assert counts["medium"] == 2
    assert counts["low"] == 1
    assert counts["informational"] == 1
