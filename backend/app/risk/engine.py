from typing import Dict, List, Tuple

# Base severity weights (0-100 scale)
SEVERITY_BASE_WEIGHTS: Dict[str, int] = {
    "critical": 90,
    "high": 75,
    "medium": 55,
    "low": 30,
    "informational": 10,
}

# Severity point deductions for overall score calculation
SEVERITY_DEDUCTIONS: Dict[str, int] = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "informational": 1,
}


def calculate_finding_risk(severity: str, confidence: float = 1.0) -> int:
    """Calculate deterministic risk score (0-100) for a single security finding.

    Formula:
        risk = round(base_severity_weight * clamp(confidence, 0.1, 1.0))
        Result clamped to [0, 100].
    """
    normalized_sev = severity.lower().strip()
    base_weight = SEVERITY_BASE_WEIGHTS.get(normalized_sev, 30)

    # Constrain confidence between 0.1 and 1.0
    conf_factor = max(0.1, min(1.0, float(confidence)))

    risk = int(round(base_weight * conf_factor))
    return max(0, min(100, risk))


def map_score_to_grade(score: int) -> str:
    """Map a 0-100 security score to a human-readable grade tier."""
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Needs Improvement"
    if score >= 25:
        return "Poor"
    return "Critical"


def calculate_posture_score(findings: List[Dict[str, str]]) -> Tuple[int, str, Dict[str, int]]:
    """Calculate the overall security posture score (0-100) based on actual findings.

    Deduction model:
        Initial baseline: 100 points
        - Each Critical finding: -25 pts
        - Each High finding: -15 pts
        - Each Medium finding: -8 pts
        - Each Low finding: -3 pts
        - Each Informational: -1 pt (capped at 5 pts total)

    Security Caps:
        - If any Critical finding exists: score capped at 49 ("Poor")
        - If any High finding exists: score capped at 74 ("Needs Improvement")

    Returns:
        (overall_score, grade, severity_counts)
    """
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    for f in findings:
        sev = f.get("severity", "informational").lower().strip()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["informational"] += 1

    deductions = (
        counts["critical"] * SEVERITY_DEDUCTIONS["critical"]
        + counts["high"] * SEVERITY_DEDUCTIONS["high"]
        + counts["medium"] * SEVERITY_DEDUCTIONS["medium"]
        + counts["low"] * SEVERITY_DEDUCTIONS["low"]
        + min(5, counts["informational"] * SEVERITY_DEDUCTIONS["informational"])
    )

    score = 100 - deductions

    # Apply security ceiling caps to avoid false sense of security
    if counts["critical"] > 0:
        score = min(score, 49)
    elif counts["high"] > 0:
        score = min(score, 74)

    score = max(0, min(100, score))
    grade = map_score_to_grade(score)

    return score, grade, counts
