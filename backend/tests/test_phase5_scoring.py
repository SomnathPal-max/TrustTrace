import pytest
from backend.app.models import Finding, FindingCategory, Severity, RiskLabel, EvidenceCoverage
from backend.app.scoring.engine import scoring_engine, check_banned_phrases

def test_int01_forces_confirmed_malicious():
    findings = [
        Finding(
            id="F-01", signal_id="INT-01", category=FindingCategory.INTEL,
            title="Malicious URL", description="Listed on URLhaus",
            severity=Severity.CRITICAL, points=100, source="URLhaus",
            potential_impact="Impact", recommendation="Block", limitation="None"
        )
    ]
    cov = EvidenceCoverage(percent=100, completed_groups=["Threat intelligence"], unavailable_groups=[])
    score, label, _ = scoring_engine.calculate_score_and_label(findings, cov)
    assert label == RiskLabel.CONFIRMED_MALICIOUS
    assert score == 100

def test_heuristics_alone_never_reach_confirmed_malicious():
    # Strong heuristics across multiple categories
    findings = [
        Finding(
            id="F-01", signal_id="IMP-01", category=FindingCategory.IMPERSONATION,
            title="Impersonation", description="Brand impersonation",
            severity=Severity.HIGH, points=40, source="lexical",
            potential_impact="Impact", recommendation="Rec", limitation="None"
        ),
        Finding(
            id="F-02", signal_id="STR-01", category=FindingCategory.STRUCTURE,
            title="Structure", description="Phishing keyword",
            severity=Severity.MEDIUM, points=15, source="lexical",
            potential_impact="Impact", recommendation="Rec", limitation="None"
        ),
        Finding(
            id="F-03", signal_id="DOM-01", category=FindingCategory.DOMAIN,
            title="New domain", description="Young domain",
            severity=Severity.MEDIUM, points=25, source="RDAP",
            potential_impact="Impact", recommendation="Rec", limitation="None"
        )
    ]
    cov = EvidenceCoverage(percent=80, completed_groups=["Lexical analysis", "Domain and DNS"], unavailable_groups=[])
    score, label, _ = scoring_engine.calculate_score_and_label(findings, cov)
    # Must NOT be Confirmed Malicious (HC-05)
    assert label == RiskLabel.HIGH_RISK
    assert label != RiskLabel.CONFIRMED_MALICIOUS

def test_tls06_distrusted_ca_floor_high_risk():
    findings = [
        Finding(
            id="F-01", signal_id="TLS-06", category=FindingCategory.TLS,
            title="Distrusted CA", description="Distrusted CA in chain",
            severity=Severity.HIGH, points=45, source="distrust list",
            potential_impact="Impact", recommendation="Rec", limitation="None"
        )
    ]
    cov = EvidenceCoverage(percent=70, completed_groups=["TLS"], unavailable_groups=[])
    score, label, _ = scoring_engine.calculate_score_and_label(findings, cov)
    assert label == RiskLabel.HIGH_RISK

def test_single_category_high_score_caps_at_suspicious():
    # False-positive control: Score >= 45 from a single category (e.g. only STRUCTURE)
    findings = [
        Finding(
            id="F-01", signal_id="STR-02", category=FindingCategory.STRUCTURE,
            title="IP host", description="IP used as host",
            severity=Severity.MEDIUM, points=20, source="lexical",
            potential_impact="Impact", recommendation="Rec", limitation="None"
        ),
        Finding(
            id="F-02", signal_id="STR-03", category=FindingCategory.STRUCTURE,
            title="@ trick", description="User info in URL",
            severity=Severity.MEDIUM, points=20, source="lexical",
            potential_impact="Impact", recommendation="Rec", limitation="None"
        ),
        Finding(
            id="F-03", signal_id="STR-04", category=FindingCategory.STRUCTURE,
            title="Deep subdomains", description="Complexity",
            severity=Severity.LOW, points=10, source="lexical",
            potential_impact="Impact", recommendation="Rec", limitation="None"
        )
    ]
    cov = EvidenceCoverage(percent=70, completed_groups=["Lexical analysis"], unavailable_groups=[])
    score, label, capped = scoring_engine.calculate_score_and_label(findings, cov)
    # Only 1 category flagged -> must be Suspicious, not High Risk
    assert label == RiskLabel.SUSPICIOUS
    assert capped["STRUCTURE"] == 35  # Capped at 35

def test_lookalike_with_valid_https_never_below_suspicious():
    # IMP-01 lookalike domain with valid HTTPS cert (HC-03)
    findings = [
        Finding(
            id="F-01", signal_id="IMP-01", category=FindingCategory.IMPERSONATION,
            title="Lookalike", description="Impersonates brand",
            severity=Severity.HIGH, points=40, source="lexical",
            potential_impact="Impact", recommendation="Rec", limitation="None"
        )
    ]
    # Full 100% coverage with healthy TLS
    cov = EvidenceCoverage(
        percent=100,
        completed_groups=["Lexical analysis", "Domain and DNS", "TLS", "Security headers", "Threat intelligence"],
        unavailable_groups=[]
    )
    score, label, _ = scoring_engine.calculate_score_and_label(findings, cov)
    assert label in (RiskLabel.SUSPICIOUS, RiskLabel.HIGH_RISK)
    assert label != RiskLabel.LOW_RISK

def test_clean_site_adequate_coverage_low_risk():
    findings = []  # No findings
    cov = EvidenceCoverage(
        percent=75,
        completed_groups=["Lexical analysis", "Domain and DNS", "TLS", "Threat intelligence"],
        unavailable_groups=[]
    )
    score, label, _ = scoring_engine.calculate_score_and_label(findings, cov)
    assert label == RiskLabel.LOW_RISK
    assert score == 0

def test_clean_site_low_coverage_inconclusive():
    findings = []  # No findings, but low coverage (< 50%)
    cov = EvidenceCoverage(
        percent=35,
        completed_groups=["Lexical analysis", "Domain and DNS"],
        unavailable_groups=["TLS", "Redirect and fetch", "Threat intelligence"]
    )
    score, label, _ = scoring_engine.calculate_score_and_label(findings, cov)
    assert label == RiskLabel.INCONCLUSIVE

def test_unreachable_host_without_signals_inconclusive():
    findings = []
    cov = EvidenceCoverage(percent=65, completed_groups=["Lexical analysis", "Threat intelligence"], unavailable_groups=[])
    score, label, _ = scoring_engine.calculate_score_and_label(findings, cov, is_host_unreachable=True)
    assert label == RiskLabel.INCONCLUSIVE

def test_banned_phrases_filter():
    assert check_banned_phrases("This portal is 100% safe to use.") is not None
    assert check_banned_phrases("Verdict: Safe") is not None
    assert check_banned_phrases("The site is guaranteed secure.") is not None
    assert check_banned_phrases("No significant malicious indicators identified.") is None
