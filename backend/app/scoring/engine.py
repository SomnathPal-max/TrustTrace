import re
from typing import Dict, List, Optional, Set, Tuple, Any

from backend.app.models import (
    Finding, FindingCategory, Severity, RiskLabel, EvidenceCoverage,
    CheckRecord, Report
)

# Category point caps (Section 8.2)
CATEGORY_CAPS = {
    FindingCategory.IMPERSONATION: 50,
    FindingCategory.STRUCTURE: 35,
    FindingCategory.DOMAIN: 30,
    FindingCategory.REDIRECT: 25,
    FindingCategory.TLS: 50,      # TLS-06 excepted
    FindingCategory.INTEL: 40,    # INT-01 excepted
    FindingCategory.HEADERS: 8,   # Not counted as independent category
    FindingCategory.CONTENT: 50
}

# Coverage weights (Section 7.4)
CHECK_GROUP_WEIGHTS = {
    "Lexical analysis": 20,
    "Domain and DNS": 15,
    "Redirect and fetch": 15,
    "TLS": 20,
    "Security headers": 5,
    "Threat intelligence": 20,
    "Certificate Transparency": 5
}

# Banned phrases that must never appear as a verdict (HC-02)
BANNED_VERDICT_PHRASES = [
    re.compile(r"\b100%\s*safe\b", re.IGNORECASE),
    re.compile(r"\bcompletely\s*safe\b", re.IGNORECASE),
    re.compile(r"\bguaranteed\b", re.IGNORECASE),
    re.compile(r"\bno\s*risk\b", re.IGNORECASE),
    re.compile(r"\bverdict:\s*safe\b", re.IGNORECASE),
    re.compile(r"\bsite\s*is\s*safe\b", re.IGNORECASE),
    re.compile(r"\bsite\s*is\s*secure\b", re.IGNORECASE),
]

def check_banned_phrases(text: str) -> Optional[str]:
    """Returns matched banned phrase if text improperly claims a site is 100% safe/secure."""
    for pattern in BANNED_VERDICT_PHRASES:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None

class ScoringEngine:
    def calculate_coverage(
        self,
        completed_groups: List[str],
        unavailable_groups: List[str]
    ) -> EvidenceCoverage:
        total_weight = 0
        for grp in completed_groups:
            if grp in CHECK_GROUP_WEIGHTS:
                total_weight += CHECK_GROUP_WEIGHTS[grp]
        
        # Clamp to 100
        percent = min(100, total_weight)
        return EvidenceCoverage(
            percent=percent,
            completed_groups=completed_groups,
            unavailable_groups=unavailable_groups
        )

    def calculate_score_and_label(
        self,
        findings: List[Finding],
        coverage: EvidenceCoverage,
        is_official_brand: bool = False,
        domain_age_days: Optional[int] = None,
        is_host_unreachable: bool = False
    ) -> Tuple[int, RiskLabel, Dict[str, int]]:
        """
        Executes strict Section 8.3 label decision order.
        Returns: (final_score, risk_label, capped_category_scores)
        """
        # Step 1: If INT-01 fired: label is Confirmed Malicious. Stop.
        for f in findings:
            if f.signal_id == "INT-01":
                return 100, RiskLabel.CONFIRMED_MALICIOUS, {"INTEL": 100}

        # Step 2: Compute category scores with caps
        category_raw: Dict[FindingCategory, int] = {}
        has_tls_06 = False
        has_impersonation = False

        for f in findings:
            cat = f.category
            category_raw[cat] = category_raw.get(cat, 0) + f.points
            if f.signal_id == "TLS-06":
                has_tls_06 = True
            if cat == FindingCategory.IMPERSONATION:
                has_impersonation = True

        # Apply category caps
        capped_scores: Dict[str, int] = {}
        for cat, raw_pts in category_raw.items():
            if cat == FindingCategory.TLS and has_tls_06:
                # TLS-06 excepted from 50 cap
                capped_scores[cat.value] = min(100, raw_pts)
            elif cat == FindingCategory.INTEL and any(f.signal_id == "INT-01" for f in findings):
                capped_scores[cat.value] = 100
            else:
                cap = CATEGORY_CAPS.get(cat, 50)
                capped_scores[cat.value] = min(cap, raw_pts)

        # Count distinct flagged categories (excluding HEADERS)
        distinct_categories: Set[FindingCategory] = set()
        for f in findings:
            if f.category != FindingCategory.HEADERS and f.points > 0:
                distinct_categories.add(f.category)
        distinct_cat_count = len(distinct_categories)

        # Calculate base score
        score = sum(capped_scores.values())

        # Mitigation MIT-02: domain older than 5 years (1825 days) subtracts 10 points
        if domain_age_days and domain_age_days >= 1825:
            # Does not offset INTEL or TLS-06
            non_critical_pts = score - (capped_scores.get("INTEL", 0) + (45 if has_tls_06 else 0))
            if non_critical_pts > 0:
                deduction = min(10, non_critical_pts)
                score = max(0, score - deduction)

        score = min(100, max(0, score))

        # Step 3: If TLS-06 fired: label is at least High Risk
        if has_tls_06:
            return max(score, 75), RiskLabel.HIGH_RISK, capped_scores

        # Step 4: If score is 45 or more AND at least two distinct categories flagged: High Risk
        if score >= 45 and distinct_cat_count >= 2:
            return score, RiskLabel.HIGH_RISK, capped_scores

        # Step 5: Else if score is 15 or more, OR any IMPERSONATION signal fired: Suspicious
        # (This includes score of 45+ from a single category, the false-positive control)
        if score >= 15 or has_impersonation:
            return score, RiskLabel.SUSPICIOUS, capped_scores

        # Step 6: Else (score below 15):
        # If evidence coverage is 60 percent or more and at least one of TLS or redirect completed: Low Risk; else Inconclusive
        has_tls_or_redirect = ("TLS" in coverage.completed_groups) or ("Redirect and fetch" in coverage.completed_groups)
        if coverage.percent >= 60 and has_tls_or_redirect:
            # Step 7: If coverage is below 50 percent and label would be Low Risk -> Inconclusive
            if coverage.percent < 50:
                return score, RiskLabel.INCONCLUSIVE, capped_scores
            
            # Step 8: If host cannot be resolved or reached and no impersonation/structure signal fired -> Inconclusive
            if is_host_unreachable and not has_impersonation and not ("STRUCTURE" in capped_scores):
                return score, RiskLabel.INCONCLUSIVE, capped_scores

            return score, RiskLabel.LOW_RISK, capped_scores
        else:
            return score, RiskLabel.INCONCLUSIVE, capped_scores

    def assemble_report(
        self,
        report_id: str,
        input_type: str,
        input_display: str,
        normalized_url: str,
        registrable_domain: str,
        final_url: str,
        final_domain: str,
        resolved_ips: List[str],
        findings: List[Finding],
        checks: List[CheckRecord],
        coverage: EvidenceCoverage,
        risk_label: RiskLabel,
        risk_score: int,
        redirect_chain: List[Any],
        tls: Optional[Any],
        security_headers: List[Any],
        threat_intel: Any,
        campaign: Any,
        message_analysis: Optional[Any],
        ai_explanation: Any,
        duration_ms: int,
        is_cached_sample: bool = False
    ) -> Report:
        # Sort findings by severity then points (Section 7.2 & 9 Phase 5)
        severity_order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1
        }
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 0), f.points),
            reverse=True
        )

        # Gather concrete recommended actions
        rec_actions = []
        if risk_label in (RiskLabel.HIGH_RISK, RiskLabel.CONFIRMED_MALICIOUS):
            rec_actions.append("Do not open the link, download files, or enter credentials or sensitive details.")
            rec_actions.append("If credentials or payment details were already submitted, immediately change passwords and freeze affected bank cards.")
            rec_actions.append("Report this link to the impersonated brand and local cybercrime authorities.")
        elif risk_label == RiskLabel.SUSPICIOUS:
            rec_actions.append("Exercise caution. Verify the sender or domain independently through official published channels.")
            rec_actions.append("Check the domain spelling carefully before proceeding.")
        elif risk_label == RiskLabel.LOW_RISK:
            rec_actions.append("No malicious indicators detected within available passive checks.")
            rec_actions.append("Exercise standard web hygiene and ensure the browser shows a valid lock icon.")
        else:
            rec_actions.append("Insufficient data to complete verification. Do not enter credentials until the destination can be verified.")

        # Limitations list
        limitations = [
            "Absence of a match in these sources does not prove a site is safe.",
            "Passive inspection does not execute JavaScript or perform intrusive vulnerability testing."
        ]
        for grp in coverage.unavailable_groups:
            limitations.append(f"The '{grp}' check group was unavailable or timed out.")

        # Disclaimer (Appendix F)
        disclaimer = (
            "No automated tool can guarantee a website is completely safe. "
            "This assessment reflects only the checks that were available at the time of analysis."
        )

        # Enforce Banned-phrase verification (HC-02)
        all_text = f"{ai_explanation.summary} {' '.join(ai_explanation.recommended_actions)} {' '.join(rec_actions)}"
        banned = check_banned_phrases(all_text)
        if banned:
            raise ValueError(f"Report generation blocked: Banned phrase '{banned}' detected (HC-02 violation).")

        from datetime import datetime, timezone
        now_str = datetime.now(timezone.utc).isoformat()

        return Report(
            report_id=report_id,
            schema_version=1,
            created_at=now_str,
            input_type=input_type,
            input_display=input_display,
            normalized_url=normalized_url,
            registrable_domain=registrable_domain,
            final_url=final_url,
            final_domain=final_domain,
            resolved_ips=resolved_ips,
            risk_label=risk_label,
            risk_score=risk_score,
            evidence_coverage=coverage,
            findings=sorted_findings,
            checks=checks,
            redirect_chain=redirect_chain,
            tls=tls,
            security_headers=security_headers,
            threat_intel=threat_intel,
            campaign=campaign,
            message_analysis=message_analysis,
            ai_explanation=ai_explanation,
            recommended_actions=rec_actions,
            limitations=limitations,
            disclaimer=disclaimer,
            analysis_duration_ms=duration_ms,
            is_cached_sample=is_cached_sample
        )

scoring_engine = ScoringEngine()
