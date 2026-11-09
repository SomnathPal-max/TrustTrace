import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Any
from sqlalchemy.orm import Session

from backend.app.models import CampaignInfo, Report, RiskLabel
from backend.app.db.models import ScanRecord, IndicatorRecord
from backend.app.core.safe_client import defang_url

SALT = "TrustTrace-Campaign-Salt-2026"

STRONG_INDICATOR_TYPES = {
    "cert_spki_sha256",
    "message_template_hash",
    "hashed_phone",
    "hashed_upi",
    "final_domain"
}

def hash_salted(val: str) -> str:
    """Computes a salted SHA-256 hash for PII/identifiers."""
    return hashlib.sha256(f"{SALT}:{val.strip().lower()}".encode("utf-8")).hexdigest()

def compute_message_template_hash(text: str) -> str:
    """
    Normalizes message text by replacing dynamic entities (URLs, numbers, amounts, phones, emails)
    with placeholders and collapsing whitespace to catch campaign templates.
    """
    t = text.lower()
    # Replace URLs
    t = re.sub(r"https?://\S+|hxxps?://\S+", "<URL>", t)
    # Replace emails
    t = re.sub(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", "<EMAIL>", t)
    # Replace phone numbers
    t = re.sub(r"(?:\+?91[\-\s]?)?[6-9]\d{9}", "<PHONE>", t)
    # Replace amounts (Rs. 500, $1000, 5000 INR)
    t = re.sub(r"(?:rs\.?|inr|\$|€|£)\s*\d+(?:,\d+)*(?:\.\d+)?", "<AMOUNT>", t)
    # Replace standalone numbers
    t = re.sub(r"\b\d+\b", "<NUM>", t)
    # Collapse whitespace
    t = re.sub(r"\s+", " ", t).strip()
    return hashlib.sha256(t.encode("utf-8")).hexdigest()

class CampaignCorrelator:
    def extract_indicators_from_report(self, report: Report) -> List[Tuple[str, str, str]]:
        """
        Extracts tuples of (indicator_type, indicator_value, strength_class)
        """
        indicators: List[Tuple[str, str, str]] = []

        if report.final_domain:
            indicators.append(("final_domain", report.final_domain.lower(), "strong"))
        if report.registrable_domain:
            indicators.append(("registrable_domain", report.registrable_domain.lower(), "possible"))

        for ip in report.resolved_ips:
            indicators.append(("resolved_ip", ip.strip(), "possible"))

        for hop in report.redirect_chain:
            if hop.registrable_domain:
                indicators.append(("redirect_hop_domain", hop.registrable_domain.lower(), "possible"))

        if report.tls:
            if report.tls.certificate_sha256:
                indicators.append(("cert_sha256", report.tls.certificate_sha256.lower(), "strong"))
            if report.tls.spki_sha256:
                indicators.append(("cert_spki_sha256", report.tls.spki_sha256.lower(), "strong"))

        # Message specific indicators
        if report.message_analysis:
            ma = report.message_analysis
            template_h = compute_message_template_hash(report.input_display)
            indicators.append(("message_template_hash", template_h, "strong"))

            for u in ma.extracted_urls:
                from backend.app.analyzers.url_analyzer import parse_domain_parts
                _, r_dom, _ = parse_domain_parts(u)
                if r_dom:
                    indicators.append(("message_link_domain", r_dom.lower(), "possible"))

            for ph in ma.phone_numbers:
                indicators.append(("hashed_phone", hash_salted(ph), "strong"))

            for upi in ma.upi_ids:
                indicators.append(("hashed_upi", hash_salted(upi), "strong"))

            for em in ma.emails:
                indicators.append(("hashed_email", hash_salted(em), "possible"))

        return list(dict.fromkeys(indicators))

    def correlate(self, current_indicators: List[Tuple[str, str, str]], db: Session) -> CampaignInfo:
        if not current_indicators:
            return CampaignInfo(linked=False)

        matched_indicator_descs: List[str] = []
        matched_report_ids: Set[str] = set()
        matched_types: Set[str] = set()
        has_strong_key_match = False
        first_seen: Optional[str] = None

        for ind_type, ind_val, strength in current_indicators:
            # Only match against prior reports that are Suspicious, High Risk, or Confirmed Malicious
            matches = (
                db.query(IndicatorRecord, ScanRecord)
                .join(ScanRecord, IndicatorRecord.report_id == ScanRecord.report_id)
                .filter(
                    IndicatorRecord.indicator_type == ind_type,
                    IndicatorRecord.indicator_value == ind_val,
                    ScanRecord.risk_label.in_([RiskLabel.SUSPICIOUS.value, RiskLabel.HIGH_RISK.value, RiskLabel.CONFIRMED_MALICIOUS.value])
                )
                .all()
            )

            if matches:
                matched_types.add(ind_type)
                if ind_type in STRONG_INDICATOR_TYPES:
                    has_strong_key_match = True

                for ind_rec, scan_rec in matches:
                    matched_report_ids.add(scan_rec.report_id)
                    if not first_seen or scan_rec.created_at < first_seen:
                        first_seen = scan_rec.created_at

                # Format human readable indicator description
                if ind_type in ("final_domain", "registrable_domain", "redirect_hop_domain", "message_link_domain"):
                    matched_indicator_descs.append(f"Domain: {defang_url(ind_val)}")
                elif ind_type == "resolved_ip":
                    matched_indicator_descs.append(f"Infrastructure IP: {ind_val}")
                elif ind_type == "cert_spki_sha256":
                    matched_indicator_descs.append(f"Shared TLS Certificate SPKI: {ind_val[:12]}...")
                elif ind_type == "message_template_hash":
                    matched_indicator_descs.append("Identical social engineering message template")
                elif ind_type == "hashed_phone":
                    matched_indicator_descs.append("Shared phone number destination")
                elif ind_type == "hashed_upi":
                    matched_indicator_descs.append("Shared UPI payment identifier")

        if not matched_report_ids:
            return CampaignInfo(linked=False)

        # Strength rules (Section 9 Phase 7):
        # Match on any strong key OR 2+ different indicator types -> strong link
        # Single resolved_ip match alone -> possible link
        if has_strong_key_match or len(matched_types) >= 2:
            strength = "strong"
            summary = (
                f"Deterministically linked to existing phishing campaign cluster ({len(matched_report_ids)} prior report(s)). "
                f"Corroborating indicators: {', '.join(matched_indicator_descs[:3])}."
            )
        else:
            strength = "possible"
            summary = (
                f"Possible infrastructure overlap with prior scan ({len(matched_report_ids)} related report(s)). "
                "Shared hosting or common IP address detected."
            )

        return CampaignInfo(
            linked=True,
            strength=strength,
            matched_indicators=list(dict.fromkeys(matched_indicator_descs)),
            related_report_count=len(matched_report_ids),
            first_seen=first_seen,
            cluster_size=len(matched_report_ids) + 1,
            ai_summary=summary
        )

def get_related_reports_for(report_id: str, db: Session) -> Dict[str, Any]:
    """Computes related reports on demand without modifying earlier reports."""
    record = db.query(ScanRecord).filter(ScanRecord.report_id == report_id).first()
    if not record:
        return {"report_id": report_id, "related_reports": [], "cluster_size": 0}

    # Get indicators for this report
    indicators = db.query(IndicatorRecord).filter(IndicatorRecord.report_id == report_id).all()
    if not indicators:
        return {"report_id": report_id, "related_reports": [], "cluster_size": 1}

    related_map = {}
    for ind in indicators:
        matches = (
            db.query(IndicatorRecord, ScanRecord)
            .join(ScanRecord, IndicatorRecord.report_id == ScanRecord.report_id)
            .filter(
                IndicatorRecord.indicator_type == ind.indicator_type,
                IndicatorRecord.indicator_value == ind.indicator_value,
                ScanRecord.report_id != report_id
            )
            .all()
        )
        for i_rec, s_rec in matches:
            if s_rec.report_id not in related_map:
                rep_json = json.loads(s_rec.full_report_json)
                related_map[s_rec.report_id] = {
                    "report_id": s_rec.report_id,
                    "created_at": s_rec.created_at,
                    "input_display": rep_json.get("input_display", ""),
                    "risk_label": s_rec.risk_label,
                    "risk_score": s_rec.risk_score,
                    "matched_indicators": [f"{ind.indicator_type}: {ind.indicator_value[:16]}..."]
                }
            else:
                related_map[s_rec.report_id]["matched_indicators"].append(f"{ind.indicator_type}: {ind.indicator_value[:16]}...")

    related_list = list(related_map.values())
    return {
        "report_id": report_id,
        "related_reports": related_list,
        "cluster_size": len(related_list) + 1
    }

campaign_correlator = CampaignCorrelator()
