import json
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from backend.app.db.models import ScanRecord, IndicatorRecord
from backend.app.models import RiskLabel
from backend.app.correlation.engine import compute_message_template_hash, hash_salted

def seed_demo_campaigns(db: Session):
    # Check if already seeded
    existing = db.query(ScanRecord).filter(ScanRecord.is_demo_seed == True).count()
    if existing > 0:
        return

    now = datetime.now(timezone.utc)

    # SEED 1: sbi-kyc-login.com (High Risk bank phishing lookalike)
    rep1_id = "seed-sbi-phish-01"
    t1 = (now - timedelta(days=5)).isoformat()
    rep1_json = {
        "report_id": rep1_id,
        "input_type": "url",
        "input_display": "http://sbi-kyc-login.com/auth",
        "registrable_domain": "sbi-kyc-login.com",
        "final_domain": "sbi-kyc-login.com",
        "risk_label": RiskLabel.HIGH_RISK.value,
        "risk_score": 85,
        "is_demo_seed": True
    }
    db.add(ScanRecord(
        report_id=rep1_id,
        created_at=t1,
        input_type="url",
        risk_label=RiskLabel.HIGH_RISK.value,
        risk_score=85,
        full_report_json=json.dumps(rep1_json),
        is_committed=True,
        is_demo_seed=True,
        report_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ))
    db.add(IndicatorRecord(report_id=rep1_id, indicator_type="final_domain", indicator_value="sbi-kyc-login.com", strength_class="strong", created_at=t1))
    db.add(IndicatorRecord(report_id=rep1_id, indicator_type="resolved_ip", indicator_value="198.51.100.25", strength_class="possible", created_at=t1))
    db.add(IndicatorRecord(report_id=rep1_id, indicator_type="cert_spki_sha256", indicator_value="4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945", strength_class="strong", created_at=t1))

    # SEED 2: Historical scam SMS with matching template & phone number
    rep2_id = "seed-sms-scam-02"
    t2 = (now - timedelta(days=3)).isoformat()
    sms_text = "URGENT: Your SBI bank account will be blocked within 2 hours. Update your PAN card and Aadhaar details immediately to avoid deactivation: http://sbi-kyc-update.com/pan. Call 9876543210."
    tmpl_hash = compute_message_template_hash(sms_text)
    rep2_json = {
        "report_id": rep2_id,
        "input_type": "message",
        "input_display": sms_text,
        "risk_label": RiskLabel.HIGH_RISK.value,
        "risk_score": 90,
        "is_demo_seed": True
    }
    db.add(ScanRecord(
        report_id=rep2_id,
        created_at=t2,
        input_type="message",
        risk_label=RiskLabel.HIGH_RISK.value,
        risk_score=90,
        full_report_json=json.dumps(rep2_json),
        is_committed=True,
        is_demo_seed=True,
        report_hash="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
    ))
    db.add(IndicatorRecord(report_id=rep2_id, indicator_type="message_template_hash", indicator_value=tmpl_hash, strength_class="strong", created_at=t2))
    db.add(IndicatorRecord(report_id=rep2_id, indicator_type="hashed_phone", indicator_value=hash_salted("9876543210"), strength_class="strong", created_at=t2))
    db.add(IndicatorRecord(report_id=rep2_id, indicator_type="message_link_domain", indicator_value="sbi-kyc-update.com", strength_class="possible", created_at=t2))

    # SEED 3: hdfc-online-kyc.in (Shares resolved_ip 198.51.100.25 with SEED 1 -> tests soft link "Possible infrastructure overlap")
    rep3_id = "seed-shared-ip-03"
    t3 = (now - timedelta(days=2)).isoformat()
    rep3_json = {
        "report_id": rep3_id,
        "input_type": "url",
        "input_display": "http://hdfc-online-kyc.in/login",
        "registrable_domain": "hdfc-online-kyc.in",
        "final_domain": "hdfc-online-kyc.in",
        "risk_label": RiskLabel.HIGH_RISK.value,
        "risk_score": 80,
        "is_demo_seed": True
    }
    db.add(ScanRecord(
        report_id=rep3_id,
        created_at=t3,
        input_type="url",
        risk_label=RiskLabel.HIGH_RISK.value,
        risk_score=80,
        full_report_json=json.dumps(rep3_json),
        is_committed=True,
        is_demo_seed=True,
        report_hash="35a9e381b1a27567549b5f8a6f783c167ebf809630c399144d738a82b1a038ac"
    ))
    db.add(IndicatorRecord(report_id=rep3_id, indicator_type="final_domain", indicator_value="hdfc-online-kyc.in", strength_class="strong", created_at=t3))
    db.add(IndicatorRecord(report_id=rep3_id, indicator_type="resolved_ip", indicator_value="198.51.100.25", strength_class="possible", created_at=t3))

    db.commit()
