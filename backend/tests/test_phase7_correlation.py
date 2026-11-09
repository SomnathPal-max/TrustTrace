import pytest
from backend.app.db.session import SessionLocal, init_db
from backend.app.db.seed_data import seed_demo_campaigns
from backend.app.db.models import ScanRecord, IndicatorRecord
from backend.app.correlation.engine import campaign_correlator, compute_message_template_hash, hash_salted, get_related_reports_for

@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    db = SessionLocal()
    seed_demo_campaigns(db)
    db.close()

def test_strong_campaign_link():
    db = SessionLocal()
    try:
        # Scan with matching SPKI certificate hash as SEED-01
        test_indicators = [
            ("cert_spki_sha256", "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945", "strong"),
            ("final_domain", "another-sbi-portal.com", "strong")
        ]
        campaign = campaign_correlator.correlate(test_indicators, db)
        assert campaign.linked is True
        assert campaign.strength == "strong"
        assert campaign.related_report_count >= 1
        assert any("Shared TLS Certificate SPKI" in ind for ind in campaign.matched_indicators)
    finally:
        db.close()

def test_message_template_campaign_link():
    db = SessionLocal()
    try:
        # Scam SMS that differs only slightly in link or amount
        new_sms = "URGENT: Your SBI bank account will be blocked within 2 hours. Update your PAN card and Aadhaar details immediately to avoid deactivation: http://sbi-fake-pan.com/update. Call 9876543210."
        new_template_h = compute_message_template_hash(new_sms)
        test_indicators = [
            ("message_template_hash", new_template_h, "strong"),
            ("hashed_phone", hash_salted("9876543210"), "strong")
        ]
        campaign = campaign_correlator.correlate(test_indicators, db)
        assert campaign.linked is True
        assert campaign.strength == "strong"
        assert any("message template" in ind.lower() for ind in campaign.matched_indicators)
    finally:
        db.close()

def test_soft_link_shared_ip_only():
    db = SessionLocal()
    try:
        # Only shares IP 198.51.100.25 (shared hosting)
        test_indicators = [
            ("resolved_ip", "198.51.100.25", "possible"),
            ("final_domain", "completely-unrelated-blog.com", "strong")
        ]
        campaign = campaign_correlator.correlate(test_indicators, db)
        assert campaign.linked is True
        # Since only 1 indicator type matched (resolved_ip), strength MUST be 'possible' (soft badge)
        assert campaign.strength == "possible"
        assert "Possible infrastructure overlap" in campaign.ai_summary
    finally:
        db.close()

def test_older_reports_unchanged():
    db = SessionLocal()
    try:
        # Check that SEED-01 report_hash remained completely intact
        seed1 = db.query(ScanRecord).filter(ScanRecord.report_id == "seed-sbi-phish-01").first()
        original_hash = seed1.report_hash
        
        # Correlate a new scan
        test_indicators = [("resolved_ip", "198.51.100.25", "possible")]
        campaign_correlator.correlate(test_indicators, db)

        # Re-fetch seed 1
        db.expire_all()
        seed1_after = db.query(ScanRecord).filter(ScanRecord.report_id == "seed-sbi-phish-01").first()
        assert seed1_after.report_hash == original_hash
    finally:
        db.close()
