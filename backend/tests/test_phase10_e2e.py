import uuid
import json
import pytest
from backend.app.orchestrator import run_scan_pipeline
from backend.app.core.job_runner import job_runner
from backend.app.db.session import SessionLocal
from backend.app.db.models import ScanRecord
from backend.app.models import ScanRequest, Report, RiskLabel
from backend.app.web3.canonical import canonical_serialize, compute_onchain_id
from backend.app.web3.client import (
    commit_report_onchain,
    verify_report_integrity,
    tamper_stored_report,
    restore_stored_report,
)

BANNED_WORDS = ["safe", "100% safe", "guaranteed safe", "completely safe"]

def test_cached_demo_samples_e2e():
    """Verify that cached demo samples (B1, B2, B3, S1, S2, S3, SIM) run through orchestrator."""
    cases = [
        ("url", "https://sbi.co.in", RiskLabel.LOW_RISK),
        ("url", "https://github.com", RiskLabel.LOW_RISK),
        ("url", "https://wikipedia.org", RiskLabel.LOW_RISK),
        ("url", "http://sbi-kyc-update.com/login", RiskLabel.HIGH_RISK),
        ("url", "http://xn--gogl-qqa.com/login", RiskLabel.SUSPICIOUS),
        ("message", "SBI Alert: Your account is blocked within 2 hours. Click http://sbi-kyc-update.com/pan", RiskLabel.HIGH_RISK),
        ("url", "https://simulated-distrusted-ca.test.local", RiskLabel.HIGH_RISK),
    ]

    db = SessionLocal()
    try:
        for atype, target, expected_label in cases:
            report_id = str(uuid.uuid4())
            req = ScanRequest(type=atype, value=target, use_cached=True)
            job_runner.register_job(report_id, atype, target)
            
            run_scan_pipeline(report_id, req, db)
            
            job = job_runner.get_status(report_id)
            assert job["status"] == "complete", f"Scan {target} failed: {job.get('error')}"
            
            report_data = job["report"]
            report = Report.model_validate(report_data)
            
            # Risk label verification
            assert report.risk_label == expected_label, f"Target {target} got {report.risk_label}, expected {expected_label}"
            
            # HC-02 check: never say "safe" in risk label
            assert "safe" not in report.risk_label.value.lower()
            
            # Check canonical hash can be computed
            _, report_hash = canonical_serialize(report.model_dump())
            assert report_hash is not None
            assert len(report_hash) == 64  # SHA-256 hex string
    finally:
        db.close()

def test_tamper_detection_e2e():
    """Test that tampering with report contents alters the canonical hash and causes MISMATCH."""
    db = SessionLocal()
    try:
        report_id = str(uuid.uuid4())
        req = ScanRequest(type="url", value="http://sbi-kyc-update.com/login", use_cached=True)
        job_runner.register_job(report_id, "url", "http://sbi-kyc-update.com/login")
        run_scan_pipeline(report_id, req, db)
        
        job = job_runner.get_status(report_id)
        assert job["status"] == "complete"
        
        # Commit report on-chain
        commit_res = commit_report_onchain(report_id, db)
        assert commit_res["status"] == "committed"
        assert commit_res["tx_hash"] is not None
        
        # 1. Verify unchanged report is MATCH
        v1 = verify_report_integrity(report_id, db)
        assert v1["result_code"] == "MATCH"
        assert "verified successfully" in v1["message"]
        
        # 2. Tamper report
        t_res = tamper_stored_report(report_id, db)
        assert t_res["tampered"] is True
        
        # 3. Verify tampered report is MISMATCH
        v2 = verify_report_integrity(report_id, db)
        assert v2["result_code"] == "MISMATCH"
        assert "tamper detected" in v2["message"].lower()
        
        # 4. Restore report and verify it matches again
        r_res = restore_stored_report(report_id, db)
        assert r_res["restored"] is True
        
        v3 = verify_report_integrity(report_id, db)
        assert v3["result_code"] == "MATCH"
    finally:
        db.close()

def test_message_scam_samples_live():
    """Verify live message analysis pipeline flags urgent financial lure."""
    db = SessionLocal()
    try:
        report_id = str(uuid.uuid4())
        sms_fraud = "SBI ALERT: Dear customer your SBI NetBanking account is blocked today. Update PAN immediately click http://sbi-kyc-update.com or your account will be suspended in 2 hours."
        req = ScanRequest(type="message", value=sms_fraud, use_cached=False)
        job_runner.register_job(report_id, "message", sms_fraud)
        
        run_scan_pipeline(report_id, req, db)
        job = job_runner.get_status(report_id)
        assert job["status"] == "complete"
        
        report = Report.model_validate(job["report"])
        assert report.risk_label in [RiskLabel.HIGH_RISK, RiskLabel.CONFIRMED_MALICIOUS]
        assert report.risk_score >= 50
        
        # Explanation must not be empty
        assert len(report.ai_explanation.summary) > 0
        
        # Banned words check (HC-02)
        summary_lower = report.ai_explanation.summary.lower()
        for word in ["100% safe", "guaranteed safe"]:
            assert word not in summary_lower
    finally:
        db.close()
