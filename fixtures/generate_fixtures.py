import json
from backend.app.models import ScanRequest
from backend.app.orchestrator import run_scan_pipeline
from backend.app.db.session import SessionLocal, init_db
from backend.app.db.models import ScanRecord

init_db()
db = SessionLocal()

cases = [
    ("B1", "url", "https://sbi.co.in"),
    ("B2", "url", "https://github.com"),
    ("B3", "url", "https://wikipedia.org"),
    ("S1", "url", "http://sbi-kyc-update.com/login"),
    ("S2", "url", "http://xn--gogl-qqa.com/login"),
    ("S3", "message", "URGENT: Your SBI bank account will be blocked within 2 hours. Update your PAN card and Aadhaar details immediately to avoid deactivation: http://sbi-kyc-update.com/pan. Call 9876543210."),
    ("SIM", "url", "https://simulated-distrusted-ca.local")
]

cached_fixtures = {}
for case_id, t, val in cases:
    rep_id = f"cached-{case_id.lower()}"
    req = ScanRequest(type=t, value=val, use_cached=True)
    run_scan_pipeline(rep_id, req, db)
    rec = db.query(ScanRecord).filter(ScanRecord.report_id == rep_id).first()
    if rec:
        rep = json.loads(rec.full_report_json)
        rep["is_cached_sample"] = True
        cached_fixtures[case_id] = rep
        label = rep.get("risk_label")
        score = rep.get("risk_score")
        cov = rep.get("evidence_coverage", {}).get("percent")
        print(f"{case_id}: {label} ({score} pts) - Coverage: {cov}%")

with open("fixtures/cached_samples.json", "w", encoding="utf-8") as f:
    json.dump(cached_fixtures, f, indent=2)

print("Successfully generated fixtures/cached_samples.json!")
