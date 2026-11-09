import pytest
from datetime import datetime
from backend.app.api.routes import get_health, get_security_controls, get_samples, start_scan, poll_scan
from backend.app.models import ScanRequest, RiskLabel
from backend.app.db.session import SessionLocal, init_db
from backend.app.db.models import ScanRecord, IndicatorRecord, CommitRecord
from fastapi import BackgroundTasks

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

def test_health_endpoint():
    data = get_health()
    assert data["status"] == "healthy"
    assert data["service"] == "Link & Scam Detective"
    assert "version" in data
    assert "timestamp" in data

def test_security_controls_endpoint():
    data = get_security_controls()
    assert "active_protections" in data
    protections = {p["id"] for p in data["active_protections"]}
    assert "CTRL-SSRF" in protections
    assert "CTRL-PASSIVE" in protections
    assert "CTRL-AI-SAFETY" in protections
    assert "CTRL-PRIVACY" in protections
    assert "CTRL-EMUDHRA" in protections

def test_samples_endpoint():
    data = get_samples()
    assert "demo_samples" in data
    assert len(data["demo_samples"]) == 6
    ids = [s["id"] for s in data["demo_samples"]]
    assert ids == ["B1", "B2", "B3", "S1", "S2", "S3"]
    assert "extra_tests" in data
    assert len(data["extra_tests"]) >= 5

def test_start_and_poll_scan():
    db = SessionLocal()
    try:
        bg = BackgroundTasks()
        req = ScanRequest(type="url", value="https://example.com")
        res = start_scan(request=req, background_tasks=bg, db=db)
        assert "report_id" in res
        assert res["status"] == "queued"
        report_id = res["report_id"]

        # Run background tasks manually
        for task in bg.tasks:
            task.func(*task.args, **task.kwargs)

        poll_res = poll_scan(report_id, db=db)
        assert poll_res["report_id"] == report_id
        assert poll_res["status"] == "complete"
        assert poll_res["report"] is not None
        assert poll_res["report"]["risk_label"] in [RiskLabel.LOW_RISK.value, RiskLabel.INCONCLUSIVE.value]
    finally:
        db.close()

def test_db_tables_exist():
    db = SessionLocal()
    try:
        count_scans = db.query(ScanRecord).count()
        count_ind = db.query(IndicatorRecord).count()
        count_commits = db.query(CommitRecord).count()
        assert count_scans >= 0
        assert count_ind >= 0
        assert count_commits >= 0
    finally:
        db.close()
