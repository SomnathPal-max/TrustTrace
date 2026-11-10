import pytest
import json
import uuid
from backend.app.db.session import SessionLocal, init_db
from backend.app.db.models import ScanRecord, CommitRecord
from backend.app.web3.canonical import canonical_serialize, compute_onchain_id
from backend.app.web3.client import (
    commit_report_onchain, verify_report_integrity,
    tamper_stored_report, restore_stored_report
)

def test_canonical_serialization_stability():
    # Report 1
    rep1 = {
        "report_id": "test-uuid-1234",
        "created_at": "2026-11-09T10:00:00Z",
        "risk_label": "High Risk",
        "risk_score": 85,
        "findings": [{"id": "F-01", "points": 40}, {"id": "F-02", "points": 15}]
    }
    # Report 2 with scrambled key orders
    rep2 = {
        "findings": [{"points": 40, "id": "F-01"}, {"points": 15, "id": "F-02"}],
        "risk_score": 85,
        "risk_label": "High Risk",
        "created_at": "2026-11-09T10:00:00Z",
        "report_id": "test-uuid-1234"
    }
    txt1, hash1 = canonical_serialize(rep1)
    txt2, hash2 = canonical_serialize(rep2)
    assert txt1 == txt2
    assert hash1 == hash2

    # Changing a single character must change the hash
    rep3 = dict(rep1)
    rep3["risk_score"] = 86
    _, hash3 = canonical_serialize(rep3)
    assert hash1 != hash3

def test_web3_commit_tamper_restore_cycle():
    init_db()
    db = SessionLocal()
    try:
        report_id = f"test-web3-{uuid.uuid4()}"
        sample_report = {
            "report_id": report_id,
            "created_at": "2026-11-09T12:00:00Z",
            "risk_label": "High Risk",
            "risk_score": 75,
            "input_type": "url",
            "input_display": "http://sbi-kyc-update.com"
        }
        rec = ScanRecord(
            report_id=report_id,
            created_at="2026-11-09T12:00:00Z",
            input_type="url",
            risk_label="High Risk",
            risk_score=75,
            full_report_json=json.dumps(sample_report),
            is_committed=False
        )
        db.add(rec)
        db.commit()

        # 1. Before commit: verify returns NOT_COMMITTED
        v0 = verify_report_integrity(report_id, db)
        assert v0["result_code"] == "NOT_COMMITTED"

        # 2. Commit report
        res_commit = commit_report_onchain(report_id, db)
        assert res_commit["status"] == "committed"
        assert "tx_hash" in res_commit

        # Idempotency test: commit second time must not fail or create duplicate
        res_commit2 = commit_report_onchain(report_id, db)
        assert res_commit2["tx_hash"] == res_commit["tx_hash"]

        # 3. Verify integrity -> MATCH
        v1 = verify_report_integrity(report_id, db)
        assert v1["result_code"] == "MATCH"
        assert v1["recomputed_hash"] == v1["onchain_hash"]

        # 4. Tamper stored report
        tamper_res = tamper_stored_report(report_id, db)
        assert tamper_res["tampered"] is True

        # 5. Verify integrity -> MISMATCH!
        v2 = verify_report_integrity(report_id, db)
        assert v2["result_code"] == "MISMATCH"
        assert v2["recomputed_hash"] != v2["onchain_hash"]

        # 6. Restore report
        restore_res = restore_stored_report(report_id, db)
        assert restore_res["restored"] is True

        # 7. Verify integrity -> MATCH again!
        v3 = verify_report_integrity(report_id, db)
        assert v3["result_code"] == "MATCH"
        assert v3["recomputed_hash"] == v3["onchain_hash"]

        # 8. Simulate backend restart: clear in-memory dict entirely
        from backend.app.web3.client import _MOCK_ONCHAIN_REGISTRY
        _MOCK_ONCHAIN_REGISTRY.clear()

        # After backend restart, verify MUST STILL SUCCEED and return MATCH from persistent DB!
        v4 = verify_report_integrity(report_id, db)
        assert v4["result_code"] == "MATCH"
        assert v4["recomputed_hash"] == v4["onchain_hash"]

    finally:
        db.close()
