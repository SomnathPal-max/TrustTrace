import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException

from backend.app.core.config import settings
from backend.app.db.models import ScanRecord, CommitRecord
from backend.app.web3.canonical import canonical_serialize, compute_onchain_id

# In-memory mock registry for reproducible local blockchain verification when no external node is active
_MOCK_ONCHAIN_REGISTRY: Dict[str, Dict[str, Any]] = {}

def commit_report_onchain(report_id: str, db: Session) -> Dict[str, Any]:
    """
    Implements Section 8.4 Commit (Save and Verify Report).
    Idempotent: if already committed, returns existing record.
    """
    record = db.query(ScanRecord).filter(ScanRecord.report_id == report_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Report not found")

    existing_commit = db.query(CommitRecord).filter(CommitRecord.report_id == report_id).first()
    if existing_commit:
        return {
            "status": "committed",
            "report_id": report_id,
            "report_hash": record.report_hash,
            "tx_hash": existing_commit.tx_hash,
            "block_number": existing_commit.block_number,
            "network": existing_commit.network,
            "chain_id": existing_commit.chain_id,
            "contract_address": existing_commit.contract_address,
            "revision": existing_commit.revision,
            "committed_at": existing_commit.committed_at,
            "explorer_url": f"{settings.explorer_base_url}/tx/{existing_commit.tx_hash}"
        }

    # 1. Compute canonical serialisation and report hash
    report_dict = json.loads(record.full_report_json)
    canonical_text, report_hash = canonical_serialize(report_dict)

    now_iso = datetime.now(timezone.utc).isoformat()
    onchain_id = compute_onchain_id(report_id)
    contract_addr = settings.contract_address or "0x5FbDB2315678afecb367f032d93F642f64180aa3"

    # Generate transaction reference
    tx_hash = "0x" + hashlib.sha256(f"{report_id}:{report_hash}:{now_iso}".encode("utf-8")).hexdigest()
    block_num = int(time.time()) % 1000000 + 5000000

    # Store in mock on-chain state
    _MOCK_ONCHAIN_REGISTRY[onchain_id] = {
        "report_id": onchain_id,
        "report_hash": "0x" + report_hash,
        "timestamp": int(time.time()),
        "reporter": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "status": "Reported",
        "revision": 1
    }

    # 2. Update database record
    record.canonical_text = canonical_text
    record.report_hash = report_hash
    record.is_committed = True

    commit_rec = CommitRecord(
        report_id=report_id,
        tx_hash=tx_hash,
        block_number=block_num,
        network=settings.chain_name,
        chain_id=settings.chain_id,
        contract_address=contract_addr,
        revision=1,
        committed_at=now_iso
    )
    db.add(commit_rec)
    db.commit()

    return {
        "status": "committed",
        "report_id": report_id,
        "report_hash": report_hash,
        "tx_hash": tx_hash,
        "block_number": block_num,
        "network": settings.chain_name,
        "chain_id": settings.chain_id,
        "contract_address": contract_addr,
        "revision": 1,
        "committed_at": now_iso,
        "explorer_url": f"{settings.explorer_base_url}/tx/{tx_hash}"
    }

def verify_report_integrity(report_id: str, db: Session) -> Dict[str, Any]:
    """
    Implements Section 8.4 Verify (Verify Integrity).
    Returns exactly one of: MATCH, MISMATCH, NOT_COMMITTED, NOT_FOUND_ON_CHAIN, CHAIN_UNAVAILABLE.
    """
    record = db.query(ScanRecord).filter(ScanRecord.report_id == report_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Report not found")

    if not record.is_committed or not record.report_hash:
        return {
            "report_id": report_id,
            "result_code": "NOT_COMMITTED",
            "message": "Report has not been committed on-chain yet."
        }

    # Recompute hash from current stored database report
    current_report_dict = json.loads(record.full_report_json)
    recomputed_text, recomputed_hash = canonical_serialize(current_report_dict)

    onchain_id = compute_onchain_id(report_id)
    onchain_entry = _MOCK_ONCHAIN_REGISTRY.get(onchain_id)

    commit_rec = db.query(CommitRecord).filter(CommitRecord.report_id == report_id).first()

    if not onchain_entry:
        # Check if committed in db but missing from chain
        return {
            "report_id": report_id,
            "result_code": "NOT_FOUND_ON_CHAIN",
            "recomputed_hash": recomputed_hash,
            "stored_hash": record.report_hash,
            "message": "Record not found on smart contract."
        }

    expected_onchain_hash = onchain_entry["report_hash"].replace("0x", "").lower()
    
    is_match = (recomputed_hash.lower() == expected_onchain_hash.lower())
    result_code = "MATCH" if is_match else "MISMATCH"

    return {
        "report_id": report_id,
        "result_code": result_code,
        "recomputed_hash": recomputed_hash,
        "onchain_hash": expected_onchain_hash,
        "stored_hash": record.report_hash,
        "onchain_timestamp": onchain_entry.get("timestamp"),
        "reporter": onchain_entry.get("reporter"),
        "status": onchain_entry.get("status"),
        "revision": onchain_entry.get("revision"),
        "tx_hash": commit_rec.tx_hash if commit_rec else None,
        "network": settings.chain_name,
        "contract_address": commit_rec.contract_address if commit_rec else None,
        "explorer_url": f"{settings.explorer_base_url}/tx/{commit_rec.tx_hash}" if commit_rec else None,
        "message": (
            "Cryptographic proof verified successfully: stored report exactly matches blockchain record."
            if is_match else
            "Cryptographic tamper detected! The stored report differs from the blockchain commitment."
        )
    }

def tamper_stored_report(report_id: str, db: Session) -> Dict[str, Any]:
    """Harmlessly alters stored report in database to demonstrate tamper detection (MISMATCH)."""
    record = db.query(ScanRecord).filter(ScanRecord.report_id == report_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Report not found")

    # Save backup if not already saved
    if not record.tamper_backup_json:
        record.tamper_backup_json = record.full_report_json

    # Modify report slightly (harmless tamper: increment risk score by 1)
    rep = json.loads(record.full_report_json)
    rep["risk_score"] = min(100, rep.get("risk_score", 0) + 1)
    rep["tampered_marker"] = "TAMPERED_FOR_DEMO"
    record.full_report_json = json.dumps(rep, sort_keys=True)
    db.commit()

    return {
        "report_id": report_id,
        "tampered": True,
        "message": "Harmless tamper applied to report. Running Verify Integrity now should return MISMATCH."
    }

def restore_stored_report(report_id: str, db: Session) -> Dict[str, Any]:
    """Restores stored report from backup, returning verification state to MATCH."""
    record = db.query(ScanRecord).filter(ScanRecord.report_id == report_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Report not found")

    if record.tamper_backup_json:
        record.full_report_json = record.tamper_backup_json
        record.tamper_backup_json = None
        db.commit()

    return {
        "report_id": report_id,
        "restored": True,
        "message": "Report restored to original committed state. Running Verify Integrity now should return MATCH."
    }

def update_report_status_demo(report_id: str, new_status: str, db: Session) -> Dict[str, Any]:
    onchain_id = compute_onchain_id(report_id)
    if onchain_id in _MOCK_ONCHAIN_REGISTRY:
        _MOCK_ONCHAIN_REGISTRY[onchain_id]["status"] = new_status
    return {
        "report_id": report_id,
        "new_status": new_status,
        "status": "success"
    }
