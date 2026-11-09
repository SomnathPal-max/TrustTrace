from typing import Dict, Any
from sqlalchemy.orm import Session
from fastapi import HTTPException
from backend.app.core.config import settings

def commit_report_onchain(report_id: str, db: Session) -> Dict[str, Any]:
    return {
        "status": "pending",
        "report_id": report_id,
        "message": "Web3 client placeholder. Will be fully wired in Phase 8."
    }

def verify_report_integrity(report_id: str, db: Session) -> Dict[str, Any]:
    return {
        "report_id": report_id,
        "result_code": "NOT_COMMITTED",
        "message": "Report not yet committed on-chain."
    }

def update_report_status_demo(report_id: str, new_status: str, db: Session) -> Dict[str, Any]:
    return {
        "report_id": report_id,
        "new_status": new_status,
        "status": "success"
    }

def tamper_stored_report(report_id: str, db: Session) -> Dict[str, Any]:
    return {
        "report_id": report_id,
        "tampered": True,
        "message": "Harmless modification applied in demo mode."
    }

def restore_stored_report(report_id: str, db: Session) -> Dict[str, Any]:
    return {
        "report_id": report_id,
        "restored": True,
        "message": "Report restored to original committed state."
    }
