from typing import Dict, Any, List
from sqlalchemy.orm import Session
from fastapi import HTTPException

def get_related_reports_for(report_id: str, db: Session) -> Dict[str, Any]:
    return {
        "report_id": report_id,
        "related_reports": [],
        "cluster_size": 0,
        "first_seen": None,
        "matched_indicators": []
    }
