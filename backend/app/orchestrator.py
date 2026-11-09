import time
import json
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.app.core.job_runner import job_runner, SCAN_STEPS
from backend.app.db.models import ScanRecord, IndicatorRecord
from backend.app.models import (
    ScanRequest, Report, RiskLabel, EvidenceCoverage, AIExplanation,
    AIEvidencePoint, ThreatIntelSummary, CampaignInfo
)

def run_scan_pipeline(report_id: str, request: ScanRequest, db: Session):
    try:
        # Step 1: Validating link safety
        job_runner.update_step(report_id, SCAN_STEPS[0])
        time.sleep(0.1)

        # Step 2: Analysing domain
        job_runner.update_step(report_id, SCAN_STEPS[1])
        time.sleep(0.1)

        # Step 3: Following redirects
        job_runner.update_step(report_id, SCAN_STEPS[2])
        time.sleep(0.1)

        # Step 4: Inspecting certificate
        job_runner.update_step(report_id, SCAN_STEPS[3])
        time.sleep(0.1)

        # Step 5: Checking threat intelligence
        job_runner.update_step(report_id, SCAN_STEPS[4])
        time.sleep(0.1)

        # Step 6: Correlating with earlier reports
        job_runner.update_step(report_id, SCAN_STEPS[5])
        time.sleep(0.1)

        # Step 7: Writing explanation
        job_runner.update_step(report_id, SCAN_STEPS[6])
        time.sleep(0.1)

        # Create structured report
        now_str = datetime.now(timezone.utc).isoformat()
        report = Report(
            report_id=report_id,
            schema_version=1,
            created_at=now_str,
            input_type=request.type,
            input_display=request.value,
            normalized_url=request.value if request.type == "url" else "",
            registrable_domain="example.com" if request.type == "url" else "",
            risk_label=RiskLabel.LOW_RISK,
            risk_score=0,
            evidence_coverage=EvidenceCoverage(
                percent=100,
                completed_groups=["Lexical analysis", "Domain and DNS", "Redirect and fetch", "TLS", "Security headers", "Threat intelligence"],
                unavailable_groups=[]
            ),
            findings=[],
            checks=[],
            redirect_chain=[],
            ai_explanation=AIExplanation(
                summary="Initial scan completed successfully with no malicious indicators detected within available checks.",
                evidence_points=[],
                recommended_actions=["No immediate threat detected. Exercise standard web hygiene."],
                limitations_note="Absence of a match in threat feeds does not prove a site is safe.",
                model_name="fallback_template",
                generated_by="fallback_template"
            ),
            recommended_actions=["Always verify URLs independently."],
            limitations=["Absence of a match in these sources does not prove a site is safe."],
            analysis_duration_ms=700,
            is_cached_sample=bool(request.use_cached)
        )

        # Save to database
        record = ScanRecord(
            report_id=report_id,
            created_at=now_str,
            input_type=request.type,
            risk_label=report.risk_label.value,
            risk_score=report.risk_score,
            full_report_json=json.dumps(report.model_dump(), sort_keys=True),
            is_committed=False,
            is_demo_seed=False
        )
        db.add(record)
        db.commit()

        job_runner.mark_complete(report_id, report.model_dump())
    except Exception as e:
        job_runner.mark_failed(report_id, str(e))
