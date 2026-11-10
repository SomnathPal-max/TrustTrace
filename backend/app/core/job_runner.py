import asyncio
import threading
from typing import Dict, Any, Optional
from datetime import datetime, timezone

SCAN_STEPS = [
    "Validating link safety",
    "Analysing domain",
    "Checking threat intelligence",
    "Following redirects",
    "Inspecting certificate",
    "Correlating with earlier reports",
    "Writing explanation"
]

class ScanJobRunner:
    def __init__(self):
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def register_job(self, report_id: str, input_type: str, input_val: str):
        with self._lock:
            self._jobs[report_id] = {
                "report_id": report_id,
                "status": "queued",  # queued, running, complete, failed
                "progress_step": SCAN_STEPS[0],
                "step_index": 0,
                "total_steps": len(SCAN_STEPS),
                "error": None,
                "report": None,
                "created_at": datetime.now(timezone.utc).isoformat()
            }

    def update_step(self, report_id: str, step_name: str):
        with self._lock:
            if report_id in self._jobs:
                self._jobs[report_id]["status"] = "running"
                self._jobs[report_id]["progress_step"] = step_name
                if step_name in SCAN_STEPS:
                    self._jobs[report_id]["step_index"] = SCAN_STEPS.index(step_name) + 1

    def mark_complete(self, report_id: str, report: Dict[str, Any]):
        with self._lock:
            if report_id in self._jobs:
                self._jobs[report_id]["status"] = "complete"
                self._jobs[report_id]["step_index"] = len(SCAN_STEPS)
                self._jobs[report_id]["report"] = report

    def mark_failed(self, report_id: str, error_msg: str):
        with self._lock:
            if report_id in self._jobs:
                self._jobs[report_id]["status"] = "failed"
                self._jobs[report_id]["error"] = error_msg

    def get_status(self, report_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._jobs.get(report_id)

job_runner = ScanJobRunner()
