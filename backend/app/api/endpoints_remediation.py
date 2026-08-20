"""
Personal AI Cyber Digital Twin - API Endpoints: Incident Remediation Playbooks
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.remediation.playbook_engine import PlaybookEngine

router = APIRouter()

class TerminateProcessRequest(BaseModel):
    pid: int
    reason: Optional[str] = "User Triggered Remediation"

@router.post("/terminate-process")
def terminate_process_endpoint(payload: TerminateProcessRequest):
    """Executes process isolation playbook to terminate suspicious process."""
    result = PlaybookEngine.terminate_process(payload.pid, payload.reason)
    return result

@router.get("/export-forensics/{event_id}")
def export_forensics_endpoint(event_id: str):
    """Generates complete forensic investigation report for target incident ID."""
    report = PlaybookEngine.generate_forensic_report(event_id)
    if "error" in report:
        raise HTTPException(status_code=404, detail=report["error"])
    return report

class QuarantineIpRequest(BaseModel):
    ip: str

@router.post("/quarantine-ip")
def quarantine_ip_endpoint(payload: QuarantineIpRequest):
    """Executes firewall quarantine playbook to block traffic to target malicious IP."""
    result = PlaybookEngine.quarantine_ip(payload.ip)
    if not result.get("success", False):
        raise HTTPException(status_code=400, detail=result.get("message"))
    return result
