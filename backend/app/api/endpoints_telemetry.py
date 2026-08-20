"""
Personal AI Cyber Digital Twin - API Endpoints: Telemetry & Events Stream
"""

from fastapi import APIRouter, Query
from typing import Optional, List
from app.digital_twin.memory_engine import MemoryEngine
from app.threat_intel.phishing_detector import PhishingDetector

router = APIRouter()

@router.get("/events")
def get_telemetry_events(
    limit: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = Query(default=None)
):
    """Retrieves recorded OS system telemetry events."""
    return MemoryEngine.get_recent_events(limit=limit, severity=severity)

@router.post("/analyze-url")
def analyze_url_endpoint(payload: dict):
    """Evaluates suspicious URLs for phishing risk and typosquatting."""
    target_url = payload.get("url", "")
    return PhishingDetector.analyze_url(target_url)
