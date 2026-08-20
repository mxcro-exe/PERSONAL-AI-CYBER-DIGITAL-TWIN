"""
Personal AI Cyber Digital Twin - API Endpoints: Incidents, Forensics & XAI
"""

from fastapi import APIRouter, HTTPException
from app.digital_twin.memory_engine import MemoryEngine
from app.agentic_ai.soc_analyst import MultiAgentSOCSuite

router = APIRouter()

@router.get("/incidents")
def list_incidents():
    """Generates real-time incident triage list from high/critical events."""
    events = MemoryEngine.get_recent_events(limit=50)
    incidents = []
    
    for e in events:
        if e.get("severity") in ("medium", "high", "critical"):
            analysis = MultiAgentSOCSuite.analyze_incident(e)
            incidents.append({
                "id": analysis["incident_id"],
                "event_id": e["id"],
                "event_type": e["event_type"],
                "severity": e["severity"],
                "risk_score": e["risk_score"],
                "mitre_technique": e.get("mitre_technique", "Unknown"),
                "soc_analysis": analysis
            })
            
    return incidents

@router.post("/evaluate-event/{event_id}")
def evaluate_single_event(event_id: str):
    """Triggers deep-dive multi-agent XAI evaluation for a single event ID."""
    events = MemoryEngine.get_recent_events(limit=200)
    target = next((e for e in events if e["id"] == event_id), None)
    
    if not target:
        raise HTTPException(status_code=404, detail="Event ID not found.")
        
    return MultiAgentSOCSuite.analyze_incident(target)
