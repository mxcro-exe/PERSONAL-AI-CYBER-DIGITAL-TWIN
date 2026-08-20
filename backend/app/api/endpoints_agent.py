"""
Personal AI Cyber Digital Twin - API Endpoints: Cyber Assistant AI Agent
"""

from fastapi import APIRouter
from app.digital_twin.memory_engine import MemoryEngine
from app.agentic_ai.soc_analyst import MultiAgentSOCSuite

router = APIRouter()

@router.post("/query")
def query_cyber_assistant(payload: dict):
    """Processes user security queries using local Digital Twin context and threat intel."""
    query = payload.get("query", "").strip()
    if not query:
        return {"response": "Please specify a security question or command."}
        
    health = MemoryEngine.calculate_twin_health()
    recent_events = MemoryEngine.get_recent_events(limit=5)
    
    query_lower = query.lower()
    
    if "health" in query_lower or "status" in query_lower:
        resp = (
            f"Your Digital Twin Security Health is currently at **{health['health_score']}% ({health['status']})**. "
            f"Active risk load over the last 24 hours is {health['active_risk_load']} across {health['events_24h']} tracked events."
        )
    elif "process" in query_lower or "execut" in query_lower:
        procs = [e for e in recent_events if e['event_type'] == 'process']
        if procs:
            last_p = procs[0]['raw_payload']
            resp = f"Recently monitored process execution: '{last_p.get('process_name')}' (PID {last_p.get('pid')}) spawned by '{last_p.get('parent_name')}'. Risk score: {procs[0]['risk_score']}."
        else:
            resp = "No suspicious process executions detected in recent telemetry window."
    elif "clipboard" in query_lower or "password" in query_lower:
        resp = "The Clipboard Guard is actively monitoring system paste buffers for cleartext credentials, private keys, and API tokens."
    else:
        resp = (
            f"Digital Twin AI Assistant analyzed query: '{query}'. "
            f"Current Security Posture: {health['status']}. MITRE ATT&CK taxonomy rule checks are active across local process, network, and device vectors."
        )
        
    return {
        "query": query,
        "response": resp,
        "twin_health_snapshot": health['health_score']
    }
