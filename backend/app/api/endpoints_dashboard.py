"""
Personal AI Cyber Digital Twin - API Endpoints: Dashboard & System Health
"""

from fastapi import APIRouter
from app.digital_twin.memory_engine import MemoryEngine
from app.core.database import get_db_connection
from app.core.config import settings

router = APIRouter()

@router.get("/health")
def get_system_health():
    """Returns real-time Digital Twin Health Index and status."""
    twin_status = MemoryEngine.calculate_twin_health()
    return {
        "app_name": settings.APP_NAME,
        "version": settings.VERSION,
        "digital_twin": twin_status
    }

@router.get("/summary")
def get_dashboard_summary():
    """Returns dashboard overview counters."""
    events = MemoryEngine.get_recent_events(limit=100)
    
    severity_counts = {"info": 0, "medium": 0, "high": 0, "critical": 0}
    event_type_counts = {}
    
    for e in events:
        sev = e.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        etype = e.get("event_type", "other")
        event_type_counts[etype] = event_type_counts.get(etype, 0) + 1
        
    return {
        "total_recent_events": len(events),
        "severity_distribution": severity_counts,
        "event_type_distribution": event_type_counts,
        "twin_health": MemoryEngine.calculate_twin_health()
    }

@router.post("/reset-health")
def reset_health_baseline():
    """Resets historical risk load to restore 100% Optimal Digital Twin security health index."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE telemetry_events SET risk_score = 0 WHERE severity IN ('medium', 'high', 'critical');")
    conn.commit()
    conn.close()
    
    return {
        "status": "HEALTH_INDEX_RESET_OPTIMAL",
        "twin_health": MemoryEngine.calculate_twin_health()
    }

@router.get("/baselines")
def get_behavioral_baselines():
    """Retrieves all active Exponential Moving Average baselines from SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT feature_name, entity_id, mean_val, std_dev, sample_count, last_updated 
        FROM behavioral_baseline 
        ORDER BY last_updated DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    
    baselines = []
    for r in rows:
        baselines.append({
            "feature_name": r["feature_name"],
            "entity_id": r["entity_id"],
            "mean_val": round(r["mean_val"], 4),
            "std_dev": round(r["std_dev"], 4),
            "sample_count": r["sample_count"],
            "last_updated": r["last_updated"]
        })
    return baselines
