"""
Personal AI Cyber Digital Twin - Digital Twin State & Memory Store
"""

import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from app.core.database import get_db_connection
from app.core.privacy import PrivacyGuard

logger = logging.getLogger("CyberTwin.DigitalTwin.Memory")

class MemoryEngine:
    @staticmethod
    def save_event(event: Dict[str, Any]):
        """Persists a scrubbed telemetry event into SQLite data store."""
        conn = get_db_connection()
        cursor = conn.cursor()
        raw_json = json.dumps(PrivacyGuard.sanitize_dict(event.get("raw_payload", {})))
        cursor.execute("""
            INSERT INTO telemetry_events (
                id, device_id, event_type, severity, source_component,
                mitre_tactic, mitre_technique, raw_payload, risk_score, privacy_scrubbed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            event["id"], event["device_id"], event["event_type"], event["severity"],
            event["source_component"], event.get("mitre_tactic"), event.get("mitre_technique"),
            raw_json, event.get("risk_score", 0)
        ))
        conn.commit()
        conn.close()

    @staticmethod
    def get_recent_events(limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves recent telemetry events for UI dashboard streams."""
        conn = get_db_connection()
        cursor = conn.cursor()
        if severity:
            cursor.execute("""
                SELECT * FROM telemetry_events WHERE severity = ?
                ORDER BY created_at DESC LIMIT ?
            """, (severity, limit))
        else:
            cursor.execute("""
                SELECT * FROM telemetry_events ORDER BY created_at DESC LIMIT ?
            """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [{
            "id": r["id"], "device_id": r["device_id"], "event_type": r["event_type"],
            "severity": r["severity"], "source_component": r["source_component"],
            "mitre_tactic": r["mitre_tactic"], "mitre_technique": r["mitre_technique"],
            "raw_payload": json.loads(r["raw_payload"]), "risk_score": r["risk_score"],
            "created_at": r["created_at"]
        } for r in rows]

    @staticmethod
    def calculate_twin_health() -> Dict[str, Any]:
        """
        Calculates the Digital Twin Health Index (0–100%).
        Uses PEAK single-event risk weighting over last 24h, not additive sum,
        so running demos/simulations don't permanently drain health.
        """
        conn = get_db_connection()
        cursor = conn.cursor()

        # Count HIGH/CRITICAL events in last 30 minutes (active window)
        cursor.execute("""
            SELECT COUNT(*) as active_count, MAX(risk_score) as peak_risk
            FROM telemetry_events
            WHERE created_at >= datetime('now', '-30 minutes')
              AND severity IN ('high', 'critical')
        """)
        row = cursor.fetchone()
        active_count = row["active_count"] if row and row["active_count"] else 0
        peak_risk    = row["peak_risk"]    if row and row["peak_risk"]    else 0

        # Count MEDIUM events in last 1 hour
        cursor.execute("""
            SELECT COUNT(*) as med_count FROM telemetry_events
            WHERE created_at >= datetime('now', '-1 hour')
              AND severity = 'medium'
        """)
        med_row = cursor.fetchone()
        med_count = med_row["med_count"] if med_row and med_row["med_count"] else 0

        # 24h totals for sidebar display
        cursor.execute("""
            SELECT COUNT(*) as event_count FROM telemetry_events
            WHERE created_at >= datetime('now', '-1 day')
        """)
        all_row = cursor.fetchone()
        event_count = all_row["event_count"] if all_row and all_row["event_count"] else 0

        conn.close()

        # Score formula: Blend peak risk weight + active incident count penalty
        # Each active HIGH/CRITICAL window event costs 12 pts; each medium 3 pts; peak_risk / 100 × 30
        penalty = min(100, (active_count * 12) + (med_count * 3) + int(peak_risk * 0.30))
        health_score = max(0, 100 - penalty)

        if health_score >= 90:
            status = "Optimal"
        elif health_score >= 75:
            status = "Elevated Caution"
        elif health_score >= 50:
            status = "Warning"
        else:
            status = "Critical Risk"

        return {
            "health_score": health_score,
            "status": status,
            "active_risk_load": peak_risk,
            "active_high_events": active_count,
            "events_24h": event_count,
            "last_evaluated": datetime.now(timezone.utc).isoformat()
        }

    @staticmethod
    def get_event_stats() -> Dict[str, Any]:
        """Returns aggregated stats for dashboard summary cards."""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) as critical_count,
                SUM(CASE WHEN severity='high'     THEN 1 ELSE 0 END) as high_count,
                SUM(CASE WHEN severity='medium'   THEN 1 ELSE 0 END) as medium_count,
                SUM(CASE WHEN event_type='process' THEN 1 ELSE 0 END) as process_count,
                SUM(CASE WHEN event_type='network' THEN 1 ELSE 0 END) as network_count,
                SUM(CASE WHEN event_type='clipboard' THEN 1 ELSE 0 END) as clipboard_count,
                SUM(CASE WHEN event_type='usb'     THEN 1 ELSE 0 END) as usb_count
            FROM telemetry_events
            WHERE created_at >= datetime('now', '-1 day')
        """)
        r = cursor.fetchone()
        conn.close()
        return dict(r) if r else {}
