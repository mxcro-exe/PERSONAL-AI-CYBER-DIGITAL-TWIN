"""
Personal AI Cyber Digital Twin - Database Engine & Normalized Schemas
"""

import sqlite3
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from app.core.config import settings

logger = logging.getLogger("CyberTwin.Database")

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.DATABASE_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for high concurrency read/write
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn

def init_db():
    """Initializes normalized database tables, indexes, and initial baselines."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Telemetry Events (Time-Series Local Engine)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS telemetry_events (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        event_type TEXT NOT NULL, -- 'process', 'network', 'clipboard', 'usb', 'phishing'
        severity TEXT NOT NULL,   -- 'info', 'low', 'medium', 'high', 'critical'
        source_component TEXT NOT NULL,
        mitre_tactic TEXT,
        mitre_technique TEXT,
        raw_payload TEXT NOT NULL, -- JSON string (Scrubbed)
        risk_score INTEGER DEFAULT 0,
        privacy_scrubbed INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # Indexes for hyper-fast querying
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_created_at ON telemetry_events(created_at DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_type_sev ON telemetry_events(event_type, severity);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_mitre ON telemetry_events(mitre_technique);")
    
    # 2. Behavioral Baseline (Digital Twin Memory Model)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS behavioral_baseline (
        id TEXT PRIMARY KEY,
        feature_name TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        mean_val REAL NOT NULL DEFAULT 0.0,
        std_dev REAL NOT NULL DEFAULT 1.0,
        sample_count INTEGER NOT NULL DEFAULT 0,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(feature_name, entity_id)
    );
    """)
    
    # 3. Incidents & Forensics Store
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
        status TEXT NOT NULL DEFAULT 'open', -- 'open', 'investigating', 'remediated', 'false_positive'
        mitre_mappings TEXT NOT NULL, -- JSON List
        xai_explanation TEXT NOT NULL, -- JSON Analysis
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP
    );
    """)
    
    # 4. Threat Intel Cache (Hashes, Domain Reputation)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_intel_cache (
        indicator TEXT PRIMARY KEY, -- Hash, IP, or Domain
        indicator_type TEXT NOT NULL, -- 'sha256', 'ip', 'domain'
        reputation TEXT NOT NULL, -- 'clean', 'suspicious', 'malicious'
        threat_actor TEXT,
        description TEXT,
        cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    conn.commit()
    conn.close()
    logger.info("Database schema initialized successfully with WAL mode enabled.")

if __name__ == "__main__":
    init_db()
