"""
Personal AI Cyber Digital Twin - Core System Configuration
"""

import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "cyber_twin.db"

class SystemSettings(BaseModel):
    APP_NAME: str = "Personal AI Cyber Digital Twin"
    VERSION: str = "1.0.0-PROD"
    DEBUG: bool = False
    
    # Storage & Database
    DATABASE_PATH: str = str(DB_PATH)
    
    # Telemetry Polling Intervals (Seconds)
    PROCESS_POLL_INTERVAL: float = 2.0
    NETWORK_POLL_INTERVAL: float = 3.0
    CLIPBOARD_POLL_INTERVAL: float = 1.0
    DEVICE_POLL_INTERVAL: float = 4.0
    
    # Behavioral Baseline Parameters
    BASELINE_ALPHA: float = 0.1  # Exponential moving average decay
    ANOMALY_Z_THRESHOLD: float = 3.0 # Standard deviations for anomaly flag
    
    # Privacy Guard
    ENABLE_DIFFERENTIAL_PRIVACY: bool = True
    PRIVACY_EPSILON: float = 0.5
    SCRUB_SENSITIVE_PATTERNS: bool = True
    
    # Server API & WebSocket
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    CORS_ORIGINS: list[str] = ["*"]

settings = SystemSettings()
