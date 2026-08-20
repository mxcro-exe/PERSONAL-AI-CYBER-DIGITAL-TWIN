"""
Personal AI Cyber Digital Twin - Multi-Agent SOC Suite & Explainable AI (XAI)
"""

import uuid
import json
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone
from app.threat_intel.mitre_mapper import MitreMapper

logger = logging.getLogger("CyberTwin.AgenticAI.SOC")

class MultiAgentSOCSuite:
    """
    Coordinates multi-agent security triage:
    1. SOC Analyst Agent: Triage & Correlation
    2. Threat Hunter Agent: MITRE & IOC Deep-Dive
    3. Forensic Agent: Root Cause & Process Tree Reconstruction
    4. XAI Explainer Agent: Human-Readable Rationale Generation
    """
    
    @classmethod
    def analyze_incident(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        raw = event.get("raw_payload", {})
        event_type = event.get("event_type", "unknown")
        severity = event.get("severity", "info")
        risk_score = event.get("risk_score", 0)
        
        # 1. SOC Analyst Agent Assessment
        soc_assessment = f"SOC Analyst evaluated {event_type.upper()} event with baseline risk score of {risk_score}/100."
        
        # 2. Threat Hunter Agent
        mitre_info = MitreMapper.map_event_to_mitre(event_type, raw)
        technique_details = MitreMapper.get_technique_details(mitre_info["technique"])
        
        threat_hunter_findings = [
            f"Mapped to MITRE ATT&CK Tactic: {mitre_info['tactic']}",
            f"Technique ID: {mitre_info['technique']}"
        ]
        if technique_details:
            threat_hunter_findings.append(f"Description: {technique_details['description']}")
            
        # 3. Forensic Agent Root Cause Graph
        forensic_trace = []
        if event_type == "process":
            proc_name = raw.get("process_name", "Unknown")
            parent_name = raw.get("parent_name", "Unknown")
            cmd = raw.get("cmdline", "")
            forensic_trace = [
                f"Execution Chain: [Parent: {parent_name}] ---> [Process: {proc_name} (PID {raw.get('pid')})]",
                f"Command Line Arguments: '{cmd}'",
                f"Executable SHA-256 Hash: {raw.get('sha256') or 'Unavailable'}"
            ]
        elif event_type == "network":
            forensic_trace = [
                f"Socket State: {raw.get('status')}",
                f"Local Endpoint: {raw.get('local_address')} <---> Remote Endpoint: {raw.get('remote_address')}",
                f"Process Owner: {raw.get('process_name')} (PID {raw.get('pid')})"
            ]
        else:
            forensic_trace = [f"Event metadata: {json.dumps(raw)}"]
            
        # 4. XAI Explainer Agent Rationale Generation
        xai_explanation = {
            "summary": f"Detected potential security anomaly in {event_type} telemetry.",
            "decision_factors": [
                {"factor": "Event Severity Level", "weight": 0.35, "val": severity},
                {"factor": "MITRE Technique Mapping", "weight": 0.40, "val": mitre_info['technique']},
                {"factor": "Behavioral Anomaly Drift", "weight": 0.25, "val": f"Risk Score {risk_score}"}
            ],
            "human_readable_rationale": (
                f"The Digital Twin security agent detected execution of '{raw.get('process_name', event_type)}' "
                f"which matches known attack patterns categorized under {mitre_info['technique']}. "
                f"Risk score has been elevated to {risk_score}."
            ),
            "recommended_playbooks": [
                "Isolate Process / Terminate Connection",
                "Quarantine File Payload",
                "Perform Full Endpoint Memory Scan",
                "Mark as Whitelisted / False Positive"
            ]
        }
        
        return {
            "incident_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "soc_agent": soc_assessment,
            "threat_hunter_agent": threat_hunter_findings,
            "forensic_agent": forensic_trace,
            "xai_explainer": xai_explanation
        }
