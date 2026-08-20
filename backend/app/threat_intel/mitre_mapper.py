"""
Personal AI Cyber Digital Twin - MITRE ATT&CK Taxonomy Engine
"""

from typing import Dict, Any, Optional

MITRE_ATTACK_MATRIX = {
    "T1059": {
        "tactic": "TA0002 Execution",
        "name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "url": "https://attack.mitre.org/techniques/T1059/"
    },
    "T1071": {
        "tactic": "TA0011 Command and Control",
        "name": "Application Layer Protocol",
        "description": "Adversaries may communicate using application layer protocols to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1071/"
    },
    "T1115": {
        "tactic": "TA0009 Collection",
        "name": "Clipboard Data",
        "description": "Adversaries may collect data stored in the OS clipboard to extract passwords, keys, or sensitive text.",
        "url": "https://attack.mitre.org/techniques/T1115/"
    },
    "T1091": {
        "tactic": "TA0001 Initial Access",
        "name": "Replication via Removable Media",
        "description": "Adversaries may insert malicious payloads into removable USB media to infect target systems.",
        "url": "https://attack.mitre.org/techniques/T1091/"
    },
    "T1566": {
        "tactic": "TA0001 Initial Access",
        "name": "Phishing",
        "description": "Adversaries may send spear-phishing messages with malicious attachments or links to gain initial access.",
        "url": "https://attack.mitre.org/techniques/T1566/"
    }
}

class MitreMapper:
    @staticmethod
    def get_technique_details(technique_id: str) -> Optional[Dict[str, Any]]:
        code = technique_id.split(" ")[0].split(".")[0]
        return MITRE_ATTACK_MATRIX.get(code, None)

    @staticmethod
    def map_event_to_mitre(event_type: str, raw_payload: Dict[str, Any]) -> Dict[str, str]:
        if event_type == "process":
            cmd = raw_payload.get("cmdline", "").lower()
            if "powershell" in cmd or "cmd.exe" in cmd:
                return {
                    "tactic": "TA0002 Execution",
                    "technique": "T1059.001 - PowerShell Execution"
                }
        elif event_type == "network":
            return {
                "tactic": "TA0011 Command and Control",
                "technique": "T1071 - Application Layer Protocol"
            }
        elif event_type == "clipboard":
            return {
                "tactic": "TA0009 Collection",
                "technique": "T1115 - Clipboard Data Harvest"
            }
        elif event_type == "usb":
            return {
                "tactic": "TA0001 Initial Access",
                "technique": "T1091 - Removable Media Insertion"
            }
            
        return {
            "tactic": "TA0007 Discovery",
            "technique": "T1082 - System Information Discovery"
        }
