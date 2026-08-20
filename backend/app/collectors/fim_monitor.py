"""
Personal AI Cyber Digital Twin - Host File Integrity Monitor (FIM) & Canary Files
"""

import os
import hashlib
import uuid
import logging
import psutil
from typing import Dict, Any, List
from datetime import datetime, timezone
from app.core.privacy import PrivacyGuard

logger = logging.getLogger("CyberTwin.Collectors.FIM")

CANARY_FILES = {
    "passwords_vault.txt": "Site Passwords:\nfacebook.com: admin123\nbankofamerica.com: userPass!1\n",
    "financial_ledger.csv": "Transaction_ID,Amount,Currency,Vendor\nTXN10029,4850.00,USD,Apex_Threat_Intel\nTXN10030,12850.00,USD,DarkWeb_Canary\n"
}

class FileIntegrityMonitor:
    def __init__(self):
        # Setup canary folder under data directory
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.canary_dir = os.path.join(base_dir, "data", "canaries")
        os.makedirs(self.canary_dir, exist_ok=True)
        
        self.file_hashes: Dict[str, str] = {}
        self.initialize_canary_files()

    def calculate_hash(self, filepath: str) -> str:
        """Calculates SHA-256 hash of a file."""
        if not os.path.exists(filepath):
            return "DELETED"
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Error hashing file {filepath}: {e}")
            return "ERROR"

    def initialize_canary_files(self):
        """Creates benign canary files and records their initial hashes."""
        for filename, content in CANARY_FILES.items():
            filepath = os.path.join(self.canary_dir, filename)
            # Create file if it doesn't exist
            if not os.path.exists(filepath):
                try:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(content)
                except Exception as e:
                    logger.error(f"Could not create canary file {filepath}: {e}")
            
            # Store initial hash
            self.file_hashes[filename] = self.calculate_hash(filepath)
        logger.info(f"FIM initialized. Monitoring canary files in: {self.canary_dir}")

    def detect_compromise_and_auto_remediate(self) -> List[Dict[str, Any]]:
        """Scans canary files for modifications and terminates the suspect process."""
        events = []
        
        for filename in CANARY_FILES.keys():
            filepath = os.path.join(self.canary_dir, filename)
            current_hash = self.calculate_hash(filepath)
            original_hash = self.file_hashes.get(filename)
            
            if current_hash != original_hash:
                logger.warning(f"[FIM ALERT] Canary file compromised! {filename} changed from {original_hash[:10]} to {current_hash[:10]}")
                
                # Heuristically find the suspect process (most recently launched user python/powershell/cmd/exe process)
                suspect_pid = None
                suspect_name = "Unknown Process"
                suspect_cmdline = "N/A"
                
                try:
                    # Sort running processes by create time to find most recent ones
                    procs = []
                    for p in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline']):
                        try:
                            # Filter out system processes
                            pname = p.info['name'].lower()
                            if pname not in ('system', 'idle', 'svchost.exe', 'lsass.exe', 'explorer.exe'):
                                procs.append(p.info)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    procs.sort(key=lambda x: x['create_time'], reverse=True)
                    if procs:
                        # Top process is the most recently created process
                        newest = procs[0]
                        suspect_pid = newest['pid']
                        suspect_name = newest['name']
                        suspect_cmdline = " ".join(newest['cmdline'] or [])
                except Exception as e:
                    logger.error(f"Error querying process tree for FIM: {e}")
                
                # Auto-remediation (kill the suspect process to stop ransomware encryption)
                killed_status = "Auto-Remediation Skipped (Suspect unresolved)"
                if suspect_pid and suspect_pid != os.getpid():
                    try:
                        proc_to_kill = psutil.Process(suspect_pid)
                        proc_to_kill.terminate()
                        killed_status = f"Auto-Remediated: Terminated PID {suspect_pid} ({suspect_name}) to prevent ransomware propagation"
                        logger.critical(f"QUARANTINE EXECUTED: Terminated PID {suspect_pid} for modifying canary '{filename}'!")
                    except Exception as e:
                        killed_status = f"Remediation Failed: {e}"
                        
                event = {
                    "id": str(uuid.uuid4()),
                    "device_id": PrivacyGuard.hash_identifier("LOCAL_HOST_DEVICE"),
                    "event_type": "usb" if "usb" in filename else "process", # Mock categorise or custom
                    "severity": "critical",
                    "risk_score": 98,
                    "source_component": "FIMMonitor",
                    "mitre_tactic": "TA0040 Impact",
                    "mitre_technique": "T1486 - Data Encrypted for Impact (Canary File Modified)",
                    "raw_payload": {
                        "action": "canary_modified" if current_hash != "DELETED" else "canary_deleted",
                        "filepath": filepath,
                        "filename": filename,
                        "suspect_process": suspect_name,
                        "suspect_pid": suspect_pid,
                        "suspect_cmdline": suspect_cmdline,
                        "action_taken": killed_status
                    },
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                events.append(event)
                
                # Restore canary file contents so it doesn't loop fire
                try:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(CANARY_FILES[filename])
                    self.file_hashes[filename] = self.calculate_hash(filepath)
                    logger.info(f"Canary file '{filename}' restored to baseline state.")
                except Exception as e:
                    logger.error(f"Could not restore canary {filename}: {e}")
                    
        return events
