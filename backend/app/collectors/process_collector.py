"""
Personal AI Cyber Digital Twin - Process Execution Collector & T1059 Detection Engine
"""

import psutil
import os
import hashlib
import logging
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from app.core.privacy import PrivacyGuard

logger = logging.getLogger("CyberTwin.Collectors.Process")

# Known high-risk scripting engines (MITRE ATT&CK T1059)
SUSPICIOUS_EXECUTABLES = {
    "powershell.exe": "T1059.001 - PowerShell",
    "cmd.exe": "T1059.003 - Windows Command Shell",
    "wscript.exe": "T1059.005 - Visual Basic",
    "cscript.exe": "T1059.005 - Visual Basic",
    "mshta.exe": "T1218.005 - Mshta Execution",
    "regsvr32.exe": "T1218.010 - Regsvr32 Execution",
    "bitsadmin.exe": "T1197 - BITS Jobs",
    "certutil.exe": "T1105 - Ingress Tool Transfer"
}

class ProcessCollector:
    def __init__(self):
        # Initialize with currently running processes so we only capture new launches
        self._seen_pids = set()
        self._last_write_bytes = {}
        for proc in psutil.process_iter(['pid', 'io_counters']):
            try:
                pid = proc.info['pid']
                self._seen_pids.add(pid)
                io = proc.info['io_counters']
                if io:
                    self._last_write_bytes[pid] = io.write_bytes
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def calculate_file_hash(self, filepath: str) -> Optional[str]:
        """Calculates SHA-256 hash of process executable if available."""
        try:
            if os.path.exists(filepath) and os.access(filepath, os.R_OK):
                hasher = hashlib.sha256()
                with open(filepath, 'rb') as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        hasher.update(chunk)
                return hasher.hexdigest()
        except Exception as e:
            logger.debug(f"Could not hash process file {filepath}: {e}")
        return None

    def collect_new_processes(self) -> List[Dict[str, Any]]:
        """Polls current OS processes, identifies new executions, and monitors CPU/IO spikes."""
        events = []
        current_pids = set()
        
        # 1. Check for newly spawned processes
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid', 'create_time', 'username', 'cpu_percent', 'io_counters']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                current_pids.add(pid)
                pname = pinfo['name']
                
                # Check for resource anomalies on all non-system processes
                if pname and not any(x in pname.lower() for x in ('system', 'idle', 'svchost', 'explorer', 'registry', 'secure system', 'csrss', 'lsass', 'wininit', 'services')):
                    # Check CPU utilization
                    cpu = pinfo['cpu_percent'] or 0.0
                    if cpu > 85.0:
                        event = {
                            "id": str(uuid.uuid4()),
                            "device_id": PrivacyGuard.hash_identifier("LOCAL_HOST_DEVICE"),
                            "event_type": "process",
                            "severity": "high",
                            "risk_score": 75,
                            "source_component": "ProcessCollector",
                            "mitre_tactic": "TA0040 Impact",
                            "mitre_technique": "T1496 - Resource Hijacking (CPU Spike)",
                            "raw_payload": {
                                "pid": pid,
                                "process_name": pname,
                                "cpu_utilization": f"{cpu}%",
                                "description": f"Process '{pname}' is exhibiting anomalous CPU utilization ({cpu}%)."
                            },
                            "created_at": datetime.now(timezone.utc).isoformat()
                        }
                        events.append(event)
                        logger.warning(f"Anomalous CPU usage: {pname} (PID {pid}) using {cpu}% CPU")

                    # Check Disk Write spikes
                    io = pinfo['io_counters']
                    if io:
                        write_bytes = io.write_bytes
                        last_write = self._last_write_bytes.get(pid, 0)
                        self._last_write_bytes[pid] = write_bytes
                        
                        if last_write > 0:
                            delta_write = write_bytes - last_write
                            # If writing more than 15MB in 2 seconds, raise Ransomware flag
                            if delta_write > 15 * 1024 * 1024:
                                event = {
                                    "id": str(uuid.uuid4()),
                                    "device_id": PrivacyGuard.hash_identifier("LOCAL_HOST_DEVICE"),
                                    "event_type": "process",
                                    "severity": "high",
                                    "risk_score": 80,
                                    "source_component": "ProcessCollector",
                                    "mitre_tactic": "TA0040 Impact",
                                    "mitre_technique": "T1486 - Ransomware Write Spike",
                                    "raw_payload": {
                                        "pid": pid,
                                        "process_name": pname,
                                        "write_speed": f"{delta_write / (1024*1024):.2f} MB/2s",
                                        "description": f"Process '{pname}' is writing data at an anomalous rate ({delta_write / (1024*1024):.2f} MB/2s)."
                                    },
                                    "created_at": datetime.now(timezone.utc).isoformat()
                                }
                                events.append(event)
                                logger.warning(f"Anomalous Disk Write: {pname} (PID {pid}) wrote {delta_write / (1024*1024):.2f} MB")
                
                # Check if this PID is newly spawned since last poll
                if pid not in self._seen_pids:
                    self._seen_pids.add(pid)
                    
                    exe_name = (pinfo['name'] or "").lower()
                    cmdline_list = pinfo['cmdline'] or []
                    raw_cmdline = " ".join(cmdline_list)
                    sanitized_cmdline = PrivacyGuard.sanitize_text(raw_cmdline)
                    
                    # Parent process resolution
                    ppid = pinfo['ppid']
                    parent_name = "unknown"
                    try:
                        parent_proc = psutil.Process(ppid)
                        parent_name = parent_proc.name()
                    except Exception:
                        pass
                        
                    # MITRE Technique Identification
                    mitre_technique = SUSPICIOUS_EXECUTABLES.get(exe_name, None)
                    mitre_tactic = "TA0002 Execution" if mitre_technique else "TA0007 Discovery"
                    
                    # Risk evaluation
                    severity = "info"
                    risk_score = 10
                    
                    if mitre_technique:
                        severity = "medium"
                        risk_score = 55
                        # Check for encoded powershell commands or hidden windows
                        if "-enc" in sanitized_cmdline.lower() or "-encodedcommand" in sanitized_cmdline.lower() or "-w hidden" in sanitized_cmdline.lower():
                            severity = "high"
                            risk_score = 85
                            
                    sha256 = self.calculate_file_hash(pinfo['exe']) if pinfo['exe'] else None
                    
                    event = {
                        "id": str(uuid.uuid4()),
                        "device_id": PrivacyGuard.hash_identifier("LOCAL_HOST_DEVICE"),
                        "event_type": "process",
                        "severity": severity,
                        "risk_score": risk_score,
                        "source_component": "ProcessCollector",
                        "mitre_tactic": mitre_tactic,
                        "mitre_technique": mitre_technique,
                        "raw_payload": {
                            "pid": pid,
                            "ppid": ppid,
                            "parent_name": parent_name,
                            "process_name": pinfo['name'],
                            "executable_path": pinfo['exe'],
                            "cmdline": sanitized_cmdline,
                            "username": pinfo['username'],
                            "sha256": sha256
                        },
                        "created_at": datetime.now(timezone.utc).isoformat()
                    }
                    events.append(event)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        # Clean up exited PIDs from our trackers
        self._seen_pids = current_pids
        self._last_write_bytes = {pid: bytes for pid, bytes in self._last_write_bytes.items() if pid in current_pids}
        return events
