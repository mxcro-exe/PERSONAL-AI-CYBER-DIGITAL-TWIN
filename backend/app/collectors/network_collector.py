"""
Personal AI Cyber Digital Twin - Network Socket & Connection Collector
"""

import psutil
import socket
import uuid
import logging
from typing import List, Dict, Any
from datetime import datetime, timezone
from app.core.privacy import PrivacyGuard

logger = logging.getLogger("CyberTwin.Collectors.Network")

# Suspicious security ports (Command & Control, TOR, Reverse Shells)
HIGH_RISK_PORTS = {
    4444: "Metasploit Default Listener",
    1337: "Custom C2 / Reverse Shell",
    6667: "IRC C2 Botnet",
    9001: "TOR Relay Port",
    9050: "TOR SOCKS Proxy",
    3389: "RDP Exposure"
}

class NetworkCollector:
    def __init__(self):
        self._seen_connections = set()

    def collect_network_events(self) -> List[Dict[str, Any]]:
        """Scans active network socket connections and detects unusual remote IPs/ports."""
        events = []
        current_conns = set()
        
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                # We only care about ESTABLISHED or LISTEN sockets
                if conn.status not in ('ESTABLISHED', 'LISTEN'):
                    continue
                    
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                conn_key = (laddr, raddr, conn.status, conn.pid)
                current_conns.add(conn_key)
                
                if conn_key not in self._seen_connections:
                    self._seen_connections.add(conn_key)
                    
                    remote_ip = conn.raddr.ip if conn.raddr else None
                    remote_port = conn.raddr.port if conn.raddr else None
                    
                    # Ignore standard loopback connections
                    if remote_ip in ("127.0.0.1", "::1", None):
                        continue
                        
                    process_name = "unknown"
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process_name = proc.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                            
                    # MITRE ATT&CK Mapping
                    mitre_technique = "T1071 - Application Layer Protocol"
                    severity = "info"
                    risk_score = 15
                    
                    if remote_port in HIGH_RISK_PORTS:
                        severity = "high"
                        risk_score = 80
                        mitre_technique = f"T1071 / Risk Port {remote_port} ({HIGH_RISK_PORTS[remote_port]})"
                        
                    event = {
                        "id": str(uuid.uuid4()),
                        "device_id": PrivacyGuard.hash_identifier("LOCAL_HOST_DEVICE"),
                        "event_type": "network",
                        "severity": severity,
                        "risk_score": risk_score,
                        "source_component": "NetworkCollector",
                        "mitre_tactic": "TA0011 Command and Control",
                        "mitre_technique": mitre_technique,
                        "raw_payload": {
                            "pid": conn.pid,
                            "process_name": process_name,
                            "local_address": laddr,
                            "remote_address": raddr,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "status": conn.status
                        },
                        "created_at": datetime.now(timezone.utc).isoformat()
                    }
                    events.append(event)
                    
        except Exception as e:
            logger.error(f"Error gathering network sockets: {e}")
            
        self._seen_connections = current_conns
        return events
