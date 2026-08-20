"""
Personal AI Cyber Digital Twin - Removable USB & Hardware Device Collector
"""

import psutil
import uuid
import logging
from typing import List, Dict, Any
from datetime import datetime, timezone
from app.core.privacy import PrivacyGuard

logger = logging.getLogger("CyberTwin.Collectors.Device")

class DeviceCollector:
    def __init__(self):
        self._seen_drives = self._get_removable_drives()

    def _get_removable_drives(self) -> Dict[str, str]:
        drives = {}
        try:
            partitions = psutil.disk_partitions(all=True)
            for p in partitions:
                # Check for removable storage flags (USB / Flash drives)
                if 'removable' in p.opts or 'cdrom' in p.opts:
                    drives[p.device] = p.mountpoint
        except Exception as e:
            logger.debug(f"Error fetching disk partitions: {e}")
        return drives

    def collect_device_events(self) -> List[Dict[str, Any]]:
        """Monitors USB drive insertion and removal events (MITRE T1091 Replication Via Removable Media)."""
        events = []
        current_drives = self._get_removable_drives()
        
        # Check newly inserted drives
        for dev, mountpoint in current_drives.items():
            if dev not in self._seen_drives:
                event = {
                    "id": str(uuid.uuid4()),
                    "device_id": PrivacyGuard.hash_identifier("LOCAL_HOST_DEVICE"),
                    "event_type": "usb",
                    "severity": "medium",
                    "risk_score": 50,
                    "source_component": "DeviceCollector",
                    "mitre_tactic": "TA0001 Initial Access",
                    "mitre_technique": "T1091 - Replication via Removable Media",
                    "raw_payload": {
                        "action": "inserted",
                        "device": dev,
                        "mountpoint": mountpoint
                    },
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                events.append(event)
                logger.info(f"Removable media attached: {dev} at {mountpoint}")
                
        self._seen_drives = current_drives
        return events
