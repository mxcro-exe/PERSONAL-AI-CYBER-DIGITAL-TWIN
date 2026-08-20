"""
Personal AI Cyber Digital Twin - Clipboard Security Collector & Data Loss Guard
"""

import pyperclip
import uuid
import logging
import re
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from app.core.privacy import PrivacyGuard, SENSITIVE_PATTERNS

logger = logging.getLogger("CyberTwin.Collectors.Clipboard")

class ClipboardCollector:
    def __init__(self):
        self._last_clip_hash = None

    def collect_clipboard_events(self) -> List[Dict[str, Any]]:
        """Monitors OS system clipboard for sensitive data exposure or unauthorized changes."""
        events = []
        try:
            current_clip = pyperclip.paste()
            if not current_clip or len(current_clip.strip()) == 0:
                return events
                
            clip_hash = PrivacyGuard.hash_identifier(current_clip)
            if clip_hash != self._last_clip_hash:
                self._last_clip_hash = clip_hash
                
                sanitized = PrivacyGuard.sanitize_text(current_clip)
                is_sensitive = sanitized != current_clip
                
                severity = "info"
                risk_score = 5
                mitre_tactic = None
                mitre_technique = None
                detected_type = "Cleartext Clipboard Copy"
                
                if is_sensitive:
                    severity = "medium"
                    risk_score = 60
                    mitre_tactic = "TA0009 Collection"
                    mitre_technique = "T1115 - Clipboard Data"
                    
                    # Determine which pattern matched to report it
                    for pattern, replacement in SENSITIVE_PATTERNS:
                        if re.search(pattern, current_clip):
                            clean_desc = replacement.replace('[', '').replace(']', '').replace('REDACTED_', '').replace('_', ' ').title()
                            detected_type = f"Sensitive {clean_desc}"
                            break
                            
                event = {
                    "id": str(uuid.uuid4()),
                    "device_id": PrivacyGuard.hash_identifier("LOCAL_HOST_DEVICE"),
                    "event_type": "clipboard",
                    "severity": severity,
                    "risk_score": risk_score,
                    "source_component": "ClipboardCollector",
                    "mitre_tactic": mitre_tactic,
                    "mitre_technique": mitre_technique,
                    "raw_payload": {
                        "length": len(current_clip),
                        "preview": sanitized[:60] + "..." if len(sanitized) > 60 else sanitized,
                        "detected_protection": detected_type
                    },
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                events.append(event)
                
                if is_sensitive:
                    logger.warning(f"Sensitive clipboard payload detected! Sanitized preview: {sanitized[:30]}")
                else:
                    logger.info(f"Clipboard content monitored: {sanitized[:30]}")
                    
        except Exception as e:
            logger.debug(f"Clipboard read exception (non-critical): {e}")
            
        return events
