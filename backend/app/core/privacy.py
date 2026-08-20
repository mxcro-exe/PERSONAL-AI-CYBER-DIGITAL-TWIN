"""
Personal AI Cyber Digital Twin - Privacy Guard & Differential Privacy Subsystem
"""

import re
import hashlib
import numpy as np
import logging
from typing import Dict, Any
from app.core.config import settings

logger = logging.getLogger("CyberTwin.Privacy")

# Sensitive Data Scrubbing Regular Expressions
SENSITIVE_PATTERNS = [
    # Passwords & API Tokens
    (r'(?i)(api[_-]?key|secret|password|passwd|auth[_-]?token|bearer)\s*[:=]\s*["\']?([^"\'\s]{6,})["\']?', r'\1: [REDACTED_SECRET]'),
    # Credit Card Numbers (Luhn-candidate digits)
    (r'\b(?:\d[ -]*?){13,16}\b', '[REDACTED_CARD_NUMBER]'),
    # Social Security Numbers (US SSN)
    (r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED_SSN]'),
    # Private Keys
    (r'-----BEGIN (?:RSA |EC |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |PGP )?PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]'),
    # Crypto Wallet Addresses (Bitcoin, Ethereum)
    (r'\b(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b', '[REDACTED_CRYPTO_ADDRESS]')
]

class PrivacyGuard:
    @staticmethod
    def sanitize_text(text: str) -> str:
        """Scrubs sensitive credentials, tokens, and PII from raw strings."""
        if not text or not settings.SCRUB_SENSITIVE_PATTERNS:
            return text
            
        sanitized = text
        for pattern, replacement in SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, replacement, sanitized)
            
        return sanitized

    @staticmethod
    def sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitizes dictionary structures."""
        clean_dict = {}
        for key, value in data.items():
            if isinstance(value, str):
                clean_dict[key] = PrivacyGuard.sanitize_text(value)
            elif isinstance(value, dict):
                clean_dict[key] = PrivacyGuard.sanitize_dict(value)
            elif isinstance(value, list):
                clean_dict[key] = [
                    PrivacyGuard.sanitize_text(v) if isinstance(v, str) else v 
                    for v in value
                ]
            else:
                clean_dict[key] = value
        return clean_dict

    @staticmethod
    def add_laplace_noise(val: float, sensitivity: float = 1.0, epsilon: float = None) -> float:
        """Adds Laplace noise for epsilon-differential privacy on statistical metrics."""
        if not settings.ENABLE_DIFFERENTIAL_PRIVACY:
            return val
            
        eps = epsilon if epsilon is not None else settings.PRIVACY_EPSILON
        scale = sensitivity / eps
        noise = np.random.laplace(0, scale)
        return float(val + noise)

    @staticmethod
    def hash_identifier(identifier: str) -> str:
        """One-way SHA-256 salted hash for usernames, emails, or hardware IDs."""
        salt = "CyberTwin_Salt_2026_v1"
        return hashlib.sha256((identifier + salt).encode('utf-8')).hexdigest()
