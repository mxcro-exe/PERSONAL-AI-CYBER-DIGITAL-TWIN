"""
Personal AI Cyber Digital Twin - Phishing & URL Maliciousness Detection Engine (With ONNX ML Classifier)
"""

import re
import math
import urllib.parse
import logging
from typing import Dict, Any
from app.threat_intel.onnx_phishing_model import ONNXPhishingClassifier

logger = logging.getLogger("CyberTwin.ThreatIntel.Phishing")

SUSPICIOUS_TLDS = {".xyz", ".top", ".work", ".click", ".link", ".gq", ".ml", ".cf", ".fit", ".buzz"}
TARGET_BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "bankofamerica", "wellsfargo", "binance", "coinbase"]

class PhishingDetector:
    @staticmethod
    def calculate_url_entropy(url: str) -> float:
        """Calculates Shannon Entropy of URL string to identify obfuscated / random domain names."""
        if not url:
            return 0.0
        prob = [float(url.count(c)) / len(url) for c in set(url)]
        return -sum([p * math.log2(p) for p in prob])

    @classmethod
    def analyze_url(cls, url: str) -> Dict[str, Any]:
        """Analyzes a target URL for phishing risk using heuristic checks and local ONNX ML predictions."""
        risk_score = 0
        reasons = []
        
        is_ip_address = False
        is_suspicious_tld = False
        is_brand_typosquat = False
        entropy = 0.0
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower() if parsed.netloc else parsed.path.lower()
            
            # Check 1: IP Address in Hostname
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                is_ip_address = True
                risk_score += 40
                reasons.append("Raw IP address used as URL host instead of domain name.")
                
            # Check 2: Subdomains / Hyphens
            subdomain_count = domain.count(".")
            if subdomain_count > 3:
                risk_score += 25
                reasons.append(f"Excessive subdomains detected ({subdomain_count} levels).")
                
            if domain.count("-") > 2:
                risk_score += 15
                reasons.append("High frequency of hyphens in domain name.")
                
            # Check 3: Suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    is_suspicious_tld = True
                    risk_score += 30
                    reasons.append(f"Suspicious high-risk top-level domain ({tld}).")
                    break
                    
            # Check 4: Brand Typosquatting
            for brand in TARGET_BRANDS:
                if brand in domain and not domain.endswith(f"{brand}.com"):
                    is_brand_typosquat = True
                    risk_score += 45
                    reasons.append(f"Potential Brand Typosquatting targeting '{brand}'.")
                    break
                    
            # Check 5: Entropy
            entropy = cls.calculate_url_entropy(domain)
            if entropy > 4.5:
                risk_score += 20
                reasons.append(f"High domain character entropy ({entropy:.2f}), suggesting auto-generated DGA domain.")
                
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            risk_score += 10
            
        # ONNX Local ML Classifier Prediction
        ml_features = {
            "url_length": len(url),
            "domain_length": len(domain) if 'domain' in locals() else len(url),
            "dot_count": domain.count(".") if 'domain' in locals() else 0,
            "hyphen_count": domain.count("-") if 'domain' in locals() else 0,
            "is_ip_address": is_ip_address,
            "is_suspicious_tld": is_suspicious_tld,
            "is_brand_typosquat": is_brand_typosquat,
            "entropy": entropy
        }
        ml_result = ONNXPhishingClassifier.predict(ml_features)
        
        # Combined Hybrid Score (50% Heuristic + 50% ONNX ML)
        hybrid_score = int(round(0.5 * min(100, risk_score) + 0.5 * ml_result["ml_risk_score"]))
        
        verdict = "SAFE"
        if hybrid_score >= 70:
            verdict = "CRITICAL_PHISHING"
        elif hybrid_score >= 40:
            verdict = "SUSPICIOUS"
            
        return {
            "url": url,
            "risk_score": hybrid_score,
            "heuristic_score": min(100, risk_score),
            "ml_model_prediction": ml_result,
            "verdict": verdict,
            "reasons": reasons,
            "entropy": round(entropy, 2)
        }
