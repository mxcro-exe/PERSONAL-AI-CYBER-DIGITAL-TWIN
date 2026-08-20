"""
Personal AI Cyber Digital Twin - Behavioral Baseline & Anomaly Analytics Subsystem
"""

import math
import uuid
import logging
from typing import Dict, Any, Tuple
from datetime import datetime, timezone
from app.core.config import settings
from app.core.database import get_db_connection
from app.core.privacy import PrivacyGuard

logger = logging.getLogger("CyberTwin.DigitalTwin.Baseline")

class BehavioralBaselineEngine:
    def __init__(self):
        self.alpha = settings.BASELINE_ALPHA
        self.z_threshold = settings.ANOMALY_Z_THRESHOLD

    def update_and_evaluate(self, feature_name: str, entity_id: str, observed_val: float) -> Tuple[bool, float, float]:
        """
        Updates the exponential moving average (EMA) baseline for a given behavioral feature
        and calculates the Z-Score to identify statistical anomalies.
        Returns: (is_anomaly, z_score, updated_mean)
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT mean_val, std_dev, sample_count 
            FROM behavioral_baseline 
            WHERE feature_name = ? AND entity_id = ?
        """, (feature_name, entity_id))
        
        row = cursor.fetchone()
        
        if row is None:
            # Initialize feature baseline
            mean_val = float(observed_val)
            std_dev = 1.0
            sample_count = 1
            record_id = str(uuid.uuid4())
            
            cursor.execute("""
                INSERT INTO behavioral_baseline (id, feature_name, entity_id, mean_val, std_dev, sample_count)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (record_id, feature_name, entity_id, mean_val, std_dev, sample_count))
            conn.commit()
            conn.close()
            return False, 0.0, mean_val
            
        mean_val = row["mean_val"]
        std_dev = row["std_dev"]
        sample_count = row["sample_count"]
        
        # Calculate Z-score
        z_score = (observed_val - mean_val) / std_dev if std_dev > 0 else 0.0
        is_anomaly = abs(z_score) >= self.z_threshold
        
        # Update baseline statistics via Exponential Moving Average (EMA)
        new_mean = (1 - self.alpha) * mean_val + self.alpha * observed_val
        diff = observed_val - new_mean
        new_var = (1 - self.alpha) * (std_dev ** 2) + self.alpha * (diff ** 2)
        new_std = math.sqrt(max(new_var, 0.01))
        
        # Apply differential privacy noise to metrics stored in database
        private_mean = PrivacyGuard.add_laplace_noise(new_mean, sensitivity=0.1)
        
        cursor.execute("""
            UPDATE behavioral_baseline
            SET mean_val = ?, std_dev = ?, sample_count = sample_count + 1, last_updated = CURRENT_TIMESTAMP
            WHERE feature_name = ? AND entity_id = ?
        """, (private_mean, new_std, feature_name, entity_id))
        
        conn.commit()
        conn.close()
        
        return is_anomaly, z_score, private_mean
