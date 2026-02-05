"""Anomaly-based detection engine using machine learning."""

import json
import logging
import joblib
import numpy as np
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime, timezone
from sklearn.ensemble import IsolationForest
from ..features.flow_models import Flow
from ..alerts.alerts import Alert


logger = logging.getLogger(__name__)


class AnomalyEngine:
    """
    Anomaly detection engine using Isolation Forest.
    
    Learns normal network behavior and detects deviations.
    Score convention: anomaly_score = -decision_function (higher = more anomalous)
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize anomaly engine.
        
        Args:
            config: ML configuration dictionary
        """
        self.config = config
        self.enabled = config.get('enabled', True)
        self.feature_list = config.get('feature_list', [])
        self.model_path = config.get('model_path', 'data/model.joblib')
        self.meta_path = config.get('meta_path', 'data/model_meta.json')
        self.contamination = config.get('contamination', 0.02)
        self.anomaly_threshold = config.get('anomaly_threshold', 0.15)

        # Normalisation statistics (mean and std for each feature).  These
        # values are computed during training and stored in model
        # metadata.  During scoring, feature vectors are standardised
        # before being passed to the IsolationForest.  If scaling
        # parameters are not available, raw features are used.
        self.scaler_mean: Optional[List[float]] = None
        self.scaler_std: Optional[List[float]] = None
        
        self.model: Optional[IsolationForest] = None
        self.model_metadata: Optional[Dict] = None
        
        if self.enabled:
            self.load_model()
    
    def load_model(self) -> None:
        """Load trained model from disk."""
        if not Path(self.model_path).exists():
            logger.warning(f"Model file not found: {self.model_path}. ML detection disabled.")
            self.enabled = False
            return
        
        try:
            self.model = joblib.load(self.model_path)
            logger.info(f"Loaded ML model from {self.model_path}")
            
            # Load metadata if available
            if Path(self.meta_path).exists():
                with open(self.meta_path, 'r') as f:
                    self.model_metadata = json.load(f)
                logger.info(f"Loaded model metadata from {self.meta_path}")
                # Load scaler statistics and override anomaly threshold if
                # present in metadata
                scaler = self.model_metadata.get('scaler', {})
                if 'mean' in scaler and 'std' in scaler:
                    self.scaler_mean = scaler['mean']
                    self.scaler_std = scaler['std']
                # If threshold was computed during training, use it
                if 'threshold' in self.model_metadata:
                    self.anomaly_threshold = float(self.model_metadata['threshold'])
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.enabled = False
            self.model = None
    
    def train_from_feature_rows(self, rows: List[List[float]]) -> None:
        """
        Train Isolation Forest model from feature vectors.
        
        Args:
            rows: List of feature vectors (each matching feature_list order)
        """
        if not rows:
            logger.warning("No training data provided")
            return
        
        logger.info(f"Training Isolation Forest on {len(rows)} samples...")
        
        try:
            # Convert to numpy array
            X = np.array(rows)

            # Compute per-feature mean and standard deviation for scaling
            mean = X.mean(axis=0)
            std = X.std(axis=0)
            # Avoid division by zero: replace zeros with ones
            std_corrected = np.where(std == 0, 1.0, std)

            # Standardise training data
            X_scaled = (X - mean) / std_corrected
            
            # Train model on scaled data
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_scaled)
            
            # Compute anomaly scores for training data to determine
            # threshold dynamically.  The IsolationForest's decision
            # function gives higher values for more normal points; we
            # convert to anomaly scores (higher = more anomalous) and
            # choose the (1 - contamination) quantile as threshold.
            train_decisions = self.model.decision_function(X_scaled)
            train_scores = -train_decisions  # convert
            # Determine threshold at (1 - contamination) quantile
            quantile = 1.0 - float(self.contamination)
            threshold = float(np.quantile(train_scores, quantile))

            # Save model
            Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.model, self.model_path)
            logger.info(f"Saved model to {self.model_path}")

            # Save metadata including scaler and threshold
            metadata = {
                'feature_list': self.feature_list,
                'training_samples': len(rows),
                'contamination': self.contamination,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'threshold': threshold,
                'scaler': {
                    'mean': mean.tolist(),
                    'std': std_corrected.tolist()
                }
            }
            with open(self.meta_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            logger.info(f"Saved metadata to {self.meta_path}")

            self.model_metadata = metadata
            self.anomaly_threshold = threshold
            self.scaler_mean = mean.tolist()
            self.scaler_std = std_corrected.tolist()
            self.enabled = True
            
        except Exception as e:
            logger.error(f"Failed to train model: {e}", exc_info=True)
            self.enabled = False
    
    def score(self, feature_row: List[float]) -> Optional[float]:
        """
        Compute anomaly score for a feature vector.
        
        Args:
            feature_row: Feature vector matching feature_list order
            
        Returns:
            Anomaly score (higher = more anomalous), or None if model unavailable
        """
        if not self.enabled or self.model is None:
            return None
        
        try:
            # Standardise feature vector if scaler parameters are available
            X = np.array([feature_row], dtype=float)
            if self.scaler_mean is not None and self.scaler_std is not None:
                mean = np.array(self.scaler_mean, dtype=float)
                std = np.array(self.scaler_std, dtype=float)
                X = (X - mean) / std

            # Get decision function (higher = more normal in IsolationForest)
            decision = self.model.decision_function(X)[0]

            # Convert to anomaly score (higher = more anomalous)
            anomaly_score = -decision

            return float(anomaly_score)

        except Exception as e:
            logger.error(f"Failed to score feature vector: {e}")
            return None
    
    def evaluate(self, feature_row: List[float], flow_context: Flow) -> Optional[Alert]:
        """
        Evaluate feature vector and generate alert if anomalous.
        
        Args:
            feature_row: Feature vector to evaluate
            flow_context: Flow object for context in alert
            
        Returns:
            Alert if anomaly detected, None otherwise
        """
        score = self.score(feature_row)
        
        if score is None:
            return None
        
        if score >= self.anomaly_threshold:
            # Generate anomaly alert
            flow_key = flow_context.flow_key
            
            return Alert(
                timestamp_utc=datetime.now().astimezone().isoformat(),
                severity=self._score_to_severity(score),
                detection_type='ANOMALY',
                rule_id='ml_anomaly_detection',
                flow_id=f"{flow_key.a_ip}:{flow_key.a_port}-{flow_key.b_ip}:{flow_key.b_port}-{flow_key.protocol}",
                src={'ip': flow_key.a_ip, 'port': flow_key.a_port},
                dst={'ip': flow_key.b_ip, 'port': flow_key.b_port},
                tags=['anomaly', 'ml_detection'],
                description=f'Anomalous network flow detected (score: {score:.3f})',
                evidence={
                    'anomaly_score': round(score, 4),
                    'threshold': self.anomaly_threshold,
                    'duration_seconds': flow_context.get_duration_seconds(),
                    'total_packets': flow_context.get_total_packets(),
                    'total_bytes': flow_context.get_total_bytes()
                }
            )
        
        return None
    
    def extract_features(self, flow: Flow) -> List[float]:
        """
        Extract feature vector from flow.
        
        Features are extracted in the exact order specified in feature_list.
        
        Args:
            flow: Flow to extract features from
            
        Returns:
            Feature vector matching feature_list order
        """
        features = []
        
        for feature_name in self.feature_list:
            value = self._compute_feature(feature_name, flow)
            features.append(value)
        
        return features
    
    def _compute_feature(self, feature_name: str, flow: Flow) -> float:
        """
        Compute individual feature value.
        
        Args:
            feature_name: Name of feature to compute
            flow: Flow object
            
        Returns:
            Feature value as float
        """
        # Duration
        if feature_name == 'duration_seconds':
            return max(0.0, flow.last_seen_monotonic - flow.first_seen_monotonic)
        
        # Packet counts
        elif feature_name == 'packets_total':
            return float(flow.packets_fwd + flow.packets_rev)
        elif feature_name == 'packets_fwd':
            return float(flow.packets_fwd)
        elif feature_name == 'packets_rev':
            return float(flow.packets_rev)
        
        # Byte counts
        elif feature_name == 'bytes_total':
            return float(flow.bytes_fwd + flow.bytes_rev)
        elif feature_name == 'bytes_fwd':
            return float(flow.bytes_fwd)
        elif feature_name == 'bytes_rev':
            return float(flow.bytes_rev)
        
        # Derived metrics
        elif feature_name == 'bytes_per_packet':
            total_packets = flow.packets_fwd + flow.packets_rev
            total_bytes = flow.bytes_fwd + flow.bytes_rev
            return float(total_bytes) / max(1.0, float(total_packets))
        
        # TCP flag counts
        elif feature_name == 'syn_count':
            return float(flow.tcp_flags_counts.get('SYN', 0))
        elif feature_name == 'fin_count':
            return float(flow.tcp_flags_counts.get('FIN', 0))
        elif feature_name == 'rst_count':
            return float(flow.tcp_flags_counts.get('RST', 0))
        
        # TCP flag ratios
        elif feature_name == 'syn_ratio':
            total_packets = flow.packets_fwd + flow.packets_rev
            syn_count = flow.tcp_flags_counts.get('SYN', 0)
            return float(syn_count) / max(1.0, float(total_packets))
        elif feature_name == 'rst_ratio':
            total_packets = flow.packets_fwd + flow.packets_rev
            rst_count = flow.tcp_flags_counts.get('RST', 0)
            return float(rst_count) / max(1.0, float(total_packets))
        
        # Inter-arrival statistics
        elif feature_name == 'interarrival_mean_ms':
            return float(flow.interarrival_mean_ms) if flow.interarrival_mean_ms is not None else 0.0
        elif feature_name == 'interarrival_var_ms':
            return float(flow.interarrival_var_ms) if flow.interarrival_var_ms is not None else 0.0
        
        else:
            logger.warning(f"Unknown feature: {feature_name}")
            return 0.0
    
    def _score_to_severity(self, score: float) -> str:
        """
        Map anomaly score to severity level.
        
        Args:
            score: Anomaly score
            
        Returns:
            Severity string (LOW, MEDIUM, HIGH, CRITICAL)
        """
        if score >= 0.5:
            return 'CRITICAL'
        elif score >= 0.3:
            return 'HIGH'
        elif score >= 0.2:
            return 'MEDIUM'
        else:
            return 'LOW'
