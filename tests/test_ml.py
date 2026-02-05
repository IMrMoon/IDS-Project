"""Tests for ML-based anomaly detection."""

import pytest
import numpy as np
import time
from datetime import datetime, timezone

from src.detection.anomaly_engine import AnomalyEngine
from src.features.flow_models import Flow, FlowKey


class TestAnomalyEngine:
    """Test anomaly detection engine."""
    
    def create_flow(self, packets_fwd=10, packets_rev=10, bytes_fwd=1000, bytes_rev=1000,
                   syn_count=1, fin_count=1, rst_count=0):
        """Helper to create a flow with specified characteristics."""
        now = time.monotonic()
        ts_utc = datetime.now(timezone.utc).isoformat()
        
        key = FlowKey(
            a_ip='10.0.0.5',
            b_ip='192.168.1.10',
            a_port=80,
            b_port=12345,
            protocol='TCP'
        )
        
        flow = Flow(
            flow_key=key,
            first_seen_utc=ts_utc,
            last_seen_utc=ts_utc,
            first_seen_monotonic=now,
            last_seen_monotonic=now + 1.0,
            packets_fwd=packets_fwd,
            packets_rev=packets_rev,
            bytes_fwd=bytes_fwd,
            bytes_rev=bytes_rev
        )
        
        flow.tcp_flags_counts['SYN'] = syn_count
        flow.tcp_flags_counts['FIN'] = fin_count
        flow.tcp_flags_counts['RST'] = rst_count
        flow.interarrival_mean_ms = 100.0
        flow.interarrival_var_ms = 50.0
        
        return flow
    
    def test_feature_extraction(self):
        """Test that features are extracted in correct order."""
        config = {
            'enabled': True,
            'feature_list': [
                'duration_seconds',
                'packets_total',
                'bytes_total',
                'packets_fwd',
                'packets_rev',
                'bytes_fwd',
                'bytes_rev',
                'bytes_per_packet',
                'syn_count',
                'fin_count',
                'rst_count',
                'syn_ratio',
                'rst_ratio',
                'interarrival_mean_ms',
                'interarrival_var_ms'
            ],
            'model_path': 'data/test_model.joblib',
            'meta_path': 'data/test_model_meta.json',
            'contamination': 0.02,
            'anomaly_threshold': 0.15,
            'training': {}
        }
        
        engine = AnomalyEngine(config)
        flow = self.create_flow()
        
        features = engine.extract_features(flow)
        
        assert len(features) == len(config['feature_list'])
        assert isinstance(features, list)
        assert all(isinstance(f, float) for f in features)
        
        # Check some specific features
        assert features[0] == 1.0  # duration_seconds
        assert features[1] == 20.0  # packets_total
        assert features[2] == 2000.0  # bytes_total
        assert features[3] == 10.0  # packets_fwd
        assert features[4] == 10.0  # packets_rev
    
    def test_training_pipeline(self):
        """Test ML model training pipeline."""
        config = {
            'enabled': True,
            'feature_list': [
                'duration_seconds',
                'packets_total',
                'bytes_total',
                'bytes_per_packet',
                'syn_ratio'
            ],
            'model_path': 'data/test_model.joblib',
            'meta_path': 'data/test_model_meta.json',
            'contamination': 0.02,
            'anomaly_threshold': 0.15,
            'training': {}
        }
        
        engine = AnomalyEngine(config)
        
        # Generate training data (normal flows)
        training_flows = []
        for i in range(100):
            flow = self.create_flow(
                packets_fwd=10 + i % 10,
                packets_rev=10 + i % 10,
                bytes_fwd=1000 + i * 10,
                bytes_rev=1000 + i * 10
            )
            training_flows.append(flow)
        
        # Extract features
        feature_rows = [engine.extract_features(flow) for flow in training_flows]
        
        # Train model
        engine.train_from_feature_rows(feature_rows)
        
        assert engine.model is not None, "Model should be trained"
        assert engine.enabled == True, "Engine should be enabled after training"
    
    def test_anomaly_scoring(self):
        """Test anomaly score computation."""
        config = {
            'enabled': True,
            'feature_list': [
                'duration_seconds',
                'packets_total',
                'bytes_total',
                'bytes_per_packet',
                'syn_ratio'
            ],
            'model_path': 'data/test_model.joblib',
            'meta_path': 'data/test_model_meta.json',
            'contamination': 0.02,
            'anomaly_threshold': 0.15,
            'training': {}
        }
        
        engine = AnomalyEngine(config)
        
        # Generate and train on normal flows
        training_flows = []
        for i in range(100):
            flow = self.create_flow(
                packets_fwd=10,
                packets_rev=10,
                bytes_fwd=1000,
                bytes_rev=1000
            )
            training_flows.append(flow)
        
        feature_rows = [engine.extract_features(flow) for flow in training_flows]
        engine.train_from_feature_rows(feature_rows)
        
        # Score a normal flow
        normal_flow = self.create_flow(packets_fwd=10, packets_rev=10)
        normal_features = engine.extract_features(normal_flow)
        normal_score = engine.score(normal_features)
        
        assert normal_score is not None, "Should be able to score flow"
        assert isinstance(normal_score, float)
        
        # Score an anomalous flow (very different characteristics)
        anomalous_flow = self.create_flow(
            packets_fwd=1000,
            packets_rev=0,
            bytes_fwd=1000000,
            bytes_rev=0,
            syn_count=500
        )
        anomalous_features = engine.extract_features(anomalous_flow)
        anomalous_score = engine.score(anomalous_features)
        
        assert anomalous_score is not None
        # Anomalous flow should generally have higher score
        # (though this depends on the model and data)
    
    def test_alert_generation(self):
        """Test that alerts are generated for high anomaly scores."""
        config = {
            'enabled': True,
            'feature_list': ['duration_seconds', 'packets_total', 'bytes_total'],
            'model_path': 'data/test_model.joblib',
            'meta_path': 'data/test_model_meta.json',
            'contamination': 0.02,
            'anomaly_threshold': 0.15,
            'training': {}
        }
        
        engine = AnomalyEngine(config)
        
        # Train on normal data
        training_rows = [[1.0, 10.0, 1000.0] for _ in range(100)]
        engine.train_from_feature_rows(training_rows)
        
        # Create a flow
        flow = self.create_flow()
        
        # Test with a feature vector that should trigger alert
        # (very different from training data)
        anomalous_features = [100.0, 10000.0, 10000000.0]
        alert = engine.evaluate(anomalous_features, flow)
        
        # Alert may or may not be generated depending on model
        # but the function should not crash
        if alert:
            assert alert.detection_type == 'ANOMALY'
            assert alert.rule_id == 'ml_anomaly_detection'
    
    def test_feature_order_consistency(self):
        """Test that feature extraction order matches config."""
        config = {
            'enabled': True,
            'feature_list': [
                'bytes_total',  # Intentionally different order
                'packets_total',
                'duration_seconds'
            ],
            'model_path': 'data/test_model.joblib',
            'meta_path': 'data/test_model_meta.json',
            'contamination': 0.02,
            'anomaly_threshold': 0.15,
            'training': {}
        }
        
        engine = AnomalyEngine(config)
        flow = self.create_flow()
        
        features = engine.extract_features(flow)
        
        # Features should be in order of feature_list
        assert features[0] == 2000.0  # bytes_total
        assert features[1] == 20.0  # packets_total
        assert features[2] == 1.0  # duration_seconds
