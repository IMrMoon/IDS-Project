"""Configuration management module for IDS."""

import yaml
import os
from typing import Any, Dict


class Config:
    """Configuration container class."""
    
    def __init__(self, config_dict: Dict[str, Any]):
        """Initialize configuration from dictionary."""
        self._config = config_dict
        
        # Sniffer settings
        self.interface = config_dict['sniffer']['interface']
        self.promiscuous = config_dict['sniffer']['promiscuous']
        self.bpf_filter = config_dict['sniffer'].get('bpf_filter')
        self.queue_maxsize = config_dict['sniffer']['queue_maxsize']
        self.parse_payload_bytes_limit = config_dict['sniffer']['parse_payload_bytes_limit']
        
        # Flow settings
        self.inactivity_timeout_seconds = config_dict['flows']['inactivity_timeout_seconds']
        self.max_active_flows = config_dict['flows']['max_active_flows']
        self.retention_max_finalized_flows = config_dict['flows']['retention_max_finalized_flows']
        
        # Rules
        self.rules = config_dict['rules']
        
        # ML settings
        self.ml_enabled = config_dict['ml']['enabled']
        self.ml_feature_list = config_dict['ml']['feature_list']
        self.ml_model_path = config_dict['ml']['model_path']
        self.ml_meta_path = config_dict['ml']['meta_path']
        self.ml_contamination = config_dict['ml']['contamination']
        self.ml_anomaly_threshold = config_dict['ml']['anomaly_threshold']
        self.ml_training = config_dict['ml']['training']
        
        # Alerts
        self.alerts_jsonl_path = config_dict['alerts']['jsonl_path']
        self.alerts_retention = config_dict['alerts']['retention']
        
    def get_raw(self) -> Dict[str, Any]:
        """Get raw configuration dictionary."""
        return self._config


def load_config(path: str) -> Config:
    """
    Load configuration from YAML file.
    
    Args:
        path: Path to YAML configuration file
        
    Returns:
        Config object
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config is invalid
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Configuration file not found: {path}")
    
    with open(path, 'r') as f:
        config_dict = yaml.safe_load(f)
    
    validate_config(config_dict)
    return Config(config_dict)


def validate_config(config: Dict[str, Any]) -> None:
    """
    Validate configuration structure and values.
    
    Args:
        config: Configuration dictionary
        
    Raises:
        ValueError: If configuration is invalid
    """
    # Check required top-level keys
    required_keys = ['sniffer', 'flows', 'rules', 'ml', 'alerts']
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required configuration section: {key}")
    
    # Validate sniffer section
    sniffer_required = ['interface', 'promiscuous', 'queue_maxsize', 'parse_payload_bytes_limit']
    for key in sniffer_required:
        if key not in config['sniffer']:
            raise ValueError(f"Missing required sniffer config: {key}")
    
    if config['sniffer']['queue_maxsize'] <= 0:
        raise ValueError("queue_maxsize must be positive")
    
    # Validate flows section
    flows_required = ['inactivity_timeout_seconds', 'max_active_flows', 'retention_max_finalized_flows']
    for key in flows_required:
        if key not in config['flows']:
            raise ValueError(f"Missing required flows config: {key}")
    
    if config['flows']['inactivity_timeout_seconds'] <= 0:
        raise ValueError("inactivity_timeout_seconds must be positive")
    
    if config['flows']['max_active_flows'] <= 0:
        raise ValueError("max_active_flows must be positive")
    
    # Validate rules section
    required_rule_sections = ['port_scan_connect', 'syn_stealth', 'tcp_flag_scans', 'traffic_volume', 'payload_inspection']
    for section in required_rule_sections:
        if section not in config['rules']:
            raise ValueError(f"Missing required rules section: {section}")
    
    # Validate ML section
    ml_required = ['enabled', 'feature_list', 'model_path', 'meta_path', 'contamination', 'anomaly_threshold', 'training']
    for key in ml_required:
        if key not in config['ml']:
            raise ValueError(f"Missing required ml config: {key}")
    
    if not isinstance(config['ml']['feature_list'], list) or len(config['ml']['feature_list']) == 0:
        raise ValueError("ml.feature_list must be a non-empty list")
    
    if not (0 < config['ml']['contamination'] < 0.5):
        raise ValueError("ml.contamination must be between 0 and 0.5")
    
    if config['ml']['anomaly_threshold'] < 0:
        raise ValueError("ml.anomaly_threshold must be non-negative")
    
    # Validate alerts section
    alerts_required = ['jsonl_path', 'retention']
    for key in alerts_required:
        if key not in config['alerts']:
            raise ValueError(f"Missing required alerts config: {key}")
