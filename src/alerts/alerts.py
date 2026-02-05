"""Alert management and storage."""

import json
import logging
import threading
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from pathlib import Path
import csv


logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """Alert structure matching alertSchema."""
    timestamp_utc: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    detection_type: str  # RULE, ANOMALY, SYSTEM
    rule_id: str
    flow_id: Optional[str]
    src: Dict[str, Any]  # {'ip': str, 'port': Optional[int]}
    dst: Dict[str, Any]  # {'ip': str, 'port': Optional[int]}
    tags: List[str]
    description: str
    evidence: Dict[str, Any]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @staticmethod
    def from_dict(data: Dict) -> 'Alert':
        """Create Alert from dictionary."""
        return Alert(**data)


class AlertSink:
    """
    Manages alert storage and retrieval.
    
    Alerts are stored in JSONL format with retention policies.
    """
    
    def __init__(self, jsonl_path: str, keep_last_n: int, keep_days: int):
        """
        Initialize alert sink.
        
        Args:
            jsonl_path: Path to JSONL alert file
            keep_last_n: Maximum number of alerts to retain
            keep_days: Maximum age of alerts to retain (days)
        """
        self.jsonl_path = jsonl_path
        self.keep_last_n = keep_last_n
        self.keep_days = keep_days
        
        self._lock = threading.Lock()
        self._alerts_in_memory: List[Alert] = []
        
        # Ensure directory exists
        Path(jsonl_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing alerts
        self._load_alerts()
    
    def emit(self, alert: Alert) -> None:
        """
        Emit an alert.
        
        Appends to JSONL file and maintains in-memory list.
        """
        with self._lock:
            # Add to memory
            self._alerts_in_memory.append(alert)
            
            # Append to file
            try:
                with open(self.jsonl_path, 'a') as f:
                    f.write(alert.to_json() + '\n')
            except Exception as e:
                logger.error(f"Failed to write alert to file: {e}")
            
            # Apply retention if needed
            if len(self._alerts_in_memory) > self.keep_last_n:
                self._apply_retention()
    
    def load_recent(self, limit: int = 20) -> List[Alert]:
        """
        Load recent alerts.
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of most recent alerts
        """
        with self._lock:
            return self._alerts_in_memory[-limit:]
    
    def export_csv(self, path: str) -> None:
        """
        Export alerts to CSV file.
        
        Args:
            path: Output CSV file path
        """
        with self._lock:
            if not self._alerts_in_memory:
                logger.warning("No alerts to export")
                return
            
            try:
                with open(path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    
                    # Write header
                    writer.writerow([
                        'timestamp_utc', 'severity', 'detection_type', 'rule_id',
                        'src_ip', 'src_port', 'dst_ip', 'dst_port',
                        'description', 'tags'
                    ])
                    
                    # Write alerts
                    for alert in self._alerts_in_memory:
                        writer.writerow([
                            alert.timestamp_utc,
                            alert.severity,
                            alert.detection_type,
                            alert.rule_id,
                            alert.src['ip'],
                            alert.src.get('port', ''),
                            alert.dst['ip'],
                            alert.dst.get('port', ''),
                            alert.description,
                            ','.join(alert.tags)
                        ])
                
                logger.info(f"Exported {len(self._alerts_in_memory)} alerts to {path}")
                
            except Exception as e:
                logger.error(f"Failed to export alerts to CSV: {e}")
    
    def _load_alerts(self) -> None:
        """Load alerts from JSONL file."""
        if not Path(self.jsonl_path).exists():
            return
        
        try:
            with open(self.jsonl_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            alert_dict = json.loads(line)
                            alert = Alert.from_dict(alert_dict)
                            self._alerts_in_memory.append(alert)
                        except json.JSONDecodeError:
                            logger.warning(f"Failed to parse alert line: {line[:50]}...")
            
            logger.info(f"Loaded {len(self._alerts_in_memory)} alerts from {self.jsonl_path}")
            
            # Apply retention after loading
            self._apply_retention()
            
        except Exception as e:
            logger.error(f"Failed to load alerts: {e}")
    
    def _apply_retention(self) -> None:
        """
        Apply retention policies.
        
        Keeps only the most recent keep_last_n alerts that are within keep_days.
        """
        if not self._alerts_in_memory:
            return
        
        # Filter by age
        cutoff_time = datetime.now().astimezone() - timedelta(days=self.keep_days)
        
        filtered = []
        for alert in self._alerts_in_memory:
            try:
                alert_time = datetime.fromisoformat(alert.timestamp_utc.replace('Z', '+00:00'))
                if alert_time >= cutoff_time:
                    filtered.append(alert)
            except Exception:
                # Keep alert if we can't parse timestamp
                filtered.append(alert)
        
        # Keep only last N
        if len(filtered) > self.keep_last_n:
            filtered = filtered[-self.keep_last_n:]
        
        # Update in-memory list
        old_count = len(self._alerts_in_memory)
        self._alerts_in_memory = filtered
        new_count = len(self._alerts_in_memory)
        
        if new_count < old_count:
            logger.info(f"Applied retention: {old_count} -> {new_count} alerts")
            
            # Rewrite file with retained alerts
            try:
                with open(self.jsonl_path, 'w') as f:
                    for alert in self._alerts_in_memory:
                        f.write(alert.to_json() + '\n')
            except Exception as e:
                logger.error(f"Failed to rewrite alerts file: {e}")
    
    def get_count(self) -> int:
        """Get total alert count."""
        with self._lock:
            return len(self._alerts_in_memory)
