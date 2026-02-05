"""Rule-based detection engine."""

import time
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from collections import defaultdict, deque
from ..features.flow_models import Flow, ParsedPacket
from ..alerts.alerts import Alert


logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Rule-based detection engine.
    
    Implements detection rules for:
    - TCP connect port scans
    - SYN stealth scans
    - TCP flag scans (Xmas, NULL)
    - Traffic volume anomalies (PPS, BPS, flow rate)
    - Payload inspection (optional)
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize rule engine with configuration.
        
        Args:
            config: Rules configuration dictionary
        """
        self.config = config
        
        # Tracking structures for time-window rules
        # Port scan tracking: src_ip -> [(timestamp, dst_port), ...]
        self._port_scan_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # SYN stealth tracking: src_ip -> [(timestamp, had_ack), ...]
        self._syn_stealth_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Traffic volume tracking
        self._pps_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self._bps_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self._flow_creation_times: deque = deque(maxlen=10000)
        
        # Cooldown tracking: (rule_id, entity) -> last_alert_time
        self._cooldowns: Dict[tuple, float] = {}
    
    def evaluate_packet(self, packet: ParsedPacket, flow: Flow) -> List[Alert]:
        """
        Evaluate packet-level rules.
        
        Args:
            packet: Parsed packet
            flow: Associated flow
            
        Returns:
            List of alerts triggered by this packet
        """
        alerts = []
        now = time.monotonic()
        
        # Track for port scan detection
        if packet.protocol == "TCP" and packet.dst_port:
            self._port_scan_data[packet.src_ip].append((now, packet.dst_port))
        
        # Track for SYN stealth detection
        if packet.protocol == "TCP" and packet.tcp_flags:
            has_syn = 'S' in packet.tcp_flags
            has_ack = 'A' in packet.tcp_flags
            if has_syn:
                self._syn_stealth_data[packet.src_ip].append((now, has_ack))
        
        # Track for traffic volume
        self._pps_data[packet.src_ip].append((now, 1))
        self._bps_data[packet.src_ip].append((now, packet.length_bytes))
        
        # TCP flag scans (Xmas, NULL) - check on SYN packets
        if packet.protocol == "TCP" and packet.tcp_flags:
            flag_alerts = self._check_tcp_flag_scans(packet, now)
            alerts.extend(flag_alerts)
        
        # Payload inspection (if enabled)
        if self.config.get('payload_inspection', {}).get('enabled', False):
            if packet.payload_bytes:
                payload_alerts = self._check_payload_patterns(packet, now)
                alerts.extend(payload_alerts)
        
        return alerts
    
    def evaluate_flow(self, flow: Flow, now_monotonic: float) -> List[Alert]:
        """
        Evaluate flow-level rules on finalized flows.
        
        Args:
            flow: Finalized flow to evaluate
            now_monotonic: Current monotonic time
            
        Returns:
            List of alerts triggered by this flow
        """
        alerts = []
        
        # Port scan detection
        port_scan_alert = self._check_port_scan(flow.flow_key.a_ip, now_monotonic)
        if port_scan_alert:
            alerts.append(port_scan_alert)
        
        # SYN stealth scan
        syn_stealth_alert = self._check_syn_stealth(flow.flow_key.a_ip, now_monotonic)
        if syn_stealth_alert:
            alerts.append(syn_stealth_alert)
        
        # Traffic volume checks
        volume_alerts = self._check_traffic_volume(flow.flow_key.a_ip, now_monotonic)
        alerts.extend(volume_alerts)
        
        # Also check from B endpoint
        port_scan_alert_b = self._check_port_scan(flow.flow_key.b_ip, now_monotonic)
        if port_scan_alert_b:
            alerts.append(port_scan_alert_b)
        
        syn_stealth_alert_b = self._check_syn_stealth(flow.flow_key.b_ip, now_monotonic)
        if syn_stealth_alert_b:
            alerts.append(syn_stealth_alert_b)
        
        volume_alerts_b = self._check_traffic_volume(flow.flow_key.b_ip, now_monotonic)
        alerts.extend(volume_alerts_b)
        
        return alerts
    
    def evaluate_flow_creation(self, now_monotonic: float) -> List[Alert]:
        """
        Evaluate flow creation rate.
        
        Args:
            now_monotonic: Current monotonic time
            
        Returns:
            List of alerts for high flow creation rate
        """
        self._flow_creation_times.append(now_monotonic)
        
        alert = self._check_flow_creation_rate(now_monotonic)
        return [alert] if alert else []
    
    def _check_port_scan(self, src_ip: str, now: float) -> Optional[Alert]:
        """Check for TCP connect port scan."""
        config = self.config.get('port_scan_connect', {})
        window = config.get('window_seconds', 10)
        threshold = config.get('unique_dst_ports_threshold', 20)
        min_packets = config.get('min_packets_threshold', 25)
        cooldown = config.get('cooldown_seconds', 30)
        
        # Check cooldown
        rule_id = 'port_scan_connect'
        if self._is_on_cooldown(rule_id, src_ip, now, cooldown):
            return None
        
        # Get recent activity
        recent = [(ts, port) for ts, port in self._port_scan_data[src_ip] if now - ts <= window]
        
        if len(recent) < min_packets:
            return None
        
        # Count unique ports
        unique_ports = len(set(port for _, port in recent))
        
        if unique_ports >= threshold:
            self._set_cooldown(rule_id, src_ip, now)
            
            return Alert(
                timestamp_utc=datetime.now().astimezone().isoformat(),
                severity='HIGH',
                detection_type='RULE',
                rule_id=rule_id,
                flow_id=None,
                src={'ip': src_ip, 'port': None},
                dst={'ip': 'multiple', 'port': None},
                tags=['port_scan', 'reconnaissance'],
                description=f'TCP connect port scan detected: {unique_ports} unique ports in {window}s',
                evidence={
                    'unique_ports': unique_ports,
                    'total_packets': len(recent),
                    'window_seconds': window,
                    'threshold': threshold
                }
            )
        
        return None
    
    def _check_syn_stealth(self, src_ip: str, now: float) -> Optional[Alert]:
        """Check for SYN stealth scan."""
        config = self.config.get('syn_stealth', {})
        window = config.get('window_seconds', 10)
        threshold = config.get('syn_without_ack_threshold', 50)
        cooldown = config.get('cooldown_seconds', 30)
        
        # Check cooldown
        rule_id = 'syn_stealth'
        if self._is_on_cooldown(rule_id, src_ip, now, cooldown):
            return None
        
        # Get recent SYN packets
        recent = [(ts, has_ack) for ts, has_ack in self._syn_stealth_data[src_ip] 
                  if now - ts <= window]
        
        # Count SYN without ACK
        syn_without_ack = sum(1 for _, has_ack in recent if not has_ack)
        
        if syn_without_ack >= threshold:
            self._set_cooldown(rule_id, src_ip, now)
            
            return Alert(
                timestamp_utc=datetime.now().astimezone().isoformat(),
                severity='HIGH',
                detection_type='RULE',
                rule_id=rule_id,
                flow_id=None,
                src={'ip': src_ip, 'port': None},
                dst={'ip': 'multiple', 'port': None},
                tags=['syn_scan', 'stealth', 'reconnaissance'],
                description=f'SYN stealth scan detected: {syn_without_ack} SYN packets without ACK in {window}s',
                evidence={
                    'syn_without_ack': syn_without_ack,
                    'window_seconds': window,
                    'threshold': threshold
                }
            )
        
        return None
    
    def _check_tcp_flag_scans(self, packet: ParsedPacket, now: float) -> List[Alert]:
        """Check for TCP flag scans (Xmas, NULL)."""
        alerts = []
        config = self.config.get('tcp_flag_scans', {})
        
        if not packet.tcp_flags:
            return alerts
        
        flags = packet.tcp_flags
        rule_id = None
        scan_type = None
        
        # Xmas scan: FIN, PSH, URG set
        if config.get('enable_xmas', True):
            if 'F' in flags and 'P' in flags and 'U' in flags and 'S' not in flags:
                rule_id = 'tcp_xmas_scan'
                scan_type = 'Xmas'
        
        # NULL scan: no flags set
        if config.get('enable_null', True):
            if not flags or flags == '':
                rule_id = 'tcp_null_scan'
                scan_type = 'NULL'
        
        if rule_id and scan_type:
            # No cooldown for flag scans - each one is significant
            alerts.append(Alert(
                timestamp_utc=datetime.now().astimezone().isoformat(),
                severity='MEDIUM',
                detection_type='RULE',
                rule_id=rule_id,
                flow_id=None,
                src={'ip': packet.src_ip, 'port': packet.src_port},
                dst={'ip': packet.dst_ip, 'port': packet.dst_port},
                tags=['flag_scan', scan_type.lower(), 'reconnaissance'],
                description=f'TCP {scan_type} scan packet detected',
                evidence={
                    'tcp_flags': flags,
                    'scan_type': scan_type
                }
            ))
        
        return alerts
    
    def _check_traffic_volume(self, src_ip: str, now: float) -> List[Alert]:
        """Check traffic volume rules (PPS, BPS)."""
        alerts = []
        config = self.config.get('traffic_volume', {})
        
        # PPS check
        pps_config = config.get('pps_per_src', {})
        window = pps_config.get('window_seconds', 5)
        threshold = pps_config.get('threshold', 500)
        cooldown = pps_config.get('cooldown_seconds', 10)
        
        rule_id = 'traffic_volume_pps'
        if not self._is_on_cooldown(rule_id, src_ip, now, cooldown):
            recent_packets = [ts for ts, _ in self._pps_data[src_ip] if now - ts <= window]
            packet_count = len(recent_packets)
            
            if packet_count >= threshold:
                self._set_cooldown(rule_id, src_ip, now)
                alerts.append(Alert(
                    timestamp_utc=datetime.now().astimezone().isoformat(),
                    severity='MEDIUM',
                    detection_type='RULE',
                    rule_id=rule_id,
                    flow_id=None,
                    src={'ip': src_ip, 'port': None},
                    dst={'ip': 'multiple', 'port': None},
                    tags=['high_pps', 'volume_anomaly'],
                    description=f'High packet rate detected: {packet_count} packets/{window}s',
                    evidence={
                        'packet_count': packet_count,
                        'threshold': threshold,
                        'window_seconds': window
                    }
                ))
        
        # BPS check
        bps_config = config.get('bps_per_src', {})
        window = bps_config.get('window_seconds', 5)
        threshold = bps_config.get('threshold_bytes_per_sec', 5000000)
        cooldown = bps_config.get('cooldown_seconds', 10)
        
        rule_id = 'traffic_volume_bps'
        if not self._is_on_cooldown(rule_id, src_ip, now, cooldown):
            recent_bytes = [bytes_val for ts, bytes_val in self._bps_data[src_ip] if now - ts <= window]
            bps = sum(recent_bytes) / window if window > 0 else 0
            
            if bps >= threshold:
                self._set_cooldown(rule_id, src_ip, now)
                alerts.append(Alert(
                    timestamp_utc=datetime.now().astimezone().isoformat(),
                    severity='MEDIUM',
                    detection_type='RULE',
                    rule_id=rule_id,
                    flow_id=None,
                    src={'ip': src_ip, 'port': None},
                    dst={'ip': 'multiple', 'port': None},
                    tags=['high_bps', 'volume_anomaly'],
                    description=f'High byte rate detected: {bps:.1f} bps',
                    evidence={
                        'bps': round(bps, 2),
                        'threshold': threshold,
                        'window_seconds': window
                    }
                ))
        
        return alerts
    
    def _check_flow_creation_rate(self, now: float) -> Optional[Alert]:
        """Check flow creation rate."""
        config = self.config.get('traffic_volume', {}).get('new_flows_rate', {})
        window = config.get('window_seconds', 5)
        threshold = config.get('threshold_flows_per_window', 800)
        cooldown = config.get('cooldown_seconds', 10)
        
        rule_id = 'traffic_volume_flow_rate'
        if self._is_on_cooldown(rule_id, 'global', now, cooldown):
            return None
        
        # Count flows in window
        recent_flows = [ts for ts in self._flow_creation_times if now - ts <= window]
        flow_count = len(recent_flows)
        
        if flow_count >= threshold:
            self._set_cooldown(rule_id, 'global', now)
            
            return Alert(
                timestamp_utc=datetime.now().astimezone().isoformat(),
                severity='MEDIUM',
                detection_type='RULE',
                rule_id=rule_id,
                flow_id=None,
                src={'ip': 'multiple', 'port': None},
                dst={'ip': 'multiple', 'port': None},
                tags=['high_flow_rate', 'volume_anomaly'],
                description=f'High flow creation rate detected: {flow_count} flows in {window}s',
                evidence={
                    'flow_count': flow_count,
                    'threshold': threshold,
                    'window_seconds': window
                }
            )
        
        return None
    
    def _check_payload_patterns(self, packet: ParsedPacket, now: float) -> List[Alert]:
        """Check payload for suspicious patterns."""
        config = self.config.get('payload_inspection', {})
        patterns = config.get('patterns', [])
        max_scan = config.get('max_scan_bytes', 512)
        
        if not packet.payload_bytes:
            return []
        
        alerts = []
        payload = packet.payload_bytes[:max_scan]
        
        try:
            # Try to decode as UTF-8 for pattern matching
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            
            for pattern in patterns:
                if pattern.lower() in payload_str:
                    alerts.append(Alert(
                        timestamp_utc=datetime.now().astimezone().isoformat(),
                        severity='MEDIUM',
                        detection_type='RULE',
                        rule_id='payload_pattern_match',
                        flow_id=None,
                        src={'ip': packet.src_ip, 'port': packet.src_port},
                        dst={'ip': packet.dst_ip, 'port': packet.dst_port},
                        tags=['payload_inspection', 'suspicious_pattern'],
                        description=f'Suspicious payload pattern detected: {pattern}',
                        evidence={
                            'pattern': pattern,
                            'protocol': packet.protocol
                        }
                    ))
        except Exception as e:
            logger.debug(f"Error in payload inspection: {e}")
        
        return alerts
    
    def _is_on_cooldown(self, rule_id: str, entity: str, now: float, cooldown: float) -> bool:
        """Check if rule is on cooldown for entity."""
        key = (rule_id, entity)
        if key in self._cooldowns:
            last_alert = self._cooldowns[key]
            return (now - last_alert) < cooldown
        return False
    
    def _set_cooldown(self, rule_id: str, entity: str, now: float) -> None:
        """Set cooldown for rule and entity."""
        key = (rule_id, entity)
        self._cooldowns[key] = now
