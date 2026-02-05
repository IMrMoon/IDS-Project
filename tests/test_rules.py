"""Tests for rule-based detection."""

import pytest
import time
from datetime import datetime, timezone

from src.detection.rule_engine import RuleEngine
from src.features.flow_models import FlowKey, Flow, ParsedPacket


class TestPortScanDetection:
    """Test TCP connect port scan detection."""
    
    def create_packet(self, src_ip, dst_ip, dst_port, protocol='TCP', length=60):
        """Helper to create a ParsedPacket."""
        return ParsedPacket(
            ts_utc=datetime.now(timezone.utc).isoformat(),
            ts_monotonic=time.monotonic(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=12345,
            dst_port=dst_port,
            protocol=protocol,
            tcp_flags='S',
            length_bytes=length
        )
    
    def test_port_scan_detection(self):
        """Test that port scans are detected."""
        config = {
            'port_scan_connect': {
                'window_seconds': 10,
                'unique_dst_ports_threshold': 20,
                'min_packets_threshold': 25,
                'cooldown_seconds': 30
            },
            'syn_stealth': {},
            'tcp_flag_scans': {},
            'traffic_volume': {},
            'payload_inspection': {'enabled': False}
        }
        
        engine = RuleEngine(config)
        
        # Create flow
        now = time.monotonic()
        ts_utc = datetime.now(timezone.utc).isoformat()
        key = FlowKey.from_packet('192.168.1.100', '10.0.0.5', 12345, 80, 'TCP')
        flow = Flow(
            flow_key=key,
            first_seen_utc=ts_utc,
            last_seen_utc=ts_utc,
            first_seen_monotonic=now,
            last_seen_monotonic=now
        )
        
        # Simulate scanning many ports
        for port in range(1, 26):  # 25 packets to 25 different ports
            packet = self.create_packet('192.168.1.100', '10.0.0.5', port)
            alerts = engine.evaluate_packet(packet, flow)
        
        # Now check for port scan
        alert = engine._check_port_scan('192.168.1.100', time.monotonic())
        
        assert alert is not None, "Port scan should be detected"
        assert alert.rule_id == 'port_scan_connect'
        assert alert.severity == 'HIGH'
        assert 'port_scan' in alert.tags
    
    def test_below_threshold_no_alert(self):
        """Test that scanning below threshold doesn't trigger alert."""
        config = {
            'port_scan_connect': {
                'window_seconds': 10,
                'unique_dst_ports_threshold': 20,
                'min_packets_threshold': 25,
                'cooldown_seconds': 30
            },
            'syn_stealth': {},
            'tcp_flag_scans': {},
            'traffic_volume': {},
            'payload_inspection': {'enabled': False}
        }
        
        engine = RuleEngine(config)
        
        # Scan only 10 ports (below threshold)
        for port in range(1, 11):
            packet = self.create_packet('192.168.1.100', '10.0.0.5', port)
            flow = None  # Not needed for this test
            engine.evaluate_packet(packet, flow)
        
        alert = engine._check_port_scan('192.168.1.100', time.monotonic())
        
        assert alert is None, "No alert should be generated below threshold"


class TestSynStealthScan:
    """Test SYN stealth scan detection."""
    
    def create_packet(self, src_ip, dst_ip, has_ack=False):
        """Helper to create a TCP packet."""
        flags = 'SA' if has_ack else 'S'
        return ParsedPacket(
            ts_utc=datetime.now(timezone.utc).isoformat(),
            ts_monotonic=time.monotonic(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=12345,
            dst_port=80,
            protocol='TCP',
            tcp_flags=flags,
            length_bytes=60
        )
    
    def test_syn_stealth_detection(self):
        """Test that SYN stealth scans are detected."""
        config = {
            'port_scan_connect': {},
            'syn_stealth': {
                'window_seconds': 10,
                'syn_without_ack_threshold': 50,
                'cooldown_seconds': 30
            },
            'tcp_flag_scans': {},
            'traffic_volume': {},
            'payload_inspection': {'enabled': False}
        }
        
        engine = RuleEngine(config)
        
        # Simulate SYN stealth scan (many SYN without ACK)
        for i in range(55):
            packet = self.create_packet('192.168.1.100', '10.0.0.5', has_ack=False)
            flow = None
            engine.evaluate_packet(packet, flow)
        
        alert = engine._check_syn_stealth('192.168.1.100', time.monotonic())
        
        assert alert is not None, "SYN stealth scan should be detected"
        assert alert.rule_id == 'syn_stealth'
        assert 'stealth' in alert.tags


class TestTrafficVolume:
    """Test traffic volume detection."""
    
    def test_high_packet_rate(self):
        """Test high packet rate detection."""
        config = {
            'port_scan_connect': {},
            'syn_stealth': {},
            'tcp_flag_scans': {},
            'traffic_volume': {
                'pps_per_src': {
                    'window_seconds': 5,
                    'threshold': 100,
                    'cooldown_seconds': 10
                },
                'bps_per_src': {
                    'window_seconds': 5,
                    'threshold_bytes_per_sec': 1000000,
                    'cooldown_seconds': 10
                },
                'new_flows_rate': {
                    'window_seconds': 5,
                    'threshold_flows_per_window': 800,
                    'cooldown_seconds': 10
                }
            },
            'payload_inspection': {'enabled': False}
        }
        
        engine = RuleEngine(config)
        
        # Simulate high packet rate
        for i in range(150):
            packet = ParsedPacket(
                ts_utc=datetime.now(timezone.utc).isoformat(),
                ts_monotonic=time.monotonic(),
                src_ip='192.168.1.100',
                dst_ip='10.0.0.5',
                src_port=12345,
                dst_port=80,
                protocol='TCP',
                tcp_flags='S',
                length_bytes=60
            )
            flow = None
            engine.evaluate_packet(packet, flow)
        
        alerts = engine._check_traffic_volume('192.168.1.100', time.monotonic())
        
        # Should trigger PPS alert
        pps_alerts = [a for a in alerts if a.rule_id == 'traffic_volume_pps']
        assert len(pps_alerts) > 0, "High PPS should be detected"


class TestTcpFlagScans:
    """Test TCP flag scan detection."""
    
    def test_xmas_scan_detection(self):
        """Test Xmas scan detection."""
        config = {
            'port_scan_connect': {},
            'syn_stealth': {},
            'tcp_flag_scans': {
                'enable_xmas': True,
                'enable_null': True
            },
            'traffic_volume': {},
            'payload_inspection': {'enabled': False}
        }
        
        engine = RuleEngine(config)
        
        # Create Xmas packet (FIN, PSH, URG)
        packet = ParsedPacket(
            ts_utc=datetime.now(timezone.utc).isoformat(),
            ts_monotonic=time.monotonic(),
            src_ip='192.168.1.100',
            dst_ip='10.0.0.5',
            src_port=12345,
            dst_port=80,
            protocol='TCP',
            tcp_flags='FPU',
            length_bytes=60
        )
        
        flow = None
        alerts = engine.evaluate_packet(packet, flow)
        
        assert len(alerts) > 0, "Xmas scan should be detected"
        assert alerts[0].rule_id == 'tcp_xmas_scan'
        assert 'xmas' in alerts[0].tags
