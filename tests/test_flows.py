"""Tests for flow canonicalization and directional counters."""

import pytest
import time
from datetime import datetime, timezone

from src.features.flow_models import FlowKey, Flow, ParsedPacket


class TestFlowKey:
    """Test FlowKey canonicalization."""
    
    def test_canonical_ordering(self):
        """Test that flow keys are canonical regardless of direction."""
        # Forward packet
        key1 = FlowKey.from_packet(
            src_ip='192.168.1.10',
            dst_ip='10.0.0.5',
            src_port=12345,
            dst_port=80,
            protocol='TCP'
        )
        
        # Reverse packet (should produce same key)
        key2 = FlowKey.from_packet(
            src_ip='10.0.0.5',
            dst_ip='192.168.1.10',
            src_port=80,
            dst_port=12345,
            protocol='TCP'
        )
        
        assert key1 == key2, "Flow keys should be identical for bidirectional traffic"
    
    def test_endpoint_ordering(self):
        """Test that endpoints are ordered lexicographically."""
        key = FlowKey.from_packet(
            src_ip='192.168.1.10',
            dst_ip='10.0.0.5',
            src_port=12345,
            dst_port=80,
            protocol='TCP'
        )
        
        # Smaller IP should be endpoint A
        assert key.a_ip == '10.0.0.5'
        assert key.b_ip == '192.168.1.10'
        assert key.a_port == 80
        assert key.b_port == 12345
    
    def test_different_protocols_different_keys(self):
        """Test that different protocols produce different keys."""
        key_tcp = FlowKey.from_packet(
            src_ip='192.168.1.10',
            dst_ip='10.0.0.5',
            src_port=12345,
            dst_port=80,
            protocol='TCP'
        )
        
        key_udp = FlowKey.from_packet(
            src_ip='192.168.1.10',
            dst_ip='10.0.0.5',
            src_port=12345,
            dst_port=80,
            protocol='UDP'
        )
        
        assert key_tcp != key_udp, "Different protocols should produce different keys"


class TestFlow:
    """Test Flow directional counters."""
    
    def create_packet(self, src_ip, dst_ip, src_port, dst_port, protocol='TCP', 
                     tcp_flags='', length=100):
        """Helper to create a ParsedPacket."""
        return ParsedPacket(
            ts_utc=datetime.now(timezone.utc).isoformat(),
            ts_monotonic=time.monotonic(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            tcp_flags=tcp_flags if tcp_flags else None,
            length_bytes=length
        )
    
    def test_directional_counters(self):
        """Test that packets are counted in correct direction."""
        now = time.monotonic()
        ts_utc = datetime.now(timezone.utc).isoformat()
        
        # Create flow key
        key = FlowKey.from_packet('10.0.0.5', '192.168.1.10', 80, 12345, 'TCP')
        
        # Create flow
        flow = Flow(
            flow_key=key,
            first_seen_utc=ts_utc,
            last_seen_utc=ts_utc,
            first_seen_monotonic=now,
            last_seen_monotonic=now
        )
        
        # Packet A->B (10.0.0.5:80 -> 192.168.1.10:12345)
        pkt1 = self.create_packet('10.0.0.5', '192.168.1.10', 80, 12345, length=100)
        flow.update_with_packet(pkt1)
        
        assert flow.packets_fwd == 1
        assert flow.packets_rev == 0
        assert flow.bytes_fwd == 100
        assert flow.bytes_rev == 0
        
        # Packet B->A (reverse direction)
        pkt2 = self.create_packet('192.168.1.10', '10.0.0.5', 12345, 80, length=200)
        flow.update_with_packet(pkt2)
        
        assert flow.packets_fwd == 1
        assert flow.packets_rev == 1
        assert flow.bytes_fwd == 100
        assert flow.bytes_rev == 200
        
        # Another A->B packet
        pkt3 = self.create_packet('10.0.0.5', '192.168.1.10', 80, 12345, length=150)
        flow.update_with_packet(pkt3)
        
        assert flow.packets_fwd == 2
        assert flow.packets_rev == 1
        assert flow.bytes_fwd == 250
        assert flow.bytes_rev == 200
    
    def test_tcp_flags_tracking(self):
        """Test TCP flags are tracked correctly."""
        now = time.monotonic()
        ts_utc = datetime.now(timezone.utc).isoformat()
        
        key = FlowKey.from_packet('10.0.0.5', '192.168.1.10', 80, 12345, 'TCP')
        flow = Flow(
            flow_key=key,
            first_seen_utc=ts_utc,
            last_seen_utc=ts_utc,
            first_seen_monotonic=now,
            last_seen_monotonic=now
        )
        
        # SYN packet
        pkt1 = self.create_packet('10.0.0.5', '192.168.1.10', 80, 12345, tcp_flags='S')
        flow.update_with_packet(pkt1)
        
        assert flow.tcp_flags_counts['SYN'] == 1
        assert flow.tcp_flags_counts['ACK'] == 0
        
        # SYN-ACK packet
        pkt2 = self.create_packet('192.168.1.10', '10.0.0.5', 12345, 80, tcp_flags='SA')
        flow.update_with_packet(pkt2)
        
        assert flow.tcp_flags_counts['SYN'] == 2
        assert flow.tcp_flags_counts['ACK'] == 1
        
        # FIN packet
        pkt3 = self.create_packet('10.0.0.5', '192.168.1.10', 80, 12345, tcp_flags='FA')
        flow.update_with_packet(pkt3)
        
        assert flow.tcp_flags_counts['FIN'] == 1
        assert flow.tcp_flags_counts['ACK'] == 2
    
    def test_flow_totals(self):
        """Test total packet and byte calculations."""
        now = time.monotonic()
        ts_utc = datetime.now(timezone.utc).isoformat()
        
        key = FlowKey.from_packet('10.0.0.5', '192.168.1.10', 80, 12345, 'TCP')
        flow = Flow(
            flow_key=key,
            first_seen_utc=ts_utc,
            last_seen_utc=ts_utc,
            first_seen_monotonic=now,
            last_seen_monotonic=now
        )
        
        # Add packets
        for i in range(5):
            pkt = self.create_packet('10.0.0.5', '192.168.1.10', 80, 12345, length=100)
            flow.update_with_packet(pkt)
        
        for i in range(3):
            pkt = self.create_packet('192.168.1.10', '10.0.0.5', 12345, 80, length=200)
            flow.update_with_packet(pkt)
        
        assert flow.get_total_packets() == 8
        assert flow.get_total_bytes() == 1100  # 5*100 + 3*200
