"""Flow models for packet aggregation and feature extraction."""

from dataclasses import dataclass, field
from typing import Optional, Dict
from datetime import datetime


@dataclass(frozen=True)
class FlowKey:
    """
    Canonical bi-directional flow identifier.
    
    Endpoints are ordered deterministically so reverse traffic maps to same FlowKey.
    Order: lexicographically by (IP, port) tuples.
    """
    a_ip: str
    b_ip: str
    a_port: Optional[int]
    b_port: Optional[int]
    protocol: str  # TCP, UDP, ICMP, OTHER
    
    @staticmethod
    def from_packet(src_ip: str, dst_ip: str, src_port: Optional[int], 
                    dst_port: Optional[int], protocol: str) -> 'FlowKey':
        """
        Create canonical FlowKey from packet endpoints.
        
        Ensures bidirectional traffic maps to same key by ordering endpoints.
        """
        # Create tuples for comparison
        endpoint_a = (src_ip, src_port if src_port is not None else -1)
        endpoint_b = (dst_ip, dst_port if dst_port is not None else -1)
        
        # Order endpoints canonically (lexicographically)
        if endpoint_a <= endpoint_b:
            return FlowKey(
                a_ip=src_ip,
                b_ip=dst_ip,
                a_port=src_port,
                b_port=dst_port,
                protocol=protocol
            )
        else:
            return FlowKey(
                a_ip=dst_ip,
                b_ip=src_ip,
                a_port=dst_port,
                b_port=src_port,
                protocol=protocol
            )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary representation."""
        return {
            'a_ip': self.a_ip,
            'b_ip': self.b_ip,
            'a_port': self.a_port,
            'b_port': self.b_port,
            'protocol': self.protocol
        }


@dataclass
class ParsedPacket:
    """Parsed packet structure matching parsedPacketSchema."""
    ts_utc: str  # ISO-8601 UTC timestamp
    ts_monotonic: float  # Monotonic timestamp for duration calculations
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str  # TCP, UDP, ICMP, OTHER
    tcp_flags: Optional[str]  # e.g., 'S', 'SA', 'FPU'
    length_bytes: int
    payload_bytes: Optional[bytes] = None


@dataclass
class Flow:
    """
    Flow aggregation with directional counters.
    
    Direction is relative to canonical endpoint ordering:
    - fwd: traffic from endpoint A to endpoint B
    - rev: traffic from endpoint B to endpoint A
    """
    flow_key: FlowKey
    first_seen_utc: str
    last_seen_utc: str
    first_seen_monotonic: float
    last_seen_monotonic: float
    
    # Directional counters
    packets_fwd: int = 0
    packets_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0
    
    # TCP flags tracking
    tcp_flags_counts: Dict[str, int] = field(default_factory=lambda: {
        'SYN': 0, 'ACK': 0, 'FIN': 0, 'RST': 0, 'PSH': 0, 'URG': 0
    })
    
    # Inter-arrival time tracking (for anomaly detection)
    _interarrival_times: list = field(default_factory=list, repr=False)
    interarrival_mean_ms: Optional[float] = None
    interarrival_var_ms: Optional[float] = None
    
    def update_with_packet(self, packet: ParsedPacket) -> None:
        """
        Update flow statistics with a new packet.
        
        Determines direction and updates appropriate counters.
        """
        # Update timestamps
        self.last_seen_utc = packet.ts_utc
        self.last_seen_monotonic = packet.ts_monotonic
        
        # Determine direction: is this packet A->B (fwd) or B->A (rev)?
        is_forward = (packet.src_ip == self.flow_key.a_ip and 
                     packet.src_port == self.flow_key.a_port)
        
        if is_forward:
            self.packets_fwd += 1
            self.bytes_fwd += packet.length_bytes
        else:
            self.packets_rev += 1
            self.bytes_rev += packet.length_bytes
        
        # Track TCP flags
        if packet.tcp_flags:
            for flag in ['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']:
                if flag[0] in packet.tcp_flags:  # Check first letter
                    self.tcp_flags_counts[flag] += 1
        
        # Track inter-arrival times for statistics
        self._interarrival_times.append(packet.ts_monotonic)
    
    def finalize(self) -> None:
        """
        Finalize flow statistics.
        
        Computes inter-arrival statistics when flow expires.
        """
        # Compute inter-arrival statistics
        if len(self._interarrival_times) >= 2:
            deltas = []
            for i in range(1, len(self._interarrival_times)):
                delta_ms = (self._interarrival_times[i] - self._interarrival_times[i-1]) * 1000
                deltas.append(delta_ms)
            
            if deltas:
                self.interarrival_mean_ms = sum(deltas) / len(deltas)
                
                if len(deltas) >= 2:
                    mean = self.interarrival_mean_ms
                    variance = sum((x - mean) ** 2 for x in deltas) / len(deltas)
                    self.interarrival_var_ms = variance
    
    def get_total_packets(self) -> int:
        """Get total packet count."""
        return self.packets_fwd + self.packets_rev
    
    def get_total_bytes(self) -> int:
        """Get total byte count."""
        return self.bytes_fwd + self.bytes_rev
    
    def get_duration_seconds(self) -> float:
        """Get flow duration in seconds."""
        return max(0.0, self.last_seen_monotonic - self.first_seen_monotonic)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary representation."""
        return {
            'flow_key': self.flow_key.to_dict(),
            'first_seen_utc': self.first_seen_utc,
            'last_seen_utc': self.last_seen_utc,
            'first_seen_monotonic': self.first_seen_monotonic,
            'last_seen_monotonic': self.last_seen_monotonic,
            'packets_fwd': self.packets_fwd,
            'packets_rev': self.packets_rev,
            'bytes_fwd': self.bytes_fwd,
            'bytes_rev': self.bytes_rev,
            'tcp_flags_counts': self.tcp_flags_counts,
            'interarrival_mean_ms': self.interarrival_mean_ms,
            'interarrival_var_ms': self.interarrival_var_ms
        }
