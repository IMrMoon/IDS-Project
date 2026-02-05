"""Network packet capture using Scapy."""

import logging
import threading
import time
from datetime import datetime, timezone
from queue import Queue, Full
from typing import Optional, Callable
from scapy.all import sniff, conf, IP, IPv6, TCP, UDP, ICMP
from ..features.flow_models import ParsedPacket


logger = logging.getLogger(__name__)


class PacketSniffer:
    """
    Captures network packets using Scapy.
    
    Uses store=0 mode with callback to avoid unbounded memory growth.
    Packets are pushed to a bounded thread-safe queue for processing.
    """
    
    def __init__(self, interface: str, promiscuous: bool, bpf_filter: Optional[str],
                 packet_queue: Queue, parse_payload_bytes_limit: int):
        """
        Initialize packet sniffer.
        
        Args:
            interface: Network interface to capture on (e.g., 'eth0')
            promiscuous: Whether to use promiscuous mode
            bpf_filter: Optional BPF filter string
            packet_queue: Bounded queue to push parsed packets
            parse_payload_bytes_limit: Maximum payload bytes to extract
        """
        self.interface = interface
        self.promiscuous = promiscuous
        self.bpf_filter = bpf_filter
        self.packet_queue = packet_queue
        self.parse_payload_bytes_limit = parse_payload_bytes_limit
        
        self._stop_event = threading.Event()
        self._sniffer_thread: Optional[threading.Thread] = None
        
        # Statistics
        self._stats = {
            'packets_captured': 0,
            'packets_dropped': 0,
            'packets_parsed': 0
        }
        self._stats_lock = threading.Lock()
    
    def start(self) -> None:
        """Start packet capture in background thread."""
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            logger.warning("Sniffer already running")
            return
        
        self._stop_event.clear()
        self._sniffer_thread = threading.Thread(target=self._run_sniffer, daemon=True)
        self._sniffer_thread.start()
        logger.info(f"Packet sniffer started on interface {self.interface}")
    
    def stop(self) -> None:
        """Stop packet capture gracefully."""
        if not self._sniffer_thread or not self._sniffer_thread.is_alive():
            logger.warning("Sniffer not running")
            return
        
        logger.info("Stopping packet sniffer...")
        self._stop_event.set()
        
        # Wait for sniffer thread to finish (with timeout)
        self._sniffer_thread.join(timeout=5.0)
        
        if self._sniffer_thread.is_alive():
            logger.warning("Sniffer thread did not stop gracefully")
        else:
            logger.info("Packet sniffer stopped")
    
    def _run_sniffer(self) -> None:
        """
        Run Scapy sniffer loop.
        
        Uses store=0 to avoid memory buildup and prn callback for processing.
        """
        try:
            # Configure Scapy
            conf.verb = 0  # Quiet mode
            
            # Build sniff parameters
            sniff_kwargs = {
                'iface': self.interface,
                'prn': self._packet_callback,
                'store': 0,  # Don't store packets in memory
                'stop_filter': lambda _: self._stop_event.is_set()
            }
            
            if self.bpf_filter:
                sniff_kwargs['filter'] = self.bpf_filter
            
            if self.promiscuous:
                sniff_kwargs['promisc'] = True
            
            # Start sniffing
            logger.info(f"Starting Scapy sniff on {self.interface}")
            
            # Run sniff in short time slices so we can stop promptly even with no traffic.
            sniff_kwargs.pop('stop_filter', None)  # stop_filter only triggers when packets arrive
            sniff_kwargs['timeout'] = 1
            
            while not self._stop_event.is_set():
                sniff(**sniff_kwargs)
            
        except PermissionError:
            logger.error("Permission denied - need root/CAP_NET_RAW to capture packets")
        except Exception as e:
            logger.error(f"Sniffer error: {e}", exc_info=True)
    
    def _packet_callback(self, packet) -> None:
        """
        Callback for each captured packet.
        
        Parses packet and pushes to queue. Drops if queue is full.
        """
        with self._stats_lock:
            self._stats['packets_captured'] += 1
        
        try:
            parsed = self._parse_packet(packet)
            if parsed:
                try:
                    # Non-blocking put - drop if queue is full
                    self.packet_queue.put_nowait(parsed)
                    with self._stats_lock:
                        self._stats['packets_parsed'] += 1
                except Full:
                    with self._stats_lock:
                        self._stats['packets_dropped'] += 1
                    # Note: Don't log every drop to avoid flooding logs
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
    
    def _parse_packet(self, packet) -> Optional[ParsedPacket]:
        """
        Parse Scapy packet into ParsedPacket structure.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            ParsedPacket or None if packet can't be parsed
        """
        try:
            # Get timestamps
            ts_utc = datetime.now(timezone.utc).isoformat()
            ts_monotonic = time.monotonic()
            
            # Check for IP layer
            if IP in packet:
                ip = packet[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                length_bytes = len(packet)
            elif IPv6 in packet:
                ip = packet[IPv6]
                src_ip = ip.src
                dst_ip = ip.dst
                length_bytes = len(packet)
            else:
                # Non-IP packet - skip
                return None
            
            # Initialize
            src_port = None
            dst_port = None
            protocol = "OTHER"
            tcp_flags = None
            payload_bytes = None
            
            # Parse transport layer
            if TCP in packet:
                tcp = packet[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                protocol = "TCP"
                
                # Parse TCP flags
                flags = []
                if tcp.flags.S:
                    flags.append('S')
                if tcp.flags.A:
                    flags.append('A')
                if tcp.flags.F:
                    flags.append('F')
                if tcp.flags.R:
                    flags.append('R')
                if tcp.flags.P:
                    flags.append('P')
                if tcp.flags.U:
                    flags.append('U')
                tcp_flags = ''.join(flags) if flags else None
                
                # Extract payload if available
                if hasattr(tcp, 'payload') and tcp.payload:
                    payload = bytes(tcp.payload)[:self.parse_payload_bytes_limit]
                    payload_bytes = payload if payload else None
                    
            elif UDP in packet:
                udp = packet[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                protocol = "UDP"
                
                # Extract payload if available
                if hasattr(udp, 'payload') and udp.payload:
                    payload = bytes(udp.payload)[:self.parse_payload_bytes_limit]
                    payload_bytes = payload if payload else None
                    
            elif ICMP in packet:
                protocol = "ICMP"
            
            return ParsedPacket(
                ts_utc=ts_utc,
                ts_monotonic=ts_monotonic,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                tcp_flags=tcp_flags,
                length_bytes=length_bytes,
                payload_bytes=payload_bytes
            )
            
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None
    
    def get_stats(self) -> dict:
        """Get sniffer statistics."""
        with self._stats_lock:
            return self._stats.copy()
