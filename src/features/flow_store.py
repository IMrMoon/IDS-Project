"""Flow storage and management."""

import time
import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone
from .flow_models import Flow, FlowKey, ParsedPacket


logger = logging.getLogger(__name__)


class FlowStore:
    """
    Manages active flows with expiration and eviction.
    
    Maintains flows in memory and expires them based on inactivity timeout.
    Enforces max_active_flows limit via LRU-style eviction.
    """
    
    def __init__(self, inactivity_timeout_seconds: float, max_active_flows: int,
                 retention_max_finalized_flows: int):
        """
        Initialize flow store.
        
        Args:
            inactivity_timeout_seconds: Flow expires after this period of inactivity
            max_active_flows: Maximum number of active flows before eviction
            retention_max_finalized_flows: Maximum finalized flows to retain
        """
        self.inactivity_timeout_seconds = inactivity_timeout_seconds
        self.max_active_flows = max_active_flows
        self.retention_max_finalized_flows = retention_max_finalized_flows
        
        self._active_flows: Dict[FlowKey, Flow] = {}
        self._finalized_flows: List[Flow] = []
        
        # Statistics
        self._stats = {
            'total_flows_created': 0,
            'total_flows_expired': 0,
            'total_flows_evicted': 0,
            'active_flows_count': 0
        }
    
    def process_packet(self, packet: ParsedPacket) -> Optional[Flow]:
        """
        Process a packet and update corresponding flow.
        
        Args:
            packet: Parsed packet to process
            
        Returns:
            The updated flow, or None if packet was dropped due to limits
        """
        # Create canonical flow key
        flow_key = FlowKey.from_packet(
            packet.src_ip, packet.dst_ip,
            packet.src_port, packet.dst_port,
            packet.protocol
        )
        
        # Check if flow exists
        if flow_key in self._active_flows:
            flow = self._active_flows[flow_key]
            flow.update_with_packet(packet)
            return flow
        
        # New flow - check capacity
        if len(self._active_flows) >= self.max_active_flows:
            self._evict_oldest_flow()
        
        # Create new flow
        flow = Flow(
            flow_key=flow_key,
            first_seen_utc=packet.ts_utc,
            last_seen_utc=packet.ts_utc,
            first_seen_monotonic=packet.ts_monotonic,
            last_seen_monotonic=packet.ts_monotonic
        )
        flow.update_with_packet(packet)
        
        self._active_flows[flow_key] = flow
        self._stats['total_flows_created'] += 1
        self._stats['active_flows_count'] = len(self._active_flows)
        
        return flow
    
    def expire_flows(self, now_monotonic: float) -> List[Flow]:
        """
        Expire inactive flows based on timeout.
        
        Args:
            now_monotonic: Current monotonic timestamp
            
        Returns:
            List of expired flows (finalized and ready for detection)
        """
        expired = []
        to_remove = []
        
        for flow_key, flow in self._active_flows.items():
            inactivity = now_monotonic - flow.last_seen_monotonic
            if inactivity >= self.inactivity_timeout_seconds:
                flow.finalize()
                expired.append(flow)
                to_remove.append(flow_key)
                self._stats['total_flows_expired'] += 1
        
        # Remove expired flows
        for flow_key in to_remove:
            del self._active_flows[flow_key]
        
        # Add to finalized flows with retention limit
        self._finalized_flows.extend(expired)
        if len(self._finalized_flows) > self.retention_max_finalized_flows:
            overflow = len(self._finalized_flows) - self.retention_max_finalized_flows
            self._finalized_flows = self._finalized_flows[overflow:]
        
        self._stats['active_flows_count'] = len(self._active_flows)
        
        return expired
    
    def _evict_oldest_flow(self) -> None:
        """
        Evict least-recently-seen flow to make room.
        
        Uses LRU policy based on last_seen_monotonic.
        """
        if not self._active_flows:
            return
        
        # Find flow with oldest last_seen_monotonic
        oldest_key = min(self._active_flows.keys(), 
                        key=lambda k: self._active_flows[k].last_seen_monotonic)
        
        flow = self._active_flows[oldest_key]
        flow.finalize()
        
        # Add to finalized flows
        self._finalized_flows.append(flow)
        if len(self._finalized_flows) > self.retention_max_finalized_flows:
            self._finalized_flows.pop(0)
        
        del self._active_flows[oldest_key]
        
        self._stats['total_flows_evicted'] += 1
        self._stats['active_flows_count'] = len(self._active_flows)
        
        logger.warning(f"Evicted flow due to max_active_flows limit: {oldest_key}")
    
    def get_stats(self) -> Dict:
        """Get flow store statistics."""
        return self._stats.copy()
    
    def get_all_active_flows(self) -> List[Flow]:
        """Get list of all active flows."""
        return list(self._active_flows.values())
    
    def get_finalized_flows(self) -> List[Flow]:
        """Get list of finalized flows."""
        return self._finalized_flows.copy()
