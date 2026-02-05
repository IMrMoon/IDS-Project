"""Main orchestration module for IDS."""

import logging
import signal
import sys
import time
import threading
from queue import Queue, Empty
from pathlib import Path
from datetime import datetime, timezone
from colorama import Fore, Style, init as colorama_init

from .utils.config import Config
from .sniffer.sniffer import PacketSniffer
from .features.flow_store import FlowStore
from .detection.rule_engine import RuleEngine
from .detection.anomaly_engine import AnomalyEngine
from .alerts.alerts import AlertSink, Alert


# Initialize colorama for cross-platform colored output
colorama_init(autoreset=True)

logger = logging.getLogger(__name__)


class IDSMain:
    """
    Main IDS orchestrator.
    
    Coordinates packet capture, flow management, detection, and alerting.
    """
    
    def __init__(self, config: Config, disable_ml: bool = False):
        """
        Initialize IDS components.
        
        Args:
            config: Configuration object
            disable_ml: Force disable ML even if enabled in config
        """
        self.config = config
        self.running = False
        self.stop_event = threading.Event()
        
        # Setup logging
        self._setup_logging()
        
        # Create packet queue
        self.packet_queue = Queue(maxsize=config.queue_maxsize)
        
        # Initialize components
        self.sniffer = PacketSniffer(
            interface=config.interface,
            promiscuous=config.promiscuous,
            bpf_filter=config.bpf_filter,
            packet_queue=self.packet_queue,
            parse_payload_bytes_limit=config.parse_payload_bytes_limit
        )
        
        self.flow_store = FlowStore(
            inactivity_timeout_seconds=config.inactivity_timeout_seconds,
            max_active_flows=config.max_active_flows,
            retention_max_finalized_flows=config.retention_max_finalized_flows
        )
        
        self.rule_engine = RuleEngine(config.rules)
        
        # Initialize ML engine (respect disable flag)
        ml_config = config.get_raw()['ml']
        if disable_ml:
            ml_config = ml_config.copy()
            ml_config['enabled'] = False
        self.anomaly_engine = AnomalyEngine(ml_config)
        
        self.alert_sink = AlertSink(
            jsonl_path=config.alerts_jsonl_path,
            keep_last_n=config.alerts_retention['keep_last_n'],
            keep_days=config.alerts_retention['keep_days']
        )
        
        # Worker threads
        self.worker_threads = []
        
        # Statistics
        self.stats = {
            'start_time': None,
            'packets_processed': 0,
            'flows_created': 0,
            'flows_expired': 0,
            'alerts_generated': 0
        }
        self.stats_lock = threading.Lock()
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _setup_logging(self) -> None:
        """Setup logging configuration."""
        # Ensure log directory exists
        Path('logs').mkdir(exist_ok=True)
        
        # Setup root logger
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/system.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Setup alerts logger
        alerts_logger = logging.getLogger('alerts')
        alerts_handler = logging.FileHandler('logs/alerts.log')
        alerts_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
        alerts_logger.addHandler(alerts_handler)
    
    def run(self) -> None:
        """Run the IDS."""
        logger.info("Starting IDS...")
        self.running = True
        
        with self.stats_lock:
            self.stats['start_time'] = time.time()
        
        # Start sniffer
        self.sniffer.start()
        
        # Start worker threads
        num_workers = 2  # One for packet processing, one for flow expiration
        for i in range(num_workers):
            if i == 0:
                worker = threading.Thread(target=self._packet_worker, daemon=True)
            else:
                worker = threading.Thread(target=self._expiration_worker, daemon=True)
            worker.start()
            self.worker_threads.append(worker)
        
        # Start stats reporter
        stats_thread = threading.Thread(target=self._stats_reporter, daemon=True)
        stats_thread.start()
        self.worker_threads.append(stats_thread)
        
        logger.info("IDS running. Press Ctrl+C to stop.")
        
        # Wait for stop signal
        try:
            while not self.stop_event.is_set():
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        
        self.stop()
    
    def stop(self) -> None:
        """Stop the IDS gracefully."""
        if not self.running:
            return
        
        logger.info("Stopping IDS...")
        self.running = False
        self.stop_event.set()
        
        # Stop sniffer
        self.sniffer.stop()
        
        # Wait for worker threads
        for worker in self.worker_threads:
            worker.join(timeout=2.0)
        
        # Print final stats
        self._print_final_stats()
        
        logger.info("IDS stopped")
    
    def _packet_worker(self) -> None:
        """Worker thread for processing packets from queue."""
        while not self.stop_event.is_set():
            try:
                # Get packet from queue with timeout
                packet = self.packet_queue.get(timeout=0.5)
                
                # Process packet
                flow = self.flow_store.process_packet(packet)
                
                if flow:
                    # Update stats
                    with self.stats_lock:
                        self.stats['packets_processed'] += 1
                    
                    # Run packet-level rules
                    alerts = self.rule_engine.evaluate_packet(packet, flow)
                    for alert in alerts:
                        self._emit_alert(alert)
                    
                    # Check flow creation rate
                    flow_alerts = self.rule_engine.evaluate_flow_creation(time.monotonic())
                    for alert in flow_alerts:
                        self._emit_alert(alert)
                
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error in packet worker: {e}", exc_info=True)
    
    def _expiration_worker(self) -> None:
        """Worker thread for expiring flows and running detection."""
        while not self.stop_event.is_set():
            try:
                # Sleep between checks
                time.sleep(1.0)
                
                # Expire flows
                now = time.monotonic()
                expired_flows = self.flow_store.expire_flows(now)
                
                if expired_flows:
                    with self.stats_lock:
                        self.stats['flows_expired'] += len(expired_flows)
                    
                    # Process each expired flow
                    for flow in expired_flows:
                        # Run rule-based detection
                        rule_alerts = self.rule_engine.evaluate_flow(flow, now)
                        for alert in rule_alerts:
                            self._emit_alert(alert)
                        
                        # Run ML-based detection
                        if self.anomaly_engine.enabled:
                            feature_row = self.anomaly_engine.extract_features(flow)
                            ml_alert = self.anomaly_engine.evaluate(feature_row, flow)
                            if ml_alert:
                                self._emit_alert(ml_alert)
                
            except Exception as e:
                logger.error(f"Error in expiration worker: {e}", exc_info=True)
    
    def _stats_reporter(self) -> None:
        """Periodically report statistics."""
        while not self.stop_event.is_set():
            try:
                time.sleep(10.0)  # Report every 10 seconds
                
                sniffer_stats = self.sniffer.get_stats()
                flow_stats = self.flow_store.get_stats()
                
                with self.stats_lock:
                    packets = self.stats['packets_processed']
                    alerts = self.stats['alerts_generated']
                
                logger.info(
                    f"Stats: "
                    f"Captured={sniffer_stats['packets_captured']}, "
                    f"Processed={packets}, "
                    f"Dropped={sniffer_stats['packets_dropped']}, "
                    f"ActiveFlows={flow_stats['active_flows_count']}, "
                    f"Alerts={alerts}"
                )
                
            except Exception as e:
                logger.error(f"Error in stats reporter: {e}")
    
    def _emit_alert(self, alert: Alert) -> None:
        """
        Emit an alert to all outputs.
        
        Args:
            alert: Alert to emit
        """
        # Update stats
        with self.stats_lock:
            self.stats['alerts_generated'] += 1
        
        # Save to alert sink
        self.alert_sink.emit(alert)
        
        # Log to alerts log
        alerts_logger = logging.getLogger('alerts')
        alerts_logger.info(f"{alert.severity} - {alert.description}")
        
        # Print to console with color
        self._print_alert(alert)
    
    def _print_alert(self, alert: Alert) -> None:
        """Print alert to console with color coding."""
        # Color by severity
        if alert.severity == 'CRITICAL':
            color = Fore.RED + Style.BRIGHT
        elif alert.severity == 'HIGH':
            color = Fore.RED
        elif alert.severity == 'MEDIUM':
            color = Fore.YELLOW
        else:
            color = Fore.CYAN
        
        print(f"{color}[ALERT] {alert.severity} - {alert.rule_id}")
        print(f"  {alert.description}")
        print(f"  {alert.src['ip']}:{alert.src.get('port', '*')} -> {alert.dst['ip']}:{alert.dst.get('port', '*')}")
        print(f"  Tags: {', '.join(alert.tags)}")
        print(Style.RESET_ALL)
    
    def _print_final_stats(self) -> None:
        """Print final statistics on shutdown."""
        sniffer_stats = self.sniffer.get_stats()
        flow_stats = self.flow_store.get_stats()
        
        with self.stats_lock:
            runtime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
            
            print("\n" + "="*60)
            print("FINAL STATISTICS")
            print("="*60)
            print(f"Runtime: {runtime:.1f} seconds")
            print(f"Packets captured: {sniffer_stats['packets_captured']}")
            print(f"Packets processed: {self.stats['packets_processed']}")
            print(f"Packets dropped: {sniffer_stats['packets_dropped']}")
            print(f"Flows created: {flow_stats['total_flows_created']}")
            print(f"Flows expired: {flow_stats['total_flows_expired']}")
            print(f"Flows evicted: {flow_stats['total_flows_evicted']}")
            print(f"Alerts generated: {self.stats['alerts_generated']}")
            print("="*60 + "\n")
    
    def _signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}")
        self.stop_event.set()
