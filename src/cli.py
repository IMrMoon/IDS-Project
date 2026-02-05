"""Command-line interface for IDS."""

import sys
import argparse
import logging
import time
import csv
from pathlib import Path
from datetime import datetime, timezone
from queue import Queue

from .utils.config import load_config
from .main import IDSMain
from .sniffer.sniffer import PacketSniffer
from .features.flow_store import FlowStore
from .detection.anomaly_engine import AnomalyEngine
from .alerts.alerts import AlertSink
from .dashboard.dashboard_app import run_dashboard


logger = logging.getLogger(__name__)


def cmd_run(args) -> int:
    """
    Run the IDS.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code
    """
    try:
        # Load config
        config = load_config(args.config)
        
        # Override config with CLI args
        if args.interface:
            config.interface = args.interface
        
        # Check for root/CAP_NET_RAW permissions
        import os
        if os.geteuid() != 0:
            try:
                # Try to check capabilities
                import subprocess
                result = subprocess.run(
                    ['getcap', sys.executable],
                    capture_output=True,
                    text=True
                )
                if 'cap_net_raw' not in result.stdout.lower():
                    print("ERROR: Insufficient permissions to capture packets.")
                    print("Run as root or grant CAP_NET_RAW capability:")
                    print(f"  sudo setcap cap_net_raw=eip {sys.executable}")
                    return 1
            except FileNotFoundError:
                print("WARNING: Unable to check capabilities. May need root permissions.")
        
        # Create and run IDS
        ids = IDSMain(config, disable_ml=args.no_ml)
        ids.run()
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 0
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"ERROR: Configuration error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1


def cmd_stats(args) -> int:
    """
    Show statistics.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code
    """
    try:
        config = load_config(args.config)
        
        # Try to load alert sink to get alert count
        alert_sink = AlertSink(
            jsonl_path=config.alerts_jsonl_path,
            keep_last_n=config.alerts_retention['keep_last_n'],
            keep_days=config.alerts_retention['keep_days']
        )
        
        print("\n" + "="*60)
        print("IDS STATISTICS")
        print("="*60)
        print(f"Total alerts: {alert_sink.get_count()}")
        print("="*60 + "\n")
        
        return 0
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_alerts(args) -> int:
    """
    View recent alerts.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code
    """
    try:
        config = load_config(args.config)
        
        alert_sink = AlertSink(
            jsonl_path=config.alerts_jsonl_path,
            keep_last_n=config.alerts_retention['keep_last_n'],
            keep_days=config.alerts_retention['keep_days']
        )
        
        alerts = alert_sink.load_recent(limit=args.tail)
        
        if not alerts:
            print("No alerts found.")
            return 0
        
        print(f"\nShowing last {len(alerts)} alerts:\n")
        print("="*80)
        
        for alert in alerts:
            print(f"[{alert.timestamp_utc}] {alert.severity} - {alert.rule_id}")
            print(f"  {alert.description}")
            print(f"  {alert.src['ip']}:{alert.src.get('port', '*')} -> {alert.dst['ip']}:{alert.dst.get('port', '*')}")
            print(f"  Tags: {', '.join(alert.tags)}")
            print("-"*80)
        
        return 0
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_export(args) -> int:
    """
    Export alerts to CSV.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code
    """
    try:
        config = load_config(args.config)
        
        alert_sink = AlertSink(
            jsonl_path=config.alerts_jsonl_path,
            keep_last_n=config.alerts_retention['keep_last_n'],
            keep_days=config.alerts_retention['keep_days']
        )
        
        alert_sink.export_csv(args.out)
        print(f"Alerts exported to {args.out}")
        
        return 0
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_train(args) -> int:
    """
    Train ML model from benign traffic.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Exit code
    """
    try:
        # Load config
        config = load_config(args.config)
        
        # Override training duration if provided
        duration = args.duration if args.duration else config.ml_training['duration_seconds']
        max_flows = args.max_flows if args.max_flows else config.ml_training['max_flows']
        
        print(f"Starting training mode for {duration} seconds...")
        print(f"Will collect up to {max_flows} flows")
        print("Ensure only BENIGN traffic is present on the network!")
        print()
        
        # Setup packet capture
        packet_queue = Queue(maxsize=config.queue_maxsize)
        
        sniffer = PacketSniffer(
            interface=config.interface,
            promiscuous=config.promiscuous,
            bpf_filter=config.bpf_filter,
            packet_queue=packet_queue,
            parse_payload_bytes_limit=config.parse_payload_bytes_limit
        )
        
        flow_store = FlowStore(
            inactivity_timeout_seconds=config.inactivity_timeout_seconds,
            max_active_flows=config.max_active_flows,
            retention_max_finalized_flows=max_flows
        )
        
        anomaly_engine = AnomalyEngine(config.get_raw()['ml'])
        
        # Start capture
        sniffer.start()
        
        start_time = time.time()
        collected_flows = []
        
        try:
            while time.time() - start_time < duration and len(collected_flows) < max_flows:
                # Process packets
                try:
                    packet = packet_queue.get(timeout=0.5)
                    flow_store.process_packet(packet)
                except:
                    pass
                
                # Expire flows and collect them
                expired = flow_store.expire_flows(time.monotonic())
                collected_flows.extend(expired)
                
                # Progress update
                if int(time.time() - start_time) % 10 == 0:
                    print(f"Collected {len(collected_flows)} flows...", end='\r')
        
        except KeyboardInterrupt:
            print("\nTraining interrupted by user")
        
        finally:
            sniffer.stop()
        
        print(f"\nCollected {len(collected_flows)} flows")
        
        if len(collected_flows) < 10:
            print("ERROR: Not enough flows collected for training (need at least 10)")
            return 1
        
        # Extract features
        print("Extracting features...")
        feature_rows = []
        for flow in collected_flows:
            features = anomaly_engine.extract_features(flow)
            feature_rows.append(features)
        
        # Save training dataset
        dataset_path = config.ml_training['output_dataset_path']
        Path(dataset_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(dataset_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(config.ml_feature_list)
            writer.writerows(feature_rows)
        
        print(f"Saved training dataset to {dataset_path}")
        
        # Train model
        print("Training Isolation Forest model...")
        anomaly_engine.train_from_feature_rows(feature_rows)
        
        print("Training complete!")
        print(f"Model saved to {config.ml_model_path}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Training error: {e}", exc_info=True)
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_dashboard(args) -> int:
    """
    Launch the IDS dashboard.

    This command starts the Flask dashboard server which displays
    real‑time alerts and summary statistics.  It reads the same
    configuration file used by the rest of the IDS to determine where
    alerts are stored.  The dashboard is read‑only and does not modify
    any IDS files.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (always 0 unless an exception occurs)
    """
    try:
        # Use provided configuration path or default
        config_path = args.config if args.config else 'config/config.yaml'
        # Bind host and port
        host = args.host
        port = args.port
        print(f"Starting dashboard at http://{host}:{port} ...")
        run_dashboard(config_path=config_path, host=host, port=port, debug=args.debug)
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def main() -> int:
    """
    Main CLI entry point.
    
    Returns:
        Exit code
    """
    parser = argparse.ArgumentParser(
        description='Simple IDS - Network Intrusion Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Run command
    run_parser = subparsers.add_parser('run', help='Start IDS')
    run_parser.add_argument('--config', default='config/config.yaml', help='Configuration file path')
    run_parser.add_argument('--interface', help='Network interface (overrides config)')
    run_parser.add_argument('--no-ml', action='store_true', help='Disable ML detection')
    run_parser.set_defaults(func=cmd_run)
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show statistics')
    stats_parser.add_argument('--config', default='config/config.yaml', help='Configuration file path')
    stats_parser.set_defaults(func=cmd_stats)
    
    # Alerts command
    alerts_parser = subparsers.add_parser('alerts', help='View recent alerts')
    alerts_parser.add_argument('--config', default='config/config.yaml', help='Configuration file path')
    alerts_parser.add_argument('--tail', type=int, default=20, help='Number of recent alerts to show')
    alerts_parser.set_defaults(func=cmd_alerts)
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export alerts to CSV')
    export_parser.add_argument('--config', default='config/config.yaml', help='Configuration file path')
    export_parser.add_argument('--out', required=True, help='Output CSV file path')
    export_parser.set_defaults(func=cmd_export)
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train ML model')
    train_parser.add_argument('--config', default='config/config.yaml', help='Configuration file path')
    train_parser.add_argument('--duration', type=int, help='Training duration in seconds')
    train_parser.add_argument('--max-flows', type=int, help='Maximum flows to collect')
    train_parser.set_defaults(func=cmd_train)

    # Dashboard command
    dash_parser = subparsers.add_parser('dashboard', help='Run the web dashboard')
    dash_parser.add_argument('--config', default='config/config.yaml', help='Configuration file path')
    dash_parser.add_argument('--host', default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
    dash_parser.add_argument('--port', type=int, default=5000, help='Port to bind (default: 5000)')
    dash_parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    dash_parser.set_defaults(func=cmd_dashboard)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Execute command
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
