#!/usr/bin/env python3
"""
Traffic profile generator for IDS demo (python-only).

Modes:
  1) train - generate mostly benign traffic for a few minutes (avoid rules as much as possible)
  2) test  - staged scenario: quiet -> medium -> heavy (ends with many HIGH alerts)

Designed for WSL/Linux. Generates traffic that should traverse eth0 by targeting:
  - public HTTPS hosts (443) for benign/medium
  - default gateway (from /proc/net/route) for the heavy "scan" stage (many dst ports)

Prints START/END timestamps (local timezone) for correlation with alerts.jsonl.
"""

from __future__ import annotations

import argparse
import os
import random
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import yaml


DEFAULT_HTTPS_HOSTS = [
    "google.com",
    "github.com",
    "wikipedia.org",
    "stackoverflow.com",
    "ubuntu.com",
    "python.org",
]


def now_local_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get_default_gateway_linux() -> Optional[str]:
    """
    Parse /proc/net/route and return default gateway IPv4 (as dotted quad) if found.
    Works without calling external tools.
    """
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None

    # Fields: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
    for line in lines[1:]:
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        iface, destination, gateway = parts[0], parts[1], parts[2]
        if destination != "00000000":
            continue
        # gateway is little-endian hex
        try:
            g = int(gateway, 16)
        except ValueError:
            continue
        ip = socket.inet_ntoa(g.to_bytes(4, "little"))
        return ip
    return None


def tcp_connect(host: str, port: int, timeout: float = 0.5) -> None:
    """
    Try a TCP connect and close immediately. No prints.
    This creates SYN traffic and a flow attempt.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass


def https_head(host: str, timeout: float = 1.5) -> None:
    """
    Minimal HTTPS HEAD to create realistic benign traffic.
    """
    port = 443
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(s, server_hostname=host)

        req = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"User-Agent: ids-traffic-profile/1.0\r\n\r\n"
        )
        s.sendall(req.encode("ascii", errors="ignore"))
        try:
            s.recv(256)
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass


def udp_burst(dst_ip: str, dst_port: int, count: int, payload_size: int = 64, delay_s: float = 0.0) -> None:
    """
    Fire-and-forget UDP packets. Useful to raise PPS without many TCP handshakes.
    """
    data = os.urandom(max(1, payload_size))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _ in range(count):
            try:
                s.sendto(data, (dst_ip, dst_port))
            except Exception:
                pass
            if delay_s > 0:
                time.sleep(delay_s)
    finally:
        try:
            s.close()
        except Exception:
            pass


@dataclass
class DemoTuning:
    # Derived from config for "safe-ish" and "trigger" rates
    flow_window_s: float
    flow_threshold: int
    pps_window_s: float
    pps_threshold: int
    portscan_unique_ports_threshold: int
    portscan_min_packets_threshold: int
    portscan_window_s: float


def derive_tuning(cfg: dict) -> DemoTuning:
    rules = (cfg.get("rules") or {})
    tv = (rules.get("traffic_volume") or {})
    pps = (tv.get("pps_per_src") or {})
    fr = (tv.get("new_flows_rate") or {})
    ps = (rules.get("port_scan_connect") or {})

    return DemoTuning(
        flow_window_s=float(fr.get("window_seconds", 3)),
        flow_threshold=int(fr.get("threshold_flows_per_window", 15)),
        pps_window_s=float(pps.get("window_seconds", 3)),
        pps_threshold=int(pps.get("threshold", 120)),
        portscan_unique_ports_threshold=int(ps.get("unique_dst_ports_threshold", 3)),
        portscan_min_packets_threshold=int(ps.get("min_packets_threshold", 10)),
        portscan_window_s=float(ps.get("window_seconds", 5)),
    )


def run_train(cfg: dict, duration_s: int) -> None:
    """
    Goal: collect flows for ML training while staying below rule thresholds.
    Strategy:
      - Only HTTPS HEAD to a small set of hosts on port 443 (no multi-port scanning)
      - Pace requests conservatively so flow rate stays below threshold
    """
    tuning = derive_tuning(cfg)

    # Keep below new_flows_rate: threshold flows per window
    # Conservative: aim at ~60% of threshold
    safe_flows_per_window = max(1, int(tuning.flow_threshold * 0.6))
    interval = max(0.15, tuning.flow_window_s / safe_flows_per_window)

    hosts = DEFAULT_HTTPS_HOSTS[:]
    random.shuffle(hosts)

    print(f"[traffic_profile] START {now_local_iso()}")
    print(f"[traffic_profile] mode=train duration={duration_s}s")
    print(f"[traffic_profile] pacing ~1 request every {interval:.2f}s (derived from config)")
    print("[traffic_profile] notes: HTTPS only (443) to avoid port-scan rules")

    t0 = time.time()
    i = 0
    while time.time() - t0 < duration_s:
        host = hosts[i % len(hosts)]
        https_head(host, timeout=2.0)
        i += 1
        time.sleep(interval)

    print(f"[traffic_profile] END   {now_local_iso()}")
    print(f"[traffic_profile] DURATION {time.time() - t0:.1f}s")


def stage_quiet(duration_s: int) -> None:
    """
    Quiet stage: minimal traffic (should produce zero alerts ideally).
    """
    print(f"[traffic_profile] stage=quiet {duration_s}s")
    t0 = time.time()
    while time.time() - t0 < duration_s:
        https_head(random.choice(DEFAULT_HTTPS_HOSTS), timeout=2.0)
        time.sleep(3.0)


def stage_medium(cfg: dict, duration_s: int) -> None:
    """
    Medium stage: mostly MEDIUM alerts from volume/flow-rate, maybe 1-2 HIGH.
    We increase flow creation but not "insane".
    """
    tuning = derive_tuning(cfg)

    # Push near / slightly above flow threshold sometimes
    # Example: in a 3s window threshold=15, do ~18-25 connects per 3s for bursts.
    burst_per_window = max(tuning.flow_threshold + 5, int(tuning.flow_threshold * 1.4))
    interval = max(0.02, tuning.flow_window_s / burst_per_window)

    print(f"[traffic_profile] stage=medium {duration_s}s (interval ~{interval:.3f}s)")
    t0 = time.time()
    while time.time() - t0 < duration_s:
        # Mix: some HTTPS (realistic) + some plain TCP connects to 443
        if random.random() < 0.6:
            https_head(random.choice(DEFAULT_HTTPS_HOSTS), timeout=1.2)
        else:
            tcp_connect(random.choice(DEFAULT_HTTPS_HOSTS), 443, timeout=0.4)
        time.sleep(interval)


def stage_heavy(cfg: dict, duration_s: int) -> None:
    """
    Heavy stage: lots of alerts, mostly HIGH (port scan / syn stealth) + MEDIUM volume.
    Safest deterministic approach on eth0: scan DEFAULT GATEWAY with many dst ports.

    This should generate:
      - port_scan_connect (many unique dst ports quickly)
      - syn_stealth (many SYN without ACK when ports closed)
      - traffic_volume_flow_rate / pps
    """
    gw = get_default_gateway_linux()
    if not gw:
        print("[traffic_profile] ERROR: cannot determine default gateway (needed for heavy stage).")
        print("[traffic_profile] Tip: run this inside WSL/Linux with a default route.")
        return

    tuning = derive_tuning(cfg)

    # We want to exceed unique_dst_ports_threshold quickly.
    # Use a port range wide enough to keep triggering.
    port_max = 250

    # Aggressive pacing
    interval = 0.008  # ~125 ops/s (enough to trip rules)
    udp_every = 40    # every N tcp attempts, send UDP burst

    print(f"[traffic_profile] stage=heavy {duration_s}s target_gateway={gw} ports=1..{port_max} interval={interval}s")
    t0 = time.time()
    p = 1
    ops = 0
    while time.time() - t0 < duration_s:
        tcp_connect(gw, p, timeout=0.15)
        ops += 1
        p += 1
        if p > port_max:
            p = 1

        if ops % udp_every == 0:
            # small UDP burst to increase PPS; port choice not important
            udp_burst(gw, 53, count=30, payload_size=64, delay_s=0.0)

        time.sleep(interval)


def run_test(cfg: dict) -> None:
    """
    Test scenario total ~2-3 minutes:
      - quiet 35s
      - medium 60s (mostly MEDIUM)
      - heavy 45s (mostly HIGH)
    """
    quiet_s = 35
    medium_s = 60
    heavy_s = 45
    total = quiet_s + medium_s + heavy_s

    print(f"[traffic_profile] START {now_local_iso()}")
    print(f"[traffic_profile] mode=test total={total}s")
    print(f"[traffic_profile] stages: quiet={quiet_s}s -> medium={medium_s}s -> heavy={heavy_s}s")

    t0 = time.time()
    stage_quiet(quiet_s)
    stage_medium(cfg, medium_s)
    stage_heavy(cfg, heavy_s)

    print(f"[traffic_profile] END   {now_local_iso()}")
    print(f"[traffic_profile] DURATION {time.time() - t0:.1f}s")


def main() -> int:
    ap = argparse.ArgumentParser(description="IDS traffic profile generator (train/test).")
    ap.add_argument("mode", choices=["train", "test"], help="Traffic mode")
    ap.add_argument("--config", required=True, help="Path to YAML config (e.g., config/config_demo.yaml)")
    ap.add_argument("--duration", type=int, default=180, help="Train duration seconds (train mode only). Default: 180")
    args = ap.parse_args()

    cfg = load_yaml(args.config)

    if args.mode == "train":
        run_train(cfg, duration_s=args.duration)
    else:
        run_test(cfg)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
