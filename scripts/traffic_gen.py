#!/usr/bin/env python3
"""
Traffic generator for IDS demo/testing.

Modes:
- benign: mostly normal web requests + light UDP/DNS-like traffic
- noisy: higher rate requests to generate many flows quickly
- scan_local: TCP connect "scan" ONLY against localhost (safe) to trigger port-scan rules

Designed to be run in a separate terminal while IDS is running.
"""

from __future__ import annotations

import argparse
import random
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlparse
from datetime import datetime


DEFAULT_URLS = [
    "https://google.com/",
    "https://github.com/",
    "https://wikipedia.org/",
    "https://stackoverflow.com/",
    "https://ubuntu.com/",
    "https://python.org/",
]


def http_head(host: str, port: int, path: str, use_tls: bool, timeout: float) -> None:
    """Perform a minimal HTTP HEAD request."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        if use_tls:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=host)

        req = f"HEAD {path or '/'} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: ids-traffic-gen/1.0\r\n\r\n"
        s.sendall(req.encode("ascii", errors="ignore"))
        # read a little (not required, but makes it more "real")
        try:
            s.recv(256)
        except Exception:
            pass
    except Exception:
        # Intentionally ignore failures to keep generator robust
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass


def udp_burst(dst_ip: str, dst_port: int, count: int, timeout: float) -> None:
    """Send a small burst of UDP packets (DNS-like)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00example\x03com\x00\x00\x01\x00\x01"
    try:
        for _ in range(count):
            try:
                s.sendto(payload, (dst_ip, dst_port))
            except Exception:
                pass
    finally:
        try:
            s.close()
        except Exception:
            pass


def parse_url(u: str) -> tuple[str, int, str, bool]:
    p = urlparse(u)
    use_tls = (p.scheme == "https")
    host = p.hostname or ""
    port = p.port or (443 if use_tls else 80)
    path = p.path or "/"
    return host, port, path, use_tls


def worker_http(stop_at: float, urls: list[str], intensity_sleep: tuple[float, float], timeout: float) -> None:
    while time.time() < stop_at:
        u = random.choice(urls)
        host, port, path, use_tls = parse_url(u)
        if host:
            http_head(host, port, path, use_tls, timeout)
        time.sleep(random.uniform(*intensity_sleep))


def benign(duration: int, threads: int, timeout: float) -> None:
    stop_at = time.time() + duration
    urls = DEFAULT_URLS

    # Light background UDP (optional, small)
    def udp_thread():
        while time.time() < stop_at:
            # 8.8.8.8:53 is common; if blocked, it's fine
            udp_burst("8.8.8.8", 53, count=1, timeout=timeout)
            time.sleep(1.0)

    t_udp = threading.Thread(target=udp_thread, daemon=True)
    t_udp.start()

    # HTTP(S) at a gentle pace
    workers = []
    for _ in range(max(1, threads)):
        t = threading.Thread(
            target=worker_http,
            args=(stop_at, urls, (0.25, 0.75), timeout),
            daemon=True,
        )
        workers.append(t)
        t.start()

    for t in workers:
        t.join()


def noisy(duration: int, threads: int, timeout: float) -> None:
    stop_at = time.time() + duration
    # Add both http and https variants to increase flow variety
    urls = []
    for u in DEFAULT_URLS:
        urls.append(u)
        pu = urlparse(u)
        if pu.scheme == "https":
            urls.append("http://" + (pu.hostname or "") + "/")
        else:
            urls.append("https://" + (pu.hostname or "") + "/")

    # More UDP bursts
    def udp_thread():
        while time.time() < stop_at:
            udp_burst("8.8.8.8", 53, count=3, timeout=timeout)
            time.sleep(0.5)

    t_udp = threading.Thread(target=udp_thread, daemon=True)
    t_udp.start()

    workers = []
    for _ in range(max(2, threads)):
        t = threading.Thread(
            target=worker_http,
            args=(stop_at, urls, (0.02, 0.10), timeout),
            daemon=True,
        )
        workers.append(t)
        t.start()

    for t in workers:
        t.join()


def scan_local(duration: int, ports: int, timeout: float) -> None:
    """
    TCP connect attempts to many localhost ports in a short window.
    This is SAFE (localhost only) and triggers port-scan style rules.
    """
    stop_at = time.time() + duration
    port_list = list(range(1, ports + 1))
    random.shuffle(port_list)

    while time.time() < stop_at:
        for p in port_list:
            if time.time() >= stop_at:
                break
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect(("127.0.0.1", p))
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        # small pause between sweeps
        time.sleep(0.2)


def main() -> int:
    ap = argparse.ArgumentParser(description="IDS traffic generator (benign/noisy/scan_local)")
    ap.add_argument("mode", choices=["benign", "noisy", "scan_local"], help="Traffic mode")
    ap.add_argument("--duration", type=int, default=20, help="Duration in seconds")
    ap.add_argument("--threads", type=int, default=4, help="HTTP worker threads (benign/noisy)")
    ap.add_argument("--timeout", type=float, default=2.0, help="Socket timeout seconds")
    ap.add_argument("--ports", type=int, default=50, help="Number of localhost ports to try (scan_local)")
    args = ap.parse_args()

    start_ts = datetime.now().astimezone()
    print(f"[traffic_gen] START {start_ts.isoformat()}")
    print(f"[traffic_gen] mode={args.mode} duration={args.duration}s")

    if args.mode in ("benign", "noisy"):
        print(f"[traffic_gen] threads={args.threads}")
    if args.mode == "scan_local":
        print(f"[traffic_gen] localhost ports=1..{args.ports} (safe)")

    try:
        if args.mode == "benign":
            benign(args.duration, args.threads, args.timeout)
        elif args.mode == "noisy":
            noisy(args.duration, args.threads, args.timeout)
        else:
            scan_local(args.duration, args.ports, args.timeout)
    except KeyboardInterrupt:
        print("\n[traffic_gen] interrupted")

    end_ts = datetime.now().astimezone()
    duration = (end_ts - start_ts).total_seconds()

    print(f"[traffic_gen] END   {end_ts.isoformat()}")
    print(f"[traffic_gen] DURATION {duration:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
