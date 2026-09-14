"""
Passive Windows/Linux TCP port-scan detector and auto-quarantine engine.

Usage:
    python defense\\main.py --adapter "<NPCAP_ADAPTER>" --block
    python defense\\main.py --adapter "<NPCAP_ADAPTER>" --whitelist 192.168.0.1 --block --block-ttl 180
"""

import argparse
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.npcap import Pcap
from common.packet import parse_ipv4_tcp_frame, TCP_ACK, TCP_SYN
from detector import ScanDetector


def main():
    parser = argparse.ArgumentParser(description="Adaptive Multi-Vector TCP Port-Scan Detector")
    parser.add_argument("--adapter", required=True, help="Exact Npcap adapter name")
    parser.add_argument("--threshold", type=int, default=8, help="Fast-window SYN threshold (default: 8)")
    parser.add_argument("--distinct-ports", type=int, default=5, help="Fast-window distinct port threshold (default: 5)")
    parser.add_argument("--window", type=float, default=10.0, help="Fast sliding-window in seconds (default: 10.0)")
    parser.add_argument("--long-window", type=float, default=60.0, help="Slow sliding-window in seconds (default: 60.0)")
    parser.add_argument("--long-threshold", type=int, default=20, help="Slow-window SYN threshold (default: 20)")
    parser.add_argument("--canary-ports", nargs="*", type=int, default=[81], help="Decoy honeyports (default: 81)")
    parser.add_argument("--whitelist", nargs="*", default=[], help="Source IPs to ignore (e.g. gateway)")
    parser.add_argument("--block", action="store_true", help="Opt-in firewall mitigation")
    parser.add_argument("--block-ttl", type=float, default=300.0, help="Auto-release quarantine TTL in seconds (default: 300, 0=never)")
    args = parser.parse_args()

    detector = ScanDetector(
        threshold=args.threshold,
        distinct_ports=args.distinct_ports,
        window=args.window,
        long_window=args.long_window,
        long_threshold=args.long_threshold,
        canary_ports=args.canary_ports,
        whitelist=args.whitelist,
        block=args.block,
        block_ttl=args.block_ttl,
    )

    print("═════════════════════════════════════════════════════════════════")
    print("  ADAPTIVE MULTI-VECTOR PORT-SCAN DETECTOR & DEFENSE ENGINE      ")
    print("═════════════════════════════════════════════════════════════════")
    print(f"  Adapter          : {args.adapter}")
    print(f"  Fast Window      : {args.threshold} SYNs across {args.distinct_ports} ports within {args.window}s")
    print(f"  Slow Window      : {args.long_threshold} SYNs within {args.long_window}s")
    print(f"  Canary Ports     : {args.canary_ports or '(none)'}")
    print(f"  Whitelist        : {args.whitelist or '(none)'}")
    print(f"  Firewall Action  : {'ENABLED (Auto-Quarantine)' if args.block else 'DISABLED (Passive Audit)'}")
    if args.block:
        print(f"  Quarantine TTL   : {args.block_ttl}s auto-release (Self-Healing)")
    print("═════════════════════════════════════════════════════════════════")
    print("\nWaiting for network probes. Press Ctrl+C to stop.\n")

    stop_event = threading.Event()

    def ttl_monitor():
        while not stop_event.is_set():
            if args.block and args.block_ttl > 0:
                detector.release_expired()
            stop_event.wait(1.0)

    monitor_thread = threading.Thread(target=ttl_monitor, daemon=True)
    monitor_thread.start()

    try:
        with Pcap(args.adapter, snaplen=65535, promisc=True, timeout_ms=100) as cap:
            while True:
                raw = cap.recv()

                if raw is None:
                    continue

                info = parse_ipv4_tcp_frame(raw)
                if not info:
                    continue

                flags = info["flags"]
                source = info["src_ip"]
                port = info["dst_port"]

                # 1. Invalid TCP Flag Inspection (First Priority)
                bad_flags, flag_reason = detector.observe_invalid_flags(source, port, flags)
                if bad_flags:
                    print(f"[CRITICAL ALERT] {source:15s} -> {info['dst_ip']}:{port:<5d} | {flag_reason}")
                    if args.block:
                        try:
                            detector.mitigate(source, reason=flag_reason)
                        except RuntimeError as exc:
                            print(f"[MITIGATION ERROR] {exc}")
                    continue

                # 2. SYN Probe Inspection
                if not (flags & TCP_SYN) or (flags & TCP_ACK):
                    continue

                count, unique, suspicious, syn_reason = detector.observe_syn(source, port)

                print(
                    f"SYN {source:15s} -> {info['dst_ip']}:{port:<5d} "
                    f"window_count={count:<3d} distinct_ports={unique:<3d}"
                )

                if suspicious:
                    print(f"[ALERT] {source:15s} | {syn_reason}")
                    if args.block:
                        try:
                            detector.mitigate(source, reason=syn_reason)
                        except RuntimeError as exc:
                            print(f"[MITIGATION ERROR] {exc}")

    except KeyboardInterrupt:
        print("\nStopping detector and cleaning up firewall rules...")
    finally:
        stop_event.set()
        detector.cleanup()
        print("All injected firewall quarantine rules successfully removed.")


if __name__ == "__main__":
    main()