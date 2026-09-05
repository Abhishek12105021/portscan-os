import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common.npcap import Pcap
from common.packet import parse_ipv4_tcp_frame, TCP_ACK, TCP_SYN
from detector import ScanDetector


def main():
    parser = argparse.ArgumentParser(
        description="Passive Windows TCP port-scan detector"
    )
    parser.add_argument("--adapter", required=True)
    parser.add_argument("--threshold", type=int, default=8)
    parser.add_argument("--distinct-ports", type=int, default=5)
    parser.add_argument("--window", type=float, default=10.0)
    parser.add_argument("--block", action="store_true",
                        help="Opt-in TCP firewall mitigation")
    args = parser.parse_args()

    if args.threshold < 2:
        parser.error("--threshold must be >= 2")
    if args.distinct_ports < 2:
        parser.error("--distinct-ports must be >= 2")
    if args.window <= 0:
        parser.error("--window must be > 0")

    detector = ScanDetector(
        threshold=args.threshold,
        distinct_ports=args.distinct_ports,
        window=args.window,
        block=args.block,
    )

    print(f"Adapter          : {args.adapter}")
    print(f"SYN threshold    : {args.threshold}")
    print(f"Distinct ports   : {args.distinct_ports}")
    print(f"Window           : {args.window}s")
    print(f"Firewall blocking: {'ON' if args.block else 'OFF'}")
    print("\nWaiting for TCP SYN probes. Ctrl+C to stop.\n")

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

                if not (flags & TCP_SYN) or (flags & TCP_ACK):
                    continue

                source = info["src_ip"]
                port = info["dst_port"]

                count, unique, suspicious = detector.observe_syn(
                    source, port
                )

                print(
                    f"SYN {source:15s} -> "
                    f"{info['dst_ip']}:{port:<5d} "
                    f"window_count={count:<3d} "
                    f"distinct_ports={unique:<3d}"
                )

                if suspicious:
                    print(f"[ALERT] Possible TCP port scan from {source}")
                    if args.block:
                        try:
                            detector.mitigate(source)
                        except RuntimeError as exc:
                            print(f"[MITIGATION ERROR] {exc}")

    except KeyboardInterrupt:
        print("\nStopping detector...")
    finally:
        detector.cleanup()
        print("Created firewall rules have been removed.")


if __name__ == "__main__":
    main()
