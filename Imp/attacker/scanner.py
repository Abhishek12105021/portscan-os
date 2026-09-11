import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import argparse
import ipaddress
import random
import time

from common.packet import (
    build_syn_frame, parse_ipv4_tcp_frame, TCP_ACK, TCP_RST, TCP_SYN,
    STANDARD_SYN_OPTIONS,
)
from common.npcap import Pcap, local_ipv4_for_target, local_mac_for_ip, arp_resolve
from fingerprint import fingerprint


MAX_PROBES = 50
MIN_DELAY = 0.2


def scan(args):
    target_ip = ipaddress.ip_address(args.target)
    if target_ip.version != 4 or not target_ip.is_private:
        raise SystemExit("Safety limit: target must be a private IPv4 address.")
    if len(args.ports) > MAX_PROBES:
        raise SystemExit(f"Safety limit: at most {MAX_PROBES} ports per run.")
    if args.source_port + len(args.ports) - 1 > 65535:
        raise SystemExit("Source port range exceeds 65535.")
    if args.delay < MIN_DELAY:
        raise SystemExit(f"Safety limit: --delay must be >= {MIN_DELAY}s.")

    local_ip = local_ipv4_for_target(args.target)
    src_mac = local_mac_for_ip(local_ip)
    dst_mac = arp_resolve(args.target, local_ip)

    print(f"Attacker IP : {local_ip}")
    print(f"Attacker MAC: {src_mac}")
    print(f"Target IP   : {args.target}")
    print(f"Target MAC  : {dst_mac}")
    print(f"Probes      : {len(args.ports)}")
    print(f"Delay       : {args.delay:.2f}s")
    print()

    rng = random.Random(args.seed)
    observations = []
    fingerprint_candidate = None

    with Pcap(args.adapter, snaplen=65535, promisc=True, timeout_ms=100) as cap:
        for index, port in enumerate(args.ports):
            src_port = args.source_port + index
            seq = rng.randrange(1, 0xFFFFFFFF)

            frame = build_syn_frame(
                src_mac, dst_mac,
                local_ip, args.target,
                src_port, port,
                seq,
                options=STANDARD_SYN_OPTIONS,
            )

            sent_at = time.monotonic()
            cap.send(frame)

            result = None
            state = "NO RESPONSE / POSSIBLY FILTERED"
            deadline = sent_at + args.timeout

            while time.monotonic() < deadline:
                raw = cap.recv()
                if raw is None:
                    continue

                info = parse_ipv4_tcp_frame(raw)
                if not info:
                    continue

                # Exact reverse 4-tuple for this probe.
                if not (
                    info["src_ip"] == args.target
                    and info["dst_ip"] == local_ip
                    and info["src_port"] == port
                    and info["dst_port"] == src_port
                ):
                    continue

                flags = info["flags"]

                if (flags & TCP_SYN) and (flags & TCP_ACK):
                    state = "OPEN"
                    result = info
                    fingerprint_candidate = info
                    break

                if flags & TCP_RST:
                    state = "CLOSED"
                    result = info
                    # Fallback candidate: store RST if no SYN/ACK candidate found yet
                    if fingerprint_candidate is None or (fingerprint_candidate.get("flags", 0) & TCP_RST):
                        fingerprint_candidate = info
                    break

            observations.append((port, state, result))

            if result:
                print(
                    f"{port:5d}  {state:30s} "
                    f"TTL={result['ttl']:3d} "
                    f"WIN={result['window']}"
                )
            else:
                print(f"{port:5d}  {state}")

            time.sleep(args.delay)

    if fingerprint_candidate:
        fp = fingerprint(fingerprint_candidate)

        candidate_type = "Closed-Port TCP RST" if (fingerprint_candidate.get("flags", 0) & TCP_RST) else "Open-Port TCP SYN/ACK"
        print("\nOS fingerprint")
        print("----------------")
        print(f"Probe Source: {candidate_type}")
        print(f"Likely OS   : {fp['os']}")
        print(f"Confidence  : {fp['confidence']}%")
        print(f"Version     : {fp['version']}")
        if fp.get("version_tiers"):
            for tier, pct in fp["version_tiers"]:
                print(f"              {pct:3d}%  {tier}")
        print(f"TTL         : {fp['ttl']} (initial {fp['initial_ttl']}, "
              f"~{fp['hops']} hop(s))")
        print(f"Window      : {fp['window']}")
        print(f"DF bit      : {'set' if fp['df'] else 'clear'}")
        if fp.get("ip_id") is not None:
            print(f"IP ID       : {fp['ip_id']}")
        print("Options     :", ", ".join(str(x) for x in fp["options"]) or "none")
        print("Probability distribution:")
        for cls, pct in fp["distribution"]:
            bar = "#" * (pct // 5)
            print(f"  {cls:16s} {pct:3d}%  {bar}")
        print("Evidence    :")
        for reason in fp["reasons"]:
            print(f"  - {reason}")
    else:
        print("\nNo SYN/ACK or RST response was observed (host may be down or ports filtered).")


def main():
    p = argparse.ArgumentParser(
        description="Bounded custom TCP SYN port scanner for a Windows lab."
    )
    p.add_argument("--adapter", required=True,
                   help="Exact Npcap adapter name")
    p.add_argument("--target", required=True,
                   help="One explicitly authorized IPv4 target")
    p.add_argument("--ports", required=True, nargs="+", type=int)
    p.add_argument("--timeout", type=float, default=1.5)
    p.add_argument("--delay", type=float, default=0.5)
    p.add_argument("--source-port", type=int, default=40000)
    p.add_argument("--seed", type=int, default=406)
    args = p.parse_args()

    if any(not 1 <= x <= 65535 for x in args.ports):
        p.error("Every port must be between 1 and 65535.")
    if not 0.1 <= args.timeout <= 10:
        p.error("--timeout must be between 0.1 and 10 seconds.")

    scan(args)


if __name__ == "__main__":
    main()
