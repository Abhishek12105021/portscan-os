import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import argparse
import ipaddress
import random
import time

from common.packet import (
    build_syn_frame, build_ecn_syn_frame, parse_ipv4_tcp_frame, parse_tcp_options, TCP_ACK, TCP_RST, TCP_SYN,
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

                recv_time = time.monotonic()
                info = parse_ipv4_tcp_frame(raw)
                if not info:
                    continue
                info["recv_time"] = recv_time

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

    # Collect all IP IDs observed during the scan probes (Idea 2)
    ip_ids = [res["ip_id"] for _, _, res in observations if res and "ip_id" in res]
    if fingerprint_candidate:
        fingerprint_candidate["ip_ids"] = ip_ids

    # Collect TCP Timestamp samples across probes (Idea 3)
    ts_samples = []
    open_port_candidate = None
    for p, s, res in observations:
        if res and res.get("options"):
            opts = parse_tcp_options(res["options"])
            for opt in opts:
                if opt[0] == "TIMESTAMP":
                    ts_samples.append((res.get("recv_time", time.monotonic()), opt[1]))
                    if s == "OPEN":
                        open_port_candidate = p

    # RFC 3168 ECN Probe (Idea 4) & Clock Measurement
    ecn_info = {"tested": False}
    if open_port_candidate is not None:
        ecn_port = open_port_candidate
        ecn_src_port = random.randint(45000, 60000)
        time.sleep(0.4)
        with Pcap(args.adapter, snaplen=65535, promisc=True, timeout_ms=100) as ecn_cap:
            ecn_seq = rng.randrange(1, 0xFFFFFFFF)
            ecn_frame = build_ecn_syn_frame(
                src_mac, dst_mac,
                local_ip, args.target,
                ecn_src_port, ecn_port,
                ecn_seq,
                options=STANDARD_SYN_OPTIONS,
            )
            e_sent = time.monotonic()
            ecn_cap.send(ecn_frame)
            e_deadline = e_sent + args.timeout
            ecn_responded = False
            while time.monotonic() < e_deadline:
                e_raw = ecn_cap.recv()
                if not e_raw:
                    continue
                e_recv_time = time.monotonic()
                e_info = parse_ipv4_tcp_frame(e_raw)
                if not e_info:
                    continue
                if (
                    e_info["src_ip"] == args.target
                    and e_info["dst_ip"] == local_ip
                    and e_info["src_port"] == ecn_port
                    and e_info["dst_port"] == ecn_src_port
                ):
                    ecn_responded = True
                    ecn_info = {
                        "tested": True,
                        "flags": e_info["flags"],
                        "ttl": e_info["ttl"],
                        "window": e_info["window"],
                        "dropped": False,
                    }
                    if "ip_id" in e_info:
                        ip_ids.append(e_info["ip_id"])
                    if e_info.get("options"):
                        e_opts = parse_tcp_options(e_info["options"])
                        for opt in e_opts:
                            if opt[0] == "TIMESTAMP":
                                ts_samples.append((e_recv_time, opt[1]))
                    break
            if not ecn_responded:
                ecn_info = {
                    "tested": True,
                    "dropped": True,
                }
    else:
        ecn_info = {
            "tested": False,
            "reason": "No open port observed for ECN negotiation",
        }

    # If only 1 timestamp sample is available and an open port exists,
    # send a follow-up standard probe to measure clock frequency
    if len(ts_samples) == 1 and open_port_candidate is not None:
        followup_port = open_port_candidate
        followup_src_port = random.randint(45000, 60000)
        time.sleep(0.4)
        with Pcap(args.adapter, snaplen=65535, promisc=True, timeout_ms=100) as follow_cap:
            follow_seq = rng.randrange(1, 0xFFFFFFFF)
            follow_frame = build_syn_frame(
                src_mac, dst_mac,
                local_ip, args.target,
                followup_src_port, followup_port,
                follow_seq,
                options=STANDARD_SYN_OPTIONS,
            )
            f_sent = time.monotonic()
            follow_cap.send(follow_frame)
            f_deadline = f_sent + args.timeout
            while time.monotonic() < f_deadline:
                f_raw = follow_cap.recv()
                if not f_raw:
                    continue
                f_recv_time = time.monotonic()
                f_info = parse_ipv4_tcp_frame(f_raw)
                if not f_info:
                    continue
                if (
                    f_info["src_ip"] == args.target
                    and f_info["dst_ip"] == local_ip
                    and f_info["src_port"] == followup_port
                    and f_info["dst_port"] == followup_src_port
                ):
                    if "ip_id" in f_info:
                        ip_ids.append(f_info["ip_id"])
                    if f_info.get("options"):
                        f_opts = parse_tcp_options(f_info["options"])
                        for opt in f_opts:
                            if opt[0] == "TIMESTAMP":
                                ts_samples.append((f_recv_time, opt[1]))
                    break

    if fingerprint_candidate:
        fingerprint_candidate["ip_ids"] = ip_ids
        fingerprint_candidate["ts_samples"] = ts_samples
        fingerprint_candidate["ecn_info"] = ecn_info
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
        if fp.get("ip_id_sequence") and len(fp["ip_id_sequence"]) > 1:
            deltas_str = str(fp.get("ip_id_deltas", []))
            print(f"IP ID Seq   : {fp['ip_id_sequence']} (deltas: {deltas_str})")
            print(f"IP ID Class : {fp.get('ip_id_class', 'UNKNOWN')}")
        elif fp.get("ip_id") is not None:
            print(f"IP ID       : {fp['ip_id']}")
        print("Options     :", ", ".join(str(x) for x in fp["options"]) or "none")
        if fp.get("ts_class") and fp["ts_class"] != "NONE":
            if fp["ts_class"] == "RANDOM_OFFSET":
                print("Timestamp   : Clock Rate: Randomized offset (RFC 7323 Darwin PRNG)")
            elif fp.get("ts_rate") is not None:
                print(f"Timestamp   : Clock Rate: ~{fp['ts_rate']:.1f} Hz ({fp['ts_class']})")
                if fp.get("uptime"):
                    print(f"Uptime      : ~{fp['uptime']}")
        if fp.get("ecn_status") and fp["ecn_status"] != "NOT_TESTED":
            if fp["ecn_status"] == "ECN_SUPPORTED":
                print(f"ECN Probe   : Supported (ECE reflected: True, Flags: 0x{fp.get('ecn_flags', 0):02x}) [RFC 3168]")
            elif fp["ecn_status"] == "ECN_IGNORED":
                print(f"ECN Probe   : Ignored / Not Negotiated (ECE reflected: False, Flags: 0x{fp.get('ecn_flags', 0):02x}) [Default Windows Stack]")
            elif fp["ecn_status"] == "ECN_DROPPED":
                print("ECN Probe   : Dropped / Blocked by Firewall")
            else:
                print(f"ECN Probe   : {fp['ecn_status']} (Flags: 0x{fp.get('ecn_flags', 0):02x})")
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
