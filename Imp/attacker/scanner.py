import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import argparse
import ipaddress
import random
import time

from common.packet import (
    build_syn_frame, build_ecn_syn_frame, build_synfin_frame,
    build_icmp_echo_frame, build_udp_frame,
    parse_ipv4_tcp_frame, parse_ipv4_icmp_frame, parse_tcp_options,
    TCP_ACK, TCP_RST, TCP_SYN, IPPROTO_ICMP,
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
    closed_port_candidate = None
    for p, s, res in observations:
        if s == "OPEN" and open_port_candidate is None:
            open_port_candidate = p
        elif s == "CLOSED" and closed_port_candidate is None:
            closed_port_candidate = p
        if res and res.get("options"):
            opts = parse_tcp_options(res["options"])
            for opt in opts:
                if opt[0] == "TIMESTAMP":
                    ts_samples.append((res.get("recv_time", time.monotonic()), opt[1]))

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

    # Ambiguous / Invalid TCP Flags Probe (Idea 5 - SYN+FIN "Rule-Breaker")
    invalid_flags_info = {"tested": False}
    if open_port_candidate is not None:
        inv_port = open_port_candidate
        inv_src_port = random.randint(45000, 60000)
        time.sleep(0.3)
        open_resp = False
        open_flags = None
        with Pcap(args.adapter, snaplen=65535, promisc=True, timeout_ms=100) as inv_cap:
            inv_seq = rng.randrange(1, 0xFFFFFFFF)
            inv_frame = build_synfin_frame(
                src_mac, dst_mac,
                local_ip, args.target,
                inv_src_port, inv_port,
                inv_seq,
                options=STANDARD_SYN_OPTIONS,
            )
            i_sent = time.monotonic()
            inv_cap.send(inv_frame)
            i_deadline = i_sent + min(args.timeout, 1.5)
            while time.monotonic() < i_deadline:
                i_raw = inv_cap.recv()
                if not i_raw:
                    continue
                i_info = parse_ipv4_tcp_frame(i_raw)
                if not i_info:
                    continue
                if (
                    i_info["src_ip"] == args.target
                    and i_info["dst_ip"] == local_ip
                    and i_info["src_port"] == inv_port
                    and i_info["dst_port"] == inv_src_port
                ):
                    open_resp = True
                    open_flags = i_info["flags"]
                    if "ip_id" in i_info:
                        ip_ids.append(i_info["ip_id"])
                    break

        closed_resp = None
        # If open port silently dropped (Unix/Darwin behavior), test closed port if available
        if not open_resp and closed_port_candidate is not None:
            c_port = closed_port_candidate
            c_src_port = random.randint(45000, 60000)
            time.sleep(0.3)
            with Pcap(args.adapter, snaplen=65535, promisc=True, timeout_ms=100) as c_cap:
                c_seq = rng.randrange(1, 0xFFFFFFFF)
                c_frame = build_synfin_frame(
                    src_mac, dst_mac,
                    local_ip, args.target,
                    c_src_port, c_port,
                    c_seq,
                    options=STANDARD_SYN_OPTIONS,
                )
                c_sent = time.monotonic()
                c_cap.send(c_frame)
                c_deadline = c_sent + min(args.timeout, 1.2)
                closed_resp = False
                while time.monotonic() < c_deadline:
                    c_raw = c_cap.recv()
                    if not c_raw:
                        continue
                    c_info = parse_ipv4_tcp_frame(c_raw)
                    if not c_info:
                        continue
                    if (
                        c_info["src_ip"] == args.target
                        and c_info["dst_ip"] == local_ip
                        and c_info["src_port"] == c_port
                        and c_info["dst_port"] == c_src_port
                    ):
                        closed_resp = True
                        if "ip_id" in c_info:
                            ip_ids.append(c_info["ip_id"])
                        break

        invalid_flags_info = {
            "tested": True,
            "probe": "SYN+FIN",
            "open_port_responded": open_resp,
            "open_port_flags": open_flags,
            "closed_port_responded": closed_resp,
        }
    elif closed_port_candidate is not None:
        c_port = closed_port_candidate
        c_src_port = random.randint(45000, 60000)
        time.sleep(0.3)
        with Pcap(args.adapter, snaplen=65535, promisc=True, timeout_ms=100) as c_cap:
            c_seq = rng.randrange(1, 0xFFFFFFFF)
            c_frame = build_synfin_frame(
                src_mac, dst_mac,
                local_ip, args.target,
                c_src_port, c_port,
                c_seq,
                options=STANDARD_SYN_OPTIONS,
            )
            c_sent = time.monotonic()
            c_cap.send(c_frame)
            c_deadline = c_sent + min(args.timeout, 1.2)
            closed_resp = False
            while time.monotonic() < c_deadline:
                c_raw = c_cap.recv()
                if not c_raw:
                    continue
                c_info = parse_ipv4_tcp_frame(c_raw)
                if not c_info:
                    continue
                if (
                    c_info["src_ip"] == args.target
                    and c_info["dst_ip"] == local_ip
                    and c_info["src_port"] == c_port
                    and c_info["dst_port"] == c_src_port
                ):
                    closed_resp = True
                    break
        invalid_flags_info = {
            "tested": True,
            "probe": "SYN+FIN",
            "open_port_responded": False,
            "open_port_flags": None,
            "closed_port_responded": closed_resp,
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

    # ICMP & UDP Probing Battery (Idea 6)
    icmp_resp = None
    time.sleep(0.3)
    with Pcap(args.adapter, snaplen=65535, promisc=True, timeout_ms=100) as icmp_cap:
        ie_id = rng.randrange(1, 0xFFFF)
        ie_frame = build_icmp_echo_frame(
            src_mac, dst_mac,
            local_ip, args.target,
            icmp_id=ie_id, icmp_seq=1, icmp_code=9,
            payload=b"A" * 64,
        )
        ie_sent = time.monotonic()
        icmp_cap.send(ie_frame)
        ie_deadline = ie_sent + min(args.timeout, 1.2)
        while time.monotonic() < ie_deadline:
            ie_raw = icmp_cap.recv()
            if not ie_raw:
                continue
            ie_info = parse_ipv4_icmp_frame(ie_raw)
            if not ie_info:
                continue
            if (
                ie_info["src_ip"] == args.target
                and ie_info["dst_ip"] == local_ip
                and ie_info["icmp_type"] == 0
            ):
                icmp_resp = ie_info
                break

    udp_resp = None
    time.sleep(0.3)
    with Pcap(args.adapter, snaplen=65535, promisc=True, timeout_ms=100) as udp_cap:
        u_src_port = random.randint(45000, 60000)
        u_frame = build_udp_frame(
            src_mac, dst_mac,
            local_ip, args.target,
            src_port=u_src_port, dst_port=33434,
            payload=b"C" * 300,
        )
        u_sent = time.monotonic()
        udp_cap.send(u_frame)
        u_deadline = u_sent + min(args.timeout, 1.2)
        while time.monotonic() < u_deadline:
            u_raw = udp_cap.recv()
            if not u_raw:
                continue
            u_info = parse_ipv4_icmp_frame(u_raw)
            if not u_info:
                continue
            if (
                u_info["src_ip"] == args.target
                and u_info["dst_ip"] == local_ip
                and u_info["icmp_type"] == 3
            ):
                udp_resp = u_info
                break

    icmp_udp_info = {
        "tested": True,
        "echo_responded": icmp_resp is not None,
        "echo_code": icmp_resp["icmp_code"] if icmp_resp else None,
        "echo_ttl": icmp_resp["ttl"] if icmp_resp else None,
        "echo_df": icmp_resp["df"] if icmp_resp else None,
        "echo_ip_id": icmp_resp["ip_id"] if icmp_resp else None,
        "udp_responded": udp_resp is not None,
        "udp_icmp_type": udp_resp["icmp_type"] if udp_resp else None,
        "udp_icmp_code": udp_resp["icmp_code"] if udp_resp else None,
        "udp_ttl": udp_resp["ttl"] if udp_resp else None,
        "udp_quoted_len": udp_resp["quoted_length"] if udp_resp else None,
    }

    # Autonomous Firewall Fallback / Preferred ICMP: If no TCP port responded with SYN/ACK or RST,
    # or if --prefer-icmp was requested, use the ICMP Echo Reply as the fingerprint candidate!
    if (fingerprint_candidate is None or getattr(args, "prefer_icmp", False)) and icmp_resp is not None:
        fingerprint_candidate = {
            "ttl": icmp_resp["ttl"],
            "window": 0,
            "options": b"",
            "df": icmp_resp["df"],
            "ip_id": icmp_resp["ip_id"],
            "flags": 0,
            "probe_type": "ICMP Echo Reply",
            "protocol": IPPROTO_ICMP,
        }

    if fingerprint_candidate:
        fingerprint_candidate["ip_ids"] = ip_ids
        fingerprint_candidate["ts_samples"] = ts_samples
        fingerprint_candidate["ecn_info"] = ecn_info
        fingerprint_candidate["invalid_flags_info"] = invalid_flags_info
        fingerprint_candidate["icmp_udp_info"] = icmp_udp_info
        fp = fingerprint(fingerprint_candidate)

        candidate_type = fingerprint_candidate.get("probe_type") or ("Closed-Port TCP RST" if (fingerprint_candidate.get("flags", 0) & TCP_RST) else "Open-Port TCP SYN/ACK")
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
        if fp.get("invalid_flags_status") and fp["invalid_flags_status"] != "NOT_TESTED":
            print(f"Invalid Flgs: {fp.get('invalid_flags_description', fp['invalid_flags_status'])}")
        if fp.get("icmp_udp_status") and fp["icmp_udp_status"] != "NOT_TESTED":
            print(f"ICMP/UDP    : {fp.get('icmp_udp_description', fp['icmp_udp_status'])}")
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
    p.add_argument("--prefer-icmp", action="store_true",
                   help="Force using ICMP Echo Reply as primary fingerprint candidate (demo/firewall test)")
    args = p.parse_args()

    if any(not 1 <= x <= 65535 for x in args.ports):
        p.error("Every port must be between 1 and 65535.")
    if not 0.1 <= args.timeout <= 10:
        p.error("--timeout must be between 0.1 and 10 seconds.")

    scan(args)


if __name__ == "__main__":
    main()
