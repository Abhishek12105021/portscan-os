"""
Port-scan detector with multi-vector coverage and cross-platform mitigation.

Detects:
    - Classic TCP SYN scans (threshold + port-diversity sliding window)
    - Slow scans (long-window rate check)
    - Invalid TCP flag combinations (NULL, FIN-only, XMAS, SYN+FIN)
    - Decoy / Canary Honeyport access (e.g. port 81)

Mitigation:
    - Cross-platform opt-in firewall blocking (Windows netsh / Linux iptables)
    - Auto-release after a configurable TTL (default 300 seconds)
    - Whitelist support to suppress known-good sources
    - Structured incident logging (defense_incident_log.json)
"""

import json
import os
import platform
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

# Invalid TCP flag combinations
NULL_SCAN     = 0x00                     # No flags at all
FIN_ONLY      = 0x01                     # FIN without ACK
XMAS_SCAN     = 0x01 | 0x08 | 0x20       # FIN + PSH + URG (0x29)
SYN_FIN_SCAN  = 0x02 | 0x01              # SYN + FIN (RFC 793 rule-breaker)


class SourceState:
    def __init__(self):
        self.events = deque()            # Fast window: (timestamp, dst_port)
        self.long_events = deque()       # Slow window: timestamps
        self.invalid_flag_hits = 0       # Invalid flag counter

    def add(self, now, dst_port):
        self.events.append((now, dst_port))

    def prune(self, cutoff):
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def stats(self):
        ports = {port for _, port in self.events}
        return len(self.events), len(ports)


class ScanDetector:
    def __init__(
        self,
        threshold=8,
        distinct_ports=5,
        window=10.0,
        long_window=60.0,
        long_threshold=20,
        invalid_flag_alert=1,
        canary_ports=None,
        whitelist=None,
        block=False,
        block_prefix="CustomPortScanBlock",
        block_ttl=300.0,
        incident_log="defense_incident_log.json",
    ):
        self.threshold = threshold
        self.distinct_ports = distinct_ports
        self.window = window
        self.long_window = long_window
        self.long_threshold = long_threshold
        self.invalid_flag_alert = invalid_flag_alert
        self.canary_ports = set(canary_ports or [])
        self.whitelist = set(whitelist or [])
        self.block = block
        self.block_prefix = block_prefix
        self.block_ttl = block_ttl
        self.incident_log = incident_log

        self.os_type = platform.system().lower()
        self.lock = threading.Lock()
        self.states = defaultdict(SourceState)
        # ip -> {"rule": str, "added_at": float, "reason": str}
        self.blocked = {}

    # ---------------------------------------------------------------- SYN Probes
    def observe_syn(self, source_ip, destination_port):
        if source_ip in self.whitelist:
            return 0, 0, False, None

        now = time.monotonic()
        state = self.states[source_ip]

        # Check Canary / Honeyport
        if destination_port in self.canary_ports:
            return 1, 1, True, f"hit canary honeyport ({destination_port})"

        # Fast window
        state.add(now, destination_port)
        state.prune(now - self.window)
        count, unique = state.stats()
        fast_suspicious = (count >= self.threshold and unique >= self.distinct_ports)

        # Slow window
        state.long_events.append(now)
        while state.long_events and state.long_events[0] < now - self.long_window:
            state.long_events.popleft()
        long_count = len(state.long_events)
        slow_suspicious = long_count >= self.long_threshold

        reason = None
        if fast_suspicious:
            reason = f"fast port scan (SYN={count}, distinct ports={unique} within {self.window}s)"
        elif slow_suspicious:
            reason = f"slow stealth scan (SYN={long_count} within {self.long_window}s)"

        return count, unique, (fast_suspicious or slow_suspicious), reason

    # --------------------------------------------------------- Invalid TCP Flags
    def observe_invalid_flags(self, source_ip, destination_port, flags):
        if source_ip in self.whitelist:
            return False, None

        is_null = (flags == NULL_SCAN)
        is_fin_only = (flags == FIN_ONLY)
        is_xmas = (flags == XMAS_SCAN)
        is_syn_fin = (flags == SYN_FIN_SCAN)

        if not (is_null or is_fin_only or is_xmas or is_syn_fin):
            return False, None

        state = self.states[source_ip]
        state.invalid_flag_hits += 1

        label = (
            "NULL" if is_null else
            "FIN-only" if is_fin_only else
            "XMAS" if is_xmas else "SYN+FIN (Rule-Breaker)"
        )
        reason = f"invalid TCP flag combination ({label}, 0x{flags:02x}) on port {destination_port}"
        suspicious = state.invalid_flag_hits >= self.invalid_flag_alert
        return suspicious, reason

    # ------------------------------------------------------------- Mitigation
    def mitigate(self, source_ip, reason=""):
        with self.lock:
            if source_ip in self.blocked:
                return

            rule = f"{self.block_prefix}_{source_ip.replace('.', '_')}"

            if "windows" in self.os_type:
                command = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule}", "dir=in", "action=block",
                    f"remoteip={source_ip}", "protocol=TCP", "profile=any",
                ]
            else:
                command = ["iptables", "-I", "INPUT", "-s", source_ip, "-p", "tcp", "-j", "DROP"]

            completed = subprocess.run(command, capture_output=True, text=True, shell=False)
            if completed.returncode != 0:
                raise RuntimeError(f"Firewall rule injection failed: {completed.stderr.strip()}")

            self.blocked[source_ip] = {
                "rule": rule,
                "added_at": time.monotonic(),
                "reason": reason,
            }

            print(f"[MITIGATION] Blocked TCP traffic from {source_ip}")
            print(f"             Firewall rule : {rule} ({self.os_type.capitalize()})")
            print(f"             Trigger reason: {reason}")
            if self.block_ttl > 0:
                print(f"             Auto-release  : after {int(self.block_ttl)}s (self-healing)")

            self._log_incident(source_ip, reason, rule)

    def release_expired(self):
        if self.block_ttl <= 0:
            return
        with self.lock:
            now = time.monotonic()
            expired = [ip for ip, info in list(self.blocked.items()) if now - info["added_at"] >= self.block_ttl]
            for ip in expired:
                self._remove_rule(ip)
                print(f"[MITIGATION] Released quarantine block on {ip} (TTL {int(self.block_ttl)}s elapsed)")

    def _remove_rule(self, source_ip):
        info = self.blocked.pop(source_ip, None)
        if not info:
            return
        if "windows" in self.os_type:
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={info['rule']}"]
            subprocess.run(cmd, capture_output=True, text=True, shell=False)
        else:
            # On Linux, delete all duplicate DROP instances for this IP
            while True:
                cmd = ["iptables", "-D", "INPUT", "-s", source_ip, "-p", "tcp", "-j", "DROP"]
                res = subprocess.run(cmd, capture_output=True, text=True, shell=False)
                if res.returncode != 0:
                    break

    def cleanup(self):
        with self.lock:
            for ip in list(self.blocked):
                self._remove_rule(ip)

    def _log_incident(self, source_ip, reason, rule):
        record = {
            "timestamp": datetime.now().isoformat(),
            "attacker_ip": source_ip,
            "reason": reason,
            "firewall_rule": rule,
            "platform": self.os_type,
            "ttl_seconds": self.block_ttl,
        }
        try:
            records = []
            if os.path.exists(self.incident_log):
                with open(self.incident_log, "r", encoding="utf-8") as f:
                    records = json.load(f)
            records.append(record)
            with open(self.incident_log, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)
        except Exception as e:
            print(f"[LOG ERROR] Failed to record incident: {e}")