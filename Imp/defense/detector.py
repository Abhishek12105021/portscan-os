"""
Port-scan detector.

This is a defensive component. It does not generate packets.
"""

import subprocess
import time
from collections import defaultdict, deque


class SourceState:
    def __init__(self):
        self.events = deque()

    def add(self, now, dst_port):
        self.events.append((now, dst_port))

    def prune(self, cutoff):
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def stats(self):
        ports = {port for _, port in self.events}
        return len(self.events), len(ports)


class ScanDetector:
    def __init__(self, threshold=8, distinct_ports=5, window=10.0,
                 block=False, block_prefix="CustomPortScanBlock"):
        self.threshold = threshold
        self.distinct_ports = distinct_ports
        self.window = window
        self.block = block
        self.block_prefix = block_prefix
        self.states = defaultdict(SourceState)
        self.blocked = set()

    def observe_syn(self, source_ip, destination_port):
        now = time.monotonic()
        state = self.states[source_ip]
        state.add(now, destination_port)
        state.prune(now - self.window)

        count, unique = state.stats()

        suspicious = (
            count >= self.threshold
            and unique >= self.distinct_ports
        )

        return count, unique, suspicious

    def mitigate(self, source_ip):
        if source_ip in self.blocked:
            return

        rule = f"{self.block_prefix}_{source_ip.replace('.', '_')}"

        # Defensive action is opt-in. It blocks only TCP traffic from the
        # detected source IP.
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule}",
            "dir=in",
            "action=block",
            f"remoteip={source_ip}",
            "protocol=TCP",
            "profile=any",
        ]

        completed = subprocess.run(
            command, capture_output=True, text=True, shell=False
        )

        if completed.returncode != 0:
            raise RuntimeError(
                "Could not create Windows Firewall rule: "
                + completed.stderr.strip()
            )

        self.blocked.add(source_ip)
        print(f"[MITIGATION] Blocked TCP traffic from {source_ip}")
        print(f"             Firewall rule: {rule}")

    def cleanup(self):
        for source_ip in list(self.blocked):
            rule = f"{self.block_prefix}_{source_ip.replace('.', '_')}"
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall",
                    "delete", "rule", f"name={rule}"
                ],
                capture_output=True, text=True, shell=False
            )
        self.blocked.clear()
