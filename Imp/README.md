# Windows Custom Port Scanner + OS Fingerprinting + Defensive Detector

This implementation is for the assigned project:

> Port Scanning with OS information / version

The attack tool is built from scratch: it constructs and parses its own
Ethernet/IPv4/TCP frames and computes its own checksums. It does not use
Nmap or Scapy. Npcap is used only as the low-level Windows packet I/O
interface — it does not decide which ports to scan or how responses are
interpreted.

See [../design_report.md](../design_report.md) for the full design (topology,
timing, packet structure, defense algorithm) and [../HOW_TO_RUN.md](../HOW_TO_RUN.md)
for step-by-step setup and run instructions.

## Safety boundary

This is a bounded reconnaissance demonstration, not a SYN flood.

The scanner:
- accepts one explicitly supplied private IPv4 target;
- accepts an explicit list of ports;
- has a hard maximum of 50 probes per run;
- has a configurable minimum delay (default 0.5 s);
- sends one SYN per selected port;
- does not scan an IP range or attempt to exhaust resources.

Use only against a machine you own or have explicit permission to test.

## Directory

    Imp/
        common/
            packet.py           # Ethernet/IPv4/TCP construction & parsing
            npcap.py            # Npcap ctypes bindings (packet I/O)
        attacker/
            main.py             # Orchestrator (chains all phases)
            scanner.py           # Phase 1: TCP SYN port scanner
            banner.py            # Phase 2: service banner grabbing
            fingerprint.py       # Phase 3: OS fingerprinting
            exploits/
                ftp_anon.py         # Exploit 1: FTP anonymous login
                ssh_bruteforce.py   # Exploit 2: SSH weak credentials
                http_traversal.py   # Exploit 3: HTTP directory traversal
        defense/
            main.py             # Defense entry point
            detector.py         # Sliding-window scan detector
        victim/
            ftp_server.py       # Simulated vulnerable FTP server
            http_server.py      # Simulated vulnerable HTTP server
            README.md
        tools/
            list_npcap_adapters.py
        tests/
            test_packet.py
        requirements.txt
        REPORT_NOTES.md         # What to observe/measure + tools to use for the report
