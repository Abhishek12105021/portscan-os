# Design Report — Port Scanning with OS Information / Version

**Course**: CSE406 — Computer Security Lab  
**Semester**: January 2026  
**Project**: #8 — Port Scanning with OS information/version

---

## Table of Contents

1. [Overview of the Project Idea](#1-overview-of-the-project-idea)
2. [Network Topology and Components](#2-network-topology-and-components)
3. [Timing Diagrams](#3-timing-diagrams)
4. [Packet and Frame Structure](#4-packet-and-frame-structure)
5. [Implementation Plan](#5-implementation-plan)
6. [Expected Outcome of a Successful Attack](#6-expected-outcome-of-a-successful-attack)
7. [Defense Idea](#7-defense-idea)
8. [Appendix — Tools, Dependencies and References](#8-appendix)

---

## 1. Overview of the Project Idea

### 1.1 Problem Statement

Network reconnaissance is the first phase of any penetration test or cyber attack. An attacker needs to determine: which services are accessible on a target? What software versions are running? What operating system is in use? This information enables the attacker to select and execute targeted exploits.

This project builds a **complete attack-chain toolkit** — from initial port reconnaissance through exploit execution — entirely from scratch, without relying on ready-made tools like Nmap or Scapy.

### 1.2 Project Scope

The toolkit consists of five attack phases and a defensive countermeasure:

| Phase | Name | Description |
|-------|------|-------------|
| 1 | **TCP SYN Port Scanning** | Send raw TCP SYN packets to discover open, closed, and filtered ports |
| 2 | **Service Banner Grabbing** | Connect to open ports and capture service identification banners |
| 3 | **OS Fingerprinting** | Analyze TCP/IP stack behavior to determine the target's operating system |
| 4 | **Vulnerability Matching** | Map discovered services and versions to known vulnerability patterns |
| 5 | **Exploit Execution** | Execute three proof-of-concept exploits using gathered intelligence |
| Defense | **Scan Detection & Mitigation** | Detect scanning activity and optionally block the attacker via firewall |

### 1.3 Design Principles

- **From-scratch packet construction**: The scanner manually constructs Ethernet/IPv4/TCP frames byte-by-byte, computing checksums with a self-authored Internet checksum function. No Scapy or Nmap.
- **Npcap as I/O only**: Npcap provides raw packet send/receive on Windows. It does not decide which ports to scan or how to interpret responses.
- **Safety-bounded**: The scanner accepts one explicit private IPv4 target, a limited port list (max 50), and a configurable delay. It is not a SYN flood tool.
- **Windows-native**: All code runs on Windows with Python 3.10+ and Npcap. No Linux-specific dependencies.

---

## 2. Network Topology and Components

### 2.1 Lab Topology

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ISOLATED PRIVATE LAB LAN                             │
│                    (e.g., 192.168.1.0/24)                              │
│                    Host-Only or Bridged Network                         │
│                                                                         │
│  ┌────────────────────────┐              ┌─────────────────────────────┐│
│  │   ATTACKER MACHINE     │              │    VICTIM MACHINE           ││
│  │   Windows 10/11        │              │    Windows 10/11 or Linux   ││
│  │                        │              │                             ││
│  │  Components:           │   Private    │  Vulnerable Services:       ││
│  │  ┌──────────────────┐  │   Ethernet   │  ┌───────────────────────┐  ││
│  │  │ SYN Port Scanner │  │   or Wi-Fi   │  │ FTP Server (port 21) │  ││
│  │  │ Banner Grabber   │──│──────────────│──│ SSH Server (port 22) │  ││
│  │  │ OS Fingerprinter │  │              │  │ HTTP Server (port 80)│  ││
│  │  │ Exploit Modules  │  │              │  │ SMB (port 445)       │  ││
│  │  │ ─────────────────│  │              │  │ RDP (port 3389)      │  ││
│  │  │ Npcap (packet IO)│  │              │  └───────────────────────┘  ││
│  │  └──────────────────┘  │              │  ┌───────────────────────┐  ││
│  │                        │              │  │ Defense Detector      │  ││
│  │                        │              │  │ Wireshark (evidence)  │  ││
│  └────────────────────────┘              │  └───────────────────────┘  ││
│                                          └─────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Components

| Component | Machine | Role |
|-----------|---------|------|
| **SYN Scanner** | Attacker | Constructs and sends raw TCP SYN packets via Npcap |
| **Banner Grabber** | Attacker | Opens standard TCP connections to read service banners |
| **OS Fingerprinter** | Attacker | Analyzes SYN/ACK response features (TTL, window, options) |
| **Exploit Modules** | Attacker | FTP anonymous login, SSH credential attack, HTTP traversal |
| **Npcap** | Attacker | Low-level Windows packet I/O interface |
| **Vulnerable Services** | Victim | FTP, SSH, HTTP servers (real or simulated) |
| **Scan Detector** | Victim | Passive SYN monitoring with sliding-window alerting |
| **Firewall Mitigator** | Victim | Optional Windows Firewall rule creation |
| **Wireshark** | Victim | Packet capture evidence (observation, not attack tool) |

### 2.3 Communication Flow

```
Attacker                                    Victim
   │                                           │
   │ ──── [1] SYN Probes (raw packets) ──────► │  Port Scanning
   │ ◄─── SYN/ACK or RST responses ─────────── │
   │                                           │
   │ ──── [2] TCP Connect + Read Banner ─────► │  Banner Grabbing
   │ ◄─── Service identification strings ───── │
   │                                           │
   │      [3] Analyze response features         │  OS Fingerprinting
   │      (TTL, window, TCP options)            │
   │                                           │
   │ ──── [4] Exploit attempts ──────────────► │  Exploitation
   │ ◄─── Success/failure indicators ────────── │
   │                                           │
   │                                           │  Defense detects [1]
   │ ◄──── [BLOCKED by firewall] ────────────── │  Mitigation
```

---

## 3. Timing Diagrams

### 3.1 Phase 1 — TCP SYN Port Scanning

**Open Port:**
```
Scanner                               Victim
   │           t=0                       │
   │ ──────── SYN (dst=80) ───────────► │
   │           t=Δ                       │
   │ ◄──── SYN/ACK (src=80) ─────────── │   → Classified: OPEN
   │                                     │
   │  Scanner does NOT send ACK          │
   │  (half-open / stealth scan)         │
```

**Closed Port:**
```
Scanner                               Victim
   │           t=0                       │
   │ ──────── SYN (dst=443) ──────────► │
   │           t=Δ                       │
   │ ◄──────── RST (src=443) ─────────── │   → Classified: CLOSED
```

**Filtered Port (no response):**
```
Scanner                               Victim
   │           t=0                       │
   │ ──────── SYN (dst=8080) ─────────► │
   │                                     │
   │        ... timeout (1.5s) ...       │   → Classified: NO RESPONSE /
   │                                     │     POSSIBLY FILTERED
```

### 3.2 Phase 2 — Banner Grabbing

**Passive service (FTP — sends banner on connect):**
```
Scanner                               Victim (port 21)
   │                                     │
   │ ──── SYN ─────────────────────────► │
   │ ◄─── SYN/ACK ──────────────────── │
   │ ──── ACK ─────────────────────────► │   Full 3-way handshake
   │                                     │
   │ ◄─ "220 vsftpd 3.0.3\r\n" ──────── │   Banner auto-sent
   │                                     │
   │ ──── FIN ─────────────────────────► │   Clean disconnect
```

**Active service (HTTP — requires probe):**
```
Scanner                               Victim (port 80)
   │                                     │
   │ ──── TCP 3-way handshake ─────────► │
   │                                     │
   │ ──── "HEAD / HTTP/1.0\r\n\r\n" ──► │   Scanner sends probe
   │                                     │
   │ ◄── "HTTP/1.1 200 OK\r\n           │
   │      Server: Apache/2.4.49\r\n     │   Version in header
   │      ..." ──────────────────────── │
```

### 3.3 Phase 5 — Exploit Execution

**Exploit 1 — FTP Anonymous Login:**
```
Scanner                               Victim (port 21)
   │                                     │
   │ ──── TCP connect ───────────────── ►│
   │ ◄── "220 vsftpd 3.0.3" ─────────── │
   │ ──── "USER anonymous\r\n" ────────► │
   │ ◄── "331 Please specify password" ─ │
   │ ──── "PASS anon@lab\r\n" ─────────► │
   │ ◄── "230 Login successful" ──────── │   ← EXPLOIT SUCCESS
   │ ──── "PWD\r\n" ──────────────────► │
   │ ◄── "257 /" ────────────────────── │   ← Data access confirmed
   │ ──── "QUIT\r\n" ─────────────────► │
```

**Exploit 2 — SSH Weak Credentials:**
```
Scanner                               Victim (port 22)
   │                                     │
   │ ──── TCP connect ───────────────── ►│
   │ ◄── "SSH-2.0-OpenSSH_8.2p1" ────── │
   │                                     │
   │ ──── Auth(admin, admin) ──────────► │
   │ ◄── "Auth failed" ──────────────── │   Attempt 1: fail
   │                                     │
   │ ──── Auth(root, toor) ────────────► │
   │ ◄── "Auth failed" ──────────────── │   Attempt 2: fail
   │                                     │
   │ ──── Auth(test, test123) ─────────► │
   │ ◄── "Auth success" ──────────────── │   ← EXPLOIT SUCCESS
   │ ──── "whoami" ────────────────────► │
   │ ◄── "test" ───────────────────────  │   ← Command execution
```

**Exploit 3 — HTTP Directory Traversal:**
```
Scanner                               Victim (port 80)
   │                                     │
   │ ──── TCP connect ───────────────── ►│
   │ ──── "GET /..\..\..\..\            │
   │       windows\win.ini              │
   │       HTTP/1.0\r\n\r\n" ──────────► │
   │                                     │
   │ ◄── "HTTP/1.0 200 OK\r\n          │
   │      [contents of win.ini]" ────── │   ← EXPLOIT SUCCESS
   │                                     │     Sensitive file read
```

### 3.4 Defense — Scan Detection Timeline

```
Time     Event
─────    ─────────────────────────────────────────
t=0      Detector starts listening
t=5.0    SYN from 192.168.1.10 → :80    (count=1, ports=1)
t=5.5    SYN from 192.168.1.10 → :22    (count=2, ports=2)
t=6.0    SYN from 192.168.1.10 → :443   (count=3, ports=3)
t=6.5    SYN from 192.168.1.10 → :21    (count=4, ports=4)
t=7.0    SYN from 192.168.1.10 → :445   (count=5, ports=5)
t=7.5    SYN from 192.168.1.10 → :135   (count=6, ports=6)
t=8.0    SYN from 192.168.1.10 → :139   (count=7, ports=7)
t=8.5    SYN from 192.168.1.10 → :3389  (count=8, ports=8)
         ─── THRESHOLD EXCEEDED ───
         [ALERT] Possible TCP port scan from 192.168.1.10
         [MITIGATION] Blocked TCP traffic from 192.168.1.10
t=9.0    SYN from 192.168.1.10 → :8080  (DROPPED by firewall)
```

---

## 4. Packet and Frame Structure

### 4.1 Ethernet Frame (Layer 2)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│               Destination MAC Address (6 bytes)                   │
├───────────────────────────────────────────────────────────────────┤
│ Dst MAC (cont) │           Source MAC Address (6 bytes)           │
├───────────────────────────────────────────────────────────────────┤
│  Src MAC (cont)│ EtherType = 0x0800 │     Payload (IPv4) ...     │
└───────────────────────────────────────────────────────────────────┘

Total header: 14 bytes
EtherType 0x0800 = IPv4
```

### 4.2 IPv4 Header (Layer 3)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│Version│  IHL  │    DSCP   │ECN│         Total Length              │
├───────────────────────────────────────────────────────────────────┤
│         Identification        │Flags│    Fragment Offset          │
├───────────────────────────────────────────────────────────────────┤
│  Time to Live │   Protocol    │       Header Checksum             │
├───────────────────────────────────────────────────────────────────┤
│                    Source IP Address (4 bytes)                     │
├───────────────────────────────────────────────────────────────────┤
│                  Destination IP Address (4 bytes)                  │
└───────────────────────────────────────────────────────────────────┘

Total header: 20 bytes (no options)
Version = 4, IHL = 5 (20 bytes / 4)
Protocol = 6 (TCP)
TTL = 64 (our scanner) — used for OS fingerprinting on response
```

### 4.3 TCP Header (Layer 4)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
│          Source Port          │       Destination Port             │
├───────────────────────────────────────────────────────────────────┤
│                      Sequence Number                              │
├───────────────────────────────────────────────────────────────────┤
│                   Acknowledgment Number                           │
├───────────────────────────────────────────────────────────────────┤
│ Offset│Reserved │U│A│P│R│S│F│           Window                   │
├───────────────────────────────────────────────────────────────────┤
│           Checksum            │        Urgent Pointer             │
├───────────────────────────────────────────────────────────────────┤
│                    Options (variable) ...                         │
└───────────────────────────────────────────────────────────────────┘

For SYN probe: Flags = SYN (0x02), ACK Number = 0
Total header: 20 bytes minimum + options
```

### 4.4 TCP Checksum Computation

The TCP checksum is computed over a pseudo-header prepended to the TCP segment:

```
┌──────────── IPv4 Pseudo-Header (12 bytes) ───────────┐
│  Source IP Address         (4 bytes)                  │
│  Destination IP Address    (4 bytes)                  │
│  Zero | Protocol (6=TCP)   (2 bytes)                  │
│  TCP Segment Length        (2 bytes)                  │
├──────────── TCP Segment ─────────────────────────────┤
│  TCP Header + Options + Payload                      │
└──────────────────────────────────────────────────────┘

Algorithm:
  1. Concatenate pseudo-header + TCP segment
  2. Pad to even length if necessary
  3. Sum all 16-bit words with carry wraparound
  4. One's complement of the sum
```

### 4.5 OS Fingerprinting — Response Feature Table

The following features are extracted from SYN/ACK responses and compared against known OS signatures:

| Feature | Field | Windows 10/11 | Linux 5.x+ | macOS |
|---------|-------|---------------|-------------|-------|
| Initial TTL | IPv4 TTL | 128 | 64 | 64 |
| Window Size | TCP Window | 64240 or 65535 | 29200 or 65160 | 65535 |
| MSS | TCP Option 2 | 1460 | 1460 | 1460 |
| Window Scale | TCP Option 3 | 8 | 7 | 6 |
| SACK Permitted | TCP Option 4 | Yes | Yes | Yes |
| TCP Timestamp | TCP Option 8 | Often absent | Usually present | Present |
| Option Order | TCP Options | MSS,NOP,WSCALE,NOP,NOP,SACK | MSS,SACK,TS,NOP,WSCALE | MSS,NOP,WSCALE,NOP,NOP,TS,SACK |

> **Note**: OS fingerprinting is inherently probabilistic. Firewalls, NAT devices, and custom TCP/IP stack configurations can alter these values. Results are reported as "likely" or "probable", not as certainties.

---

## 5. Implementation Plan

### 5.1 Architecture

```
portscan_project_windows/
│
├── common/                      # Shared infrastructure
│   ├── packet.py                # Raw Ethernet/IPv4/TCP construction & parsing
│   └── npcap.py                 # Npcap ctypes bindings for Windows
│
├── attacker/                    # Attack toolkit
│   ├── main.py                  # Orchestrator — chains all phases
│   ├── scanner.py               # Phase 1: TCP SYN port scanner
│   ├── banner.py           [NEW]# Phase 2: Service banner grabbing
│   ├── fingerprint.py           # Phase 3: OS fingerprinting heuristics
│   └── exploits/           [NEW]# Phase 5: Exploit modules
│       ├── __init__.py
│       ├── ftp_anon.py          # Exploit 1: FTP anonymous access
│       ├── ssh_bruteforce.py    # Exploit 2: SSH weak credentials
│       └── http_traversal.py   # Exploit 3: HTTP directory traversal
│
├── defense/                     # Countermeasure
│   ├── main.py                  # Defense entry point
│   └── detector.py              # Sliding-window scan detector
│
├── victim/                 [NEW]# Simulated vulnerable services
│   ├── ftp_server.py            # Intentionally vulnerable FTP
│   ├── http_server.py           # Intentionally vulnerable HTTP
│   └── README.md                # Victim setup instructions
│
└── tools/
    └── list_npcap_adapters.py   # Npcap adapter discovery
```

### 5.2 Module Descriptions

**Banner Grabber** (`banner.py`):
Uses standard Python `socket.connect()` to open full TCP connections to each open port. For passive services (FTP, SSH, SMTP) it reads the initial banner immediately. For active services (HTTP) it sends `HEAD / HTTP/1.0\r\n\r\n` and parses the `Server:` header. Returns structured results including port, protocol, service name, version, and raw banner.

**FTP Anonymous Exploit** (`ftp_anon.py`):
Pure socket implementation of FTP command protocol. Attempts `USER anonymous` / `PASS anonymous@lab`. On success, issues `PWD` and `LIST` to demonstrate data access. Reports accessible directories and files.

**SSH Credential Exploit** (`ssh_bruteforce.py`):
Uses `paramiko` library for SSH protocol interaction. Contains a bounded wordlist of 10 common weak credential pairs. Reports successful login and attempts command execution (`whoami`, `hostname`). Uses paramiko because SSH key exchange/encryption is infeasible to implement from scratch.

**HTTP Traversal Exploit** (`http_traversal.py`):
Pure socket HTTP request with path traversal payloads. Tests multiple traversal patterns (`../`, `..\`, `..%2f`, `..%5c`). Targets common sensitive files: `/etc/passwd` (Linux), `windows/win.ini` (Windows). Reports whether file contents were successfully read.

### 5.3 Attack Chain Orchestration

The main orchestrator runs all phases sequentially:

```
1. Input: target IP, port list, adapter name
2. Phase 1: SYN scan all ports → {port: state} map
3. Phase 2: Banner grab on OPEN ports → {port: service_info}
4. Phase 3: OS fingerprint from SYN/ACK data → {os_family, confidence}
5. Phase 4: Match services to applicable exploits
6. Phase 5: Execute each applicable exploit
7. Output: comprehensive report with all findings
```

---

## 6. Expected Outcome of a Successful Attack

### 6.1 Success Criteria

| Phase | Success Indicator | Verification Method |
|-------|-------------------|---------------------|
| Port Scanning | Correctly identifies open/closed/filtered ports | Compare scanner output with `netstat -an` on victim |
| Banner Grabbing | Extracts service name and version string | Verify against known service configuration |
| OS Fingerprinting | Correctly identifies OS family (Windows/Linux) | Compare with actual victim OS |
| Exploit 1 (FTP) | Anonymous login succeeds, files listed | FTP session log shows "230 Login successful" |
| Exploit 2 (SSH) | Weak credential login succeeds | SSH session shows command execution output |
| Exploit 3 (HTTP) | Path traversal reads sensitive file | HTTP response contains file contents |
| Defense | Detector alerts on scan pattern | Detector console output shows ALERT |
| Mitigation | Firewall blocks attacker IP | Subsequent connections from attacker fail |

### 6.2 Sample Expected Output

```
═══════════════════════════════════════════════════════════════
              CUSTOM PORT SCANNER — ATTACK TOOLKIT
═══════════════════════════════════════════════════════════════

[PHASE 1] TCP SYN Port Scanning
Target: 192.168.1.25
───────────────────────────────────────────────────────────────
   21  OPEN                           TTL=128 WIN=64240
   22  OPEN                           TTL=128 WIN=64240
   80  OPEN                           TTL=128 WIN=64240
  443  CLOSED
  445  OPEN                           TTL=128 WIN=64240
 3389  NO RESPONSE / POSSIBLY FILTERED

[PHASE 2] Service Banner Grabbing
───────────────────────────────────────────────────────────────
   21  FTP     → 220 vsftpd 3.0.3
   22  SSH     → SSH-2.0-OpenSSH_8.2p1
   80  HTTP    → Apache/2.4.49
  445  SMB     → (no text banner)

[PHASE 3] OS Fingerprinting
───────────────────────────────────────────────────────────────
Likely OS : Windows family
Confidence: 81%
Version   : Windows 10/11 family
TTL       : 128
Window    : 64240
Evidence  :
  - high initial-TTL candidate (128)
  - Windows-like TCP window (64240)
  - MSS=1460
  - window scale=8

[PHASE 5] Exploit Execution
───────────────────────────────────────────────────────────────
[EXPLOIT] FTP Anonymous Login (port 21)
  Status : SUCCESS
  Detail : Logged in as anonymous, directory listing obtained
  Files  : /pub/readme.txt, /pub/data/

[EXPLOIT] SSH Weak Credentials (port 22)
  Status : SUCCESS
  Detail : Logged in as test:test123
  Output : whoami → test

[EXPLOIT] HTTP Directory Traversal (port 80)
  Status : SUCCESS
  Detail : Read /etc/passwd via ../../../../etc/passwd
  Content: root:x:0:0:root:/root:/bin/bash ...
```

---

## 7. Defense Idea

### 7.1 Detection: Sliding-Window SYN Analysis

The defensive detector is a passive monitoring system that captures all incoming TCP traffic and identifies scanning patterns.

**Algorithm:**

```
For each unique source IP, maintain:
    events = deque of (timestamp, destination_port) tuples

On each incoming packet with SYN=1 and ACK=0:
    1. Add (now, dst_port) to events[source_ip]
    2. Remove all events older than WINDOW seconds
    3. count  = total events remaining
    4. unique = number of distinct destination ports

    If count >= THRESHOLD and unique >= DISTINCT_PORTS:
        → ALERT: "Possible TCP port scan from {source_ip}"
```

**Default Parameters:**
- `THRESHOLD` = 8 SYN packets
- `DISTINCT_PORTS` = 5 unique ports
- `WINDOW` = 10 seconds

The dual condition (both count AND distinct ports) prevents false positives from legitimate rapid connections to a single service.

### 7.2 Mitigation: Dynamic Firewall Blocking

When a scan is detected and the `--block` flag is active, the detector creates a Windows Firewall inbound rule:

```
netsh advfirewall firewall add rule
    name="CustomPortScanBlock_{IP}"
    dir=in action=block
    remoteip={detected_source_IP}
    protocol=TCP profile=any
```

- Blocking is **opt-in only** to prevent accidentally blocking legitimate traffic
- Rules are automatically removed when the detector exits cleanly (Ctrl+C)
- Rule names are predictable for manual cleanup if needed

### 7.3 Why This Defense Works

1. **Low false-positive rate**: Requiring both high SYN count AND port diversity distinguishes scans from normal burst traffic
2. **Low latency**: Detection typically triggers within seconds of scan start
3. **Proportional response**: Alert-only by default; blocking is opt-in
4. **Self-cleaning**: Firewall rules are transient, not permanent

### 7.4 Limitations

- Cannot detect slow/stealthy scans below the threshold (e.g., 1 port per minute)
- Source IP can be spoofed (but SYN scanning requires seeing responses, limiting spoofing utility)
- Encrypted/tunneled traffic bypasses this layer
- Fixed thresholds may not suit all environments (adaptive thresholds would be an improvement)

---

## 8. Appendix

### 8.1 Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | Python 3.10+ | All modules |
| Packet I/O | Npcap + ctypes | Raw frame send/receive on Windows |
| SSH Library | paramiko | SSH protocol interaction for credential exploit |
| Packet Capture | Wireshark | Evidence collection (not an attack tool) |
| OS | Windows 10/11 | Attacker and victim machines |

### 8.2 References

1. Fyodor (Gordon Lyon), "Remote OS detection via TCP/IP Stack Fingerprinting," Phrack Magazine, Issue 54, 1998.
2. RFC 793 — Transmission Control Protocol (TCP)
3. RFC 791 — Internet Protocol (IPv4)
4. RFC 4987 — TCP SYN Flooding Attacks and Common Mitigations
5. MITRE ATT&CK T1046 — Network Service Scanning
6. CVE-2017-0144 — EternalBlue (example of port-scan-to-exploit chain via SMB)
7. Nmap Reference Guide — OS Detection, https://nmap.org/book/man-os-detection.html
8. SANS Institute — TCP/IP and tcpdump (GIAC reference material)
