# PortScan & OS Fingerprint Toolkit

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Npcap-lightgrey.svg)](https://npcap.com/)
[![Dependencies](https://img.shields.io/badge/dependencies-Zero%20Scapy%20%2F%20Zero%20Nmap-success.svg)]()
[![Tests](https://img.shields.io/badge/tests-51%20passing%20%28100%25%29-brightgreen.svg)]()
[![Defense](https://img.shields.io/badge/defense-Active%20Firewall%20Quarantine-red.svg)]()

> A high-performance, raw Layer-2/3/4 reconnaissance and active defense suite built **from scratch** in Python. Features hand-crafted TCP SYN port scanning, a 7-technique heuristic OS fingerprinting engine, automated exploit chains, and real-time sliding-window defense mitigation with dynamic Windows Firewall auto-quarantine.

---

## ⚡ Highlights

- **Pure Raw Packet Crafting**: Manually builds Ethernet, IPv4, TCP, UDP, and ICMP frames byte-by-byte using Python `struct` and native `Npcap` C-bindings. Computes RFC 1071 one's-complement checksums directly (**zero Scapy, zero Nmap**).
- **Stealth Half-Open SYN Scanner**: High-speed SYN probing without completing the 3-way handshake, evading naive application logging.
- **7-Vector Heuristic OS Fingerprinting**: 
  - **Zero-Open-Port RST Detection** (identifies OS even when all ports are closed)
  - **Sequential IP ID Tracking** (`ALL_ZERO`, `STRICT_INCREMENTAL`, `RANDOM_POSITIVE`)
  - **TCP Timestamp Clock Rates & Uptime** (~1000Hz Windows vs ~250Hz Linux vs Apple PRNG)
  - **RFC 3168 ECN Reflection Probing** (`ECE`/`CWR` flag negotiation)
  - **"Rule-Breaker" TCP Flag Probes** (`SYN+FIN` state machine testing)
  - **ICMP/UDP Battery & Autonomous Fallback** (Code reflection, 328B vs 28B quoting, stealth firewall bypass)
  - **Cross-Layer Banner Correlation** (RFC 7230 header ordering & distribution signatures)
- **Automated Exploitation Chain**: Chained verification for Anonymous FTP (`T1078`), SSH dictionary authentication, and 12-payload HTTP Path Traversal (`OWASP A01` / `CVE-2021-41773`).
- **Active Defense & Auto-Quarantine (10% Bonus)**: Real-time sliding-window SYN flood detector that dynamically spawns Windows Defender Firewall rules to isolate attacking IPs mid-scan.

---

## 🚀 The End-to-End Pipeline

```
[ Attacker: Raw SYN Scan ] ──► [ Banner Grabbing ] ──► [ 7-Vector OS Fingerprint ] ──► [ Automated Exploits ]
           │                                                                                     │
           │                                                                                     ▼
           ▼                                                                       ┌───────────────────────────┐
┌────────────────────────────────────────────────────────┐                         │  ✓ FTP Anonymous Access   │
│ Victim: Sliding-Window Defense Engine                  │                         │  ✓ SSH Credential Login   │
│ - Analyzes SYN frequency & distinct port thresholds    │                         │  ✓ HTTP Path Traversal    │
│ - [QUARANTINE] Spawns dynamic Windows Firewall block   │                         └───────────────────────────┘
└────────────────────────────────────────────────────────┘
```

---

## 💻 Quick Start

### 1. Prerequisites
- **OS**: Windows 10 or 11 (Run terminal as **Administrator**)
- **Npcap**: Installed in "WinPcap API-compatible Mode" ([npcap.com](https://npcap.com/))
- **Python**: 3.11+ (Install dependencies: `pip install -r Imp/requirements.txt`)

### 2. Identify Network Interface
```powershell
python Imp\tools\list_npcap_adapters.py
```
*Locate your physical network adapter GUID (e.g. `\Device\NPF_{79613882-...}`).*

---

### 3. Launch the Attack Chain
```powershell
python Imp\attacker\main.py `
  --adapter "\Device\NPF_{YOUR-ADAPTER-GUID}" `
  --target 192.168.1.104 `
  --ports 21 22 80 445 3389
```

#### Live Terminal Preview:
```text
═════════════════════════════════════════════════════════════════
  CUSTOM PORT SCANNER — ATTACK TOOLKIT
═════════════════════════════════════════════════════════════════
  Target       : 192.168.1.104
  Ports        : [21, 22, 80, 445, 3389]
  
  [PHASE 1] TCP SYN Port Scanning
  ─────────────────────────────────────────────────────────────
       21  OPEN                           TTL=128 WIN=65535
       22  CLOSED                         TTL=128 WIN=0
       80  OPEN                           TTL=128 WIN=65535
      445  OPEN                           TTL=128 WIN=65535
     3389  CLOSED                         TTL=128 WIN=0

  [PHASE 2] Service Banner Grabbing
  ✓    21  FTP   → LabFTP Server (Vulnerable Demo) Ready
  ✓    80  HTTP  → Apache/2.4.68 (Debian)

  [PHASE 3] OS Fingerprinting (7-Vector Engine)
  Candidate   : Open-Port TCP SYN/ACK
  Likely OS   : Windows (72%) | Windows 10 / 11 / Server 2016+ (71% tier)
  IP ID Class : STRICT_INCREMENTAL (deltas: [1, 1, 2, 1, 1])
  Clock Rate  : ~1001.0 Hz (HZ_1000) | Uptime: ~3 day(s), 5 hour(s)
  ECN Probe   : Ignored (Flags: 0x12) [Default Windows Stack]
  Rule-Breaker: RST on Open Port (Flags=0x14) [Windows RFC-Breaker]
  ICMP / UDP  : Code=0 normalized, TTL=128, U1 quotes 328B payload

  [PHASE 5] Exploit Execution
  [EXPLOIT] FTP Anonymous Login (port 21)        → Status: SUCCESS ✓
  [EXPLOIT] HTTP Directory Traversal (port 80)  → Status: SUCCESS ✓ (8 payloads)
```

---

### 4. Run Active Defense with Auto-Quarantine
On the victim machine, run the real-time detector in blocking mode:
```powershell
python Imp\defense\main.py `
  --adapter "\Device\NPF_{VICTIM-ADAPTER-GUID}" `
  --threshold 8 `
  --window 10 `
  --block
```
*When an attacker exceeds the scan threshold, the defense engine dynamically generates firewall rules and drops all ongoing traffic and exploit attempts:*
```text
[ALERT] Possible TCP port scan from 192.168.1.105 (Threshold: 8 ports in 10s)
[MITIGATION] Blocked TCP traffic from 192.168.1.105
             Spawned Rule: CustomPortScanBlock_192_168_1_105
```

---

## 🎯 7 Advanced OS Fingerprinting Techniques

| # | Technique | Target Signature | Technical Mechanism |
|---|---|---|---|
| **1** | **Closed-Port RST Detection** | `TTL=128, WIN=0` vs `TTL=64, WIN=0` | Evaluates kernel TCP resets to accurately fingerprint hosts **with zero open ports** (RFC 793/9293). |
| **2** | **Multi-Probe IP ID Tracking** | `ALL_ZERO` vs `STRICT_INC` | Classifies IPv4 identification sequences: Linux forces 0 on DF packets (RFC 6864); Windows strictly increments counters. |
| **3** | **TCP Timestamp Clock Estimation** | `1000Hz` vs `250Hz` vs `PRNG` | Computes clock frequency ($\Delta TSval / \Delta t$) via RFC 7323 to infer OS family and estimate live system uptime. |
| **4** | **RFC 3168 ECN Reflection** | `ECE` reflection | Sends `SYN+ECE+CWR` probes: Windows ignores ECN flags; Linux and macOS reflect `ECE` in SYN/ACK. |
| **5** | **"Rule-Breaker" TCP Flags** | `SYN+FIN` Response | Violates RFC 793 state machine: Windows improperly resets open ports (`RST 0x14`); Linux drops on open; Darwin BSD drops both. |
| **6** | **ICMP/UDP Battery & Fallback** | Code Normalization & Quoting | Windows normalizes ICMP `Code 9 -> 0` and quotes 328B on UDP unreachable; Darwin sets `DF=1` and quotes exactly 28B (RFC 792). Automatically bypasses firewalls. |
| **7** | **Cross-Layer Banner Scoring** | Header Order & Daemon Signatures | Correlates banners with kernel fingerprints and evaluates RFC 7230 HTTP header ordering (`Server` vs `Date`). |

---

## 📊 Empirical Test Suite & Verified Logs (`final-log/`)

Real-world test runs across diverse operating systems and network states are preserved in [`final-log/`](final-log/):

| Target Device | Operating System | Environment | Tested Ports | Observed Outcome | Archive Log |
|---|---|---|---|---|---|
| **Desktop PC** | Windows 11 Pro | Local LAN (`192.168.0.116`) | `21, 22, 80, 81` | Open/Closed mixed. Exploits: 2/2 SUCCESS. OS: **Windows (60%)** | [`win.log`](final-log/win.log) |
| **Desktop PC** | Windows 11 (Defense ON) | Local LAN (`192.168.0.116`) | `21-24, 80-84` | 7 ports FILTERED mid-scan. Exploit FAILED ✗ (quarantined) | [`win-atk-blocker.log`](final-log/win-atk-blocker.log) |
| **Kali Linux** | Debian Kernel 6.x | VirtualBox Host-Only VM | `22, 80, 81, 8080` | Closed RST (76%), ICMP fallback (67%), Full Stack (72%) | [`kali.log`](final-log/kali.log) |
| **Apple iPad** | iPadOS 17 (Darwin BSD) | Wi-Fi (`192.168.0.152`) | `80, 8080` | Darwin Option Layout (`WSCALE` before `TSval`), PRNG clock | [`ipad.log`](final-log/ipad.log) |
| **Android Phone** | Linux Kernel 5.x | Wi-Fi (`192.168.0.169`) | `2221, 2122` | Linux Option Layout (`SACK` before `TSval`), `IP ID = 0` | [`phn.log`](final-log/phn.log) |
| **Scale Test** | Windows 10/11 | Wi-Fi (`192.168.1.104`) | `100 Ports` (2 batches) | Batch 1: 4 Open, 46 Closed (71%). Batch 2: 50 Closed RST (69%) | [`scan_100_ports.log`](final-log/scan_100_ports.log) |

---

## 📁 Repository Architecture

```
├── README.md                      # Master project documentation
├── HOW_TO_RUN.md                  # Comprehensive terminal runbook
├── design_report.md               # Formal technical & architectural report
├── test_scan_100.ps1              # Automated dual-batch 100-port test harness
├── final-log/                     # Verified empirical test logs across 5 hardware targets
│   ├── win.log                    # Baseline attack & successful exploit log
│   ├── win-atk-blocker.log        # Active firewall auto-quarantine proof log
│   ├── kali.log                   # Full Linux kernel 6.x verification suite
│   ├── ipad.log                   # Apple Darwin BSD stack verification log
│   ├── phn.log                    # Android / Linux mobile stack verification log
│   └── scan_100_ports.log         # 100-port scale run log (firewall-off validation)
└── Imp/
    ├── common/
    │   ├── packet.py              # Raw frame builder/parser & RFC 1071 Internet checksums
    │   └── npcap.py               # Low-level ctypes bindings to Npcap C API
    ├── attacker/
    │   ├── main.py                # Pipeline orchestrator
    │   ├── scanner.py             # Phase 1: Raw SYN port scanner
    │   ├── banner.py              # Phase 2: Application banner grabber
    │   ├── fingerprint.py         # Phase 3: 7-technique heuristic OS fingerprinting engine
    │   └── exploits/              # Phase 5: Targeted exploit modules (FTP, SSH, HTTP)
    ├── defense/
    │   ├── detector.py            # Sliding-window detector & Windows Firewall blocker
    │   └── main.py                # Defensive CLI entry point
    ├── victim/                    # Simulated vulnerable target daemons (FTP, HTTP)
    └── tests/
        ├── test_packet.py         # Unit tests for packet encoders and checksums
        └── test_fingerprint.py    # 51 unit tests validating all fingerprinting heuristics
```

---

## 🛡️ Operational Safety Rails

To ensure ethical execution and eliminate network disruption risks, hardcoded safety rails are enforced:
- **Private Subnets Only**: Rejects non-RFC 1918 targets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Strict Probe Ceiling**: Hard limit of **$\le 50$ ports per command** (`MAX_PROBES = 50`).
- **Mandatory Delay**: Minimum **$0.2s$ inter-probe rate-limiting** (default $0.5s$) to prevent resource starvation.
- **Port Boundary Enforcement**: Input validation guarantees $1 \le \text{port} \le 65535$.

---

## 🧪 Automated Test Suite

Run the full suite of **51 unit tests** validating low-level framing, checksums, and heuristic models:
```powershell
python -m pytest Imp\tests\ -v
```
```text
============================== 51 passed in 0.08s ==============================
```

---

## 📚 Standards & Key References

- **RFC 793 / RFC 9293**: *Transmission Control Protocol* (Connection state machine, TCP flags & RST emission)
- **RFC 1071**: *Computing the Internet Checksum* (One's complement vector arithmetic)
- **RFC 6864**: *Updated Specification of the IPv4 ID Field* (Standardizes `IP ID = 0` on DF datagrams)
- **RFC 7323**: *TCP Extensions for High Performance* (Window scale factor & TCP Timestamp options)
- **RFC 3168**: *The Addition of Explicit Congestion Notification (ECN) to IP*
- **RFC 792 / RFC 1122**: *Internet Control Message Protocol (ICMP) & Host Requirements*
- **Fyodor (Gordon Lyon)**: *"Remote OS detection via TCP/IP Stack Fingerprinting"*, Phrack Magazine Issue 54 (1998)
- **Michal Zalewski (lcamtuf)**: *p0f v3 Passive OS Fingerprinting & TCP/IP Sequence Analysis*
- **MITRE ATT&CK**: T1046 (Network Service Discovery) & T1078 (Valid Accounts)
- **OWASP Top 10**: A01:2021 (Broken Access Control — Path Traversal)
