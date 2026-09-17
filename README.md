# PortScan & OS Fingerprint Toolkit

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Npcap-lightgrey.svg)](https://npcap.com/)
[![Dependencies](https://img.shields.io/badge/dependencies-Zero%20Scapy%20%2F%20Zero%20Nmap-success.svg)]()
[![Tests](https://img.shields.io/badge/tests-68%20passing%20%28100%25%29-brightgreen.svg)]()
[![Defense](https://img.shields.io/badge/defense-Multi--Vector%20Auto--Quarantine-red.svg)]()

> A high-performance, raw Layer-2/3/4 reconnaissance, adaptive exploitation, and active defense suite built **from scratch** in Python. Features hand-crafted TCP SYN port scanning, a 7-technique heuristic OS fingerprinting engine, a dynamic 5-phase reconnaissance-to-weaponization pipeline, multi-vector exploit modules, and a real-time multi-vector defense engine with cross-platform (Windows `netsh` / Linux `iptables`) auto-quarantine and self-healing TTL release.

---

## ⚡ Highlights

- **Pure Raw Packet Crafting**: Manually constructs Ethernet, IPv4, TCP, UDP, and ICMP frames byte-by-byte using Python `struct` and native `Npcap` C-bindings. Computes RFC 1071 one's-complement checksums directly (**zero Scapy, zero Nmap binaries**).
- **Stealth Half-Open SYN Scanner**: High-speed SYN probing without completing the 3-way handshake, evading application logging and enforcing rate-limiting safety rails.
- **7-Vector Heuristic OS Fingerprinting Engine**: 
  - **Zero-Open-Port RST Detection** (accurately identifies OS even when all ports are closed via RFC 793/9293 resets)
  - **Sequential IP ID Tracking** (`ALL_ZERO` Linux vs `STRICT_INCREMENTAL` Windows vs `RANDOM_POSITIVE` Darwin BSD)
  - **TCP Timestamp Clock Rates & Uptime** (~1000Hz Windows vs ~250Hz Linux vs Apple PRNG randomized offsets)
  - **RFC 3168 ECN Reflection Probing** (`ECE`/`CWR` active flag negotiation)
  - **"Rule-Breaker" TCP Flag Probes** (`SYN+FIN` state machine testing)
  - **ICMP/UDP Battery & Autonomous Fallback** (Code 0 normalization, 328B vs 28B quoting, stealth firewall bypass)
  - **Cross-Layer Banner Correlation** (RFC 7230 HTTP header ordering & distribution daemon signatures)
- **Phase 4 Dynamic OS-Aware Payload Selection**: Bridges reconnaissance with weaponization—automatically tailoring directory traversal targets (`win.ini` vs `/etc/passwd`) and remote execution commands (`whoami` vs `id`) based on real-time fingerprint probability.
- **5 Comprehensive Exploit Modules**:
  1. **Anonymous FTP Access**: Unauthenticated credential discovery and directory enumeration (`T1078`).
  2. **Multi-Stage FTP Write $\to$ Web Shell CGI RCE**: Uploads sandboxed `shell.py`, executes commands via HTTP CGI, and autonomously deletes forensic traces via FTP `DELE`.
  3. **FTP Bounce Attack**: Internal port pivoting with automated detection of host kernel/WFP firewall mitigation (`WinError 10053`).
  4. **OS-Aware HTTP Path Traversal**: Dynamic path traversal exploiting unmitigated web daemons across multiple encodings.
  5. **SSH Weak Credential Attack (Quiet & Loud Modes)**: Dictionary authentication against OpenSSH, featuring silent reconnaissance or full interactive post-exploitation with 1000-loop Matrix payloads, spooky desktop trophy files, and hardware speech synthesizer voice alerts.
- **Multi-Vector Active Defense & Auto-Quarantine (10% Bonus)**: Cross-platform (Windows/Linux) detection engine combining a fast sliding-window SYN/port-diversity check, a slow long-window stealth-scan check, invalid TCP flag inspection (NULL/FIN-only/XMAS/SYN+FIN), and decoy honeyport traps — with dynamic firewall quarantine (`netsh advfirewall` / `iptables`), whitelist immunity, self-healing TTL auto-release, and structured JSON incident logging (`defense_incident_log.json`).

---

## 🚀 The 5-Phase End-to-End Pipeline

```
[ Attacker: Raw SYN Scan ] ──► [ Banner Grabbing ] ──► [ 7-Vector OS Fingerprint ] ──► [ Dynamic Payload Selection ]
            │                                                                                     │
            │                                                                                     ▼
            ▼                                                                       ┌───────────────────────────┐
┌────────────────────────────────────────────────────────┐                         │  1. FTP Anonymous Access  │
│ Victim: Multi-Vector Defense Engine (Win/Linux)        │                         │  2. FTP Web Shell CGI RCE │
│ - Fast window (SYN rate + port diversity) & slow window│                         │  3. FTP Bounce Pivoting   │
│ - Invalid TCP flags (NULL/FIN/XMAS/SYN+FIN) & honeypots│                         │  4. HTTP Path Traversal   │
│ - [QUARANTINE] netsh / iptables + self-healing TTL     │                         │  5. SSH Quiet / Loud RCE  │
└────────────────────────────────────────────────────────┘                         └───────────────────────────┘
```

---

## 💻 Quick Start

### 1. Prerequisites
- **Operating System**: Windows 10 or 11 (Run terminal as **Administrator**)
- **Npcap**: Installed in "WinPcap API-compatible Mode" ([npcap.com](https://npcap.com/))
- **Python**: 3.11+ (Install dependencies: `pip install -r Imp/requirements.txt`)

### 2. Identify Network Interface GUID
```powershell
python -c "import sys; sys.path.insert(0, 'Imp'); from common.npcap import list_adapters; [print(f'{a[0]} -> {a[1]}') for a in list_adapters()]"
```
*Locate your active network adapter GUID (e.g. `\Device\NPF_{79613882-...}`).*

---

### 3. Launch the Full Attack Chain
```powershell
python Imp\attacker\main.py `
  --adapter "\Device\NPF_{YOUR-ADAPTER-GUID}" `
  --target 192.168.0.116 `
  --ports 21 22 80 81
```

#### Live Terminal Preview:
```text
═════════════════════════════════════════════════════════════════
  CUSTOM PORT SCANNER — ATTACK TOOLKIT
═════════════════════════════════════════════════════════════════
  Target       : 192.168.0.116
  Ports        : [21, 22, 80, 81]
  
  [PHASE 1] TCP SYN Port Scanning
  ─────────────────────────────────────────────────────────────
       21  OPEN                           TTL=128 WIN=65535
       22  NO RESPONSE / POSSIBLY FILTERED
       80  OPEN                           TTL=128 WIN=65535
       81  NO RESPONSE / POSSIBLY FILTERED

  [PHASE 2] Service Banner Grabbing
  ✓    21  FTP   → LabFTP Server (Vulnerable Demo) Ready
  ✓    80  HTTP  → VulnHTTP/1.0 (Lab Demo)

  [PHASE 3] OS Fingerprinting (7-Vector Engine)
  Candidate   : Open-Port TCP SYN/ACK
  Likely OS   : Windows (62%) | Windows 10 / 11 / Server 2016+ (71% tier)
  IP ID Class : STRICT_INCREMENTAL (deltas: [2, 3], avg: 2.5)
  Clock Rate  : ~1000 Hz (HZ_1000 / 1ms tick)
  ECN Probe   : Ignored (ECE=0, CWR=0) [Default Windows Stack]
  Rule-Breaker: Silently dropped on open port
  ICMP / UDP  : Code=0 normalized, TTL=128

  [PHASE 4] OS-Aware Payload Selection
  Target OS   : Windows
  Traversal   : windows\win.ini, win.ini variations
  RCE Command : whoami

  [PHASE 5] Exploit Execution
  ✓ [EXPLOIT 1] FTP Anonymous Login (port 21)       → Status: SUCCESS
  ✓ [EXPLOIT 2] FTP Write -> Web Shell -> RCE      → Status: SUCCESS (whoami: homed01\turjo)
  ✗ [EXPLOIT 3] FTP Bounce Attack (port 21)         → Status: FAILED (Mitigated by host WFP)
  ✓ [EXPLOIT 4] HTTP Directory Traversal (port 80) → Status: SUCCESS (3 payloads exfiltrated win.ini)
```

---

### 4. Multi-Vector Active Defense with Auto-Quarantine
On the victim machine (Windows or Linux), start the real-time multi-vector defense engine:
```powershell
python Imp\defense\main.py `
  --adapter "\Device\NPF_{VICTIM-ADAPTER-GUID}" `
  --threshold 8 --distinct-ports 5 --window 10 `
  --long-threshold 20 --long-window 60 `
  --canary-ports 81 `
  --block --block-ttl 60
```
```powershell
# Linux / Kali equivalent
sudo python3 defense/main.py --adapter eth0 --block --block-ttl 60
```
*The engine watches four independent vectors simultaneously — a fast SYN/port-diversity window, a slow stealth-scan window, invalid TCP flag combinations (NULL/FIN-only/XMAS/SYN+FIN), and decoy honeyport hits on port 81 — and on any trigger dynamically injects a cross-platform firewall rule (`netsh advfirewall` on Windows, `iptables` on Linux), instantly severing the connection:*
```text
[ALERT] 192.168.0.105 | fast port scan (SYN=9, distinct ports=6 within 10.0s)
[MITIGATION] Blocked TCP traffic from 192.168.0.105
             Firewall rule : CustomPortScanBlock_192_168_0_105 (Windows)
             Trigger reason: fast port scan (SYN=9, distinct ports=6 within 10.0s)
             Auto-release  : after 60s (self-healing)
```
*Blocks auto-release after the configurable TTL (self-healing quarantine), whitelisted IPs (e.g. `--whitelist 192.168.0.1`) are never blocked, and every incident is appended to `defense_incident_log.json` for SIEM-style audit.*

---

### 5. SSH Weak Credential Exploits (Quiet & Loud Modes)
Automated multi-modal runners are available in `scripts/`:
```powershell
# Quiet Mode: Silent reconnaissance (whoami, hostname, ipconfig, os_info)
.\scripts\test_ssh_attack.ps1 quiet

# Loud Mode: Drops desktop trophy, 1000-loop Matrix payloads (.exe, .bat, .py), and triggers voice alert
.\scripts\test_ssh_attack.ps1 loud
```

---

## 🎯 7 Advanced OS Fingerprinting Techniques

| # | Technique | Target Signature | Technical Mechanism |
|---|---|---|---|
| **1** | **Closed-Port RST Detection** | `TTL=128, WIN=0` vs `TTL=64, WIN=0` | Evaluates kernel TCP resets to accurately fingerprint hosts **with zero open ports** (RFC 793/9293). |
| **2** | **Multi-Probe IP ID Tracking** | `ALL_ZERO` vs `STRICT_INC` vs `RANDOM` | Classifies IPv4 identification sequences: Linux forces 0 on DF packets (RFC 6864); Windows strictly increments counters; Darwin generates random positive IDs. |
| **3** | **TCP Timestamp Clock Estimation** | `1000Hz` vs `250Hz` vs `PRNG` | Computes clock frequency ($\Delta TSval / \Delta t$) via RFC 7323 to infer OS family and estimate live system uptime. |
| **4** | **RFC 3168 ECN Reflection** | `ECE` reflection | Sends `SYN+ECE+CWR` probes: Windows ignores ECN flags; Linux and macOS reflect `ECE` in SYN/ACK. |
| **5** | **"Rule-Breaker" TCP Flags** | `SYN+FIN` Response | Violates RFC 793 state machine: Windows improperly resets open ports (`RST 0x14`); Linux drops on open; Darwin BSD drops both. |
| **6** | **ICMP/UDP Battery & Fallback** | Code Normalization & Quoting | Windows normalizes ICMP `Code 9 -> 0` and quotes 328B on UDP unreachable; Darwin sets `DF=1` and quotes exactly 28B (RFC 792). Automatically bypasses firewalls. |
| **7** | **Cross-Layer Banner Scoring** | Header Order & Daemon Signatures | Correlates banners with kernel fingerprints and evaluates RFC 7230 HTTP header ordering (`Server` vs `Date`). |

---

## 📊 Empirical Test Suite & Verified Logs (`final-log/`)

The repository maintains **12 definitive empirical verification logs** in [`final-log/`](final-log/) documenting exhaustive testing across all features, scanning modes, and platforms:

| # | Log File | Target Platform | Environment & IP | Tested Ports | Defense State | Exploits Executed | OS Fingerprint Attribution |
|---|---|---|---|---|---|---|---|
| **1** | [`full-chain.log`](final-log/full-chain.log) | **Windows 11 Desktop** | Physical LAN (`192.168.0.116`) | `21, 22, 80, 81` | Passive $\to$ **Active Block** | **3/4 OK** (Run 1) $\to$ **Quarantined** (Run 2) | **Windows 10/11 (62%)** (Incremental IP IDs, 1000Hz) |
| **2** | [`cross-platform-exploit.log`](final-log/cross-platform-exploit.log) | **Adaptive Multi-OS** | Win 11 & Kali VM | `21, 22, 80, 81` | Passive | Dynamic `win.ini` + `whoami` vs `/etc/passwd` + `id` | **Win (62%)** vs **Linux (66%)** |
| **3** | [`kali.log`](final-log/kali.log) | **Kali Linux VM** (596 lines) | Debian Kernel 6.x (`192.168.56.101`) | `22, 80, 81, 8080` | Passive | Multi-scenario (Closed RST, ICMP fallback, Banners) | **Linux (72%–76%)** (ALL_ZERO IP IDs) |
| **4** | [`win.log`](final-log/win.log) | **Desktop Windows** | Windows 11 (`192.168.0.116`) | `21, 22, 80, 81` | Passive | FTP Anon & HTTP Traversal **2/2 SUCCESS** | **Windows (60%)** (TTL 128, WIN 65535) |
| **5** | [`win-atk-blocker.log`](final-log/win-atk-blocker.log) | **Desktop Windows** (Active Blocker) | Windows 11 (`192.168.0.116`) | `21-24, 80-84` (9 ports) | **Active Blocker ON** | 7 Ports Filtered, HTTP Traversal **Blocked** | **Windows (60%)** (Captured pre-block) |
| **6** | [`ipad.log`](final-log/ipad.log) | **Apple iPad** | iPadOS 17 (`192.168.0.152`) | `80, 8080` | Passive | Skipped | **macOS / BSD (48%)** (Darwin layout: WSCALE before TS) |
| **7** | [`phn.log`](final-log/phn.log) | **Android Smartphone** | Android 14 (`192.168.0.169`) | `2221, 2122` | Passive | Skipped | **Linux (58%)** (Linux layout: SACK before TS, IP ID 0) |
| **8** | [`scan_100_ports.log`](final-log/scan_100_ports.log) | **100-Port Scale Test** | Windows 10/11 (`192.168.1.104`) | `100 Ports` (2 batches) | Passive (Firewall off) | Skipped | **Windows (71% & 69%)** (4 Open, 96 Closed RST) |
| **9** | [`ssh_quiet.log`](final-log/ssh_quiet.log) | **Windows SSH (Quiet Mode)** | Windows 11 (`192.168.1.104`) | `22` (SSH) | Passive | SSH Brute Force $\to$ Silent Recon OK | **Windows (75%)** (Microsoft OpenSSH banner) |
| **10** | [`ssh_attack.log`](final-log/ssh_attack.log) | **Windows SSH (Loud Mode)** | Windows 11 (`192.168.1.104`) | `22` (SSH) | Passive | SSH Brute Force $\to$ Trophy, Payloads, Voice Alert | **Windows (75%)** (Microsoft OpenSSH banner) |
| **11** | [`defense_kali_test.log`](final-log/defense_kali_test.log) | **Kali Linux VM** (Multi-Vector Defense, Scenarios A-G) | VirtualBox Host-Only (`192.168.56.101`) | `21, 22, 80, 81, 135, 139, 443, 445, 8080` + 20 | **Active — Linux `iptables`** | Severed pre-recon (banners/OS probes dropped) | **Linux (55%–68%)** |
| **12** | [`defense_win_test.log`](final-log/defense_win_test.log) | **Windows 11 Desktop** (Multi-Vector Defense, Scenarios A-G) | Physical LAN (`192.168.0.116`) | `21, 22, 80, 81, 135, 139, 443, 445, 8080` + 20 | **Active — Windows `netsh`** | Severed pre-recon (handshakes aborted) | **Windows (71%–75%)** |

*Scenarios A-G cover: fast SYN scan detection, canary honeyport trap, low-and-slow stealth scan, invalid TCP flag inspection, whitelist immunity, self-healing TTL auto-release, and JSON incident log / firewall audit — see logs #11 and #12 above.*

*For complete technical details and architectural comparisons, see [`final-log/README.md`](final-log/README.md).*

---

## 📁 Repository Architecture

```
├── README.md                      # Master project overview & architectural documentation
├── HOW_TO_RUN.md                  # Comprehensive terminal runbook and walkthrough
├── testflow.md                    # Complete end-to-end testing workflow cheat sheet
├── testflow_commands.ps1          # Streamlined copy-pasteable execution command script
├── design-report/                 # Project design report and technical diagrams
├── final-report/                  # Final LaTeX project report (submission copy)
│   ├── final_report.tex           # Report source (11 sections: intro -> conclusion)
│   ├── final_report.pdf           # Compiled final report PDF
│   ├── sections/                  # Per-section .tex includes (implementation, fingerprint,
│   │                               #   attack steps, results, defense, verification, etc.)
│   ├── logs/                      # Copy of the 11 empirical logs cited in the report
│   └── rsc/                       # Report assets (e.g. university logo)
├── scripts/                       # Automated execution harnesses
│   ├── test_ssh_attack.ps1        # SSH exploit runner (Quiet and Loud modes)
│   ├── test_scan_100.ps1          # Dual-batch 100-port scale test runner
│   └── testflow_commands.ps1      # Clean command cheat sheet (no hardcoded paths)
├── final-log/                     # Definitive 12-log empirical verification suite
│   ├── README.md                  # Comprehensive log index & codebase coverage matrix
│   ├── full-chain.log             # End-to-end 5-phase attack & active defense isolation
│   ├── cross-platform-exploit.log # Adaptive OS-aware exploit comparison (Win vs Kali)
│   ├── kali.log                   # 596-line multi-phase Kali Linux battery
│   ├── win.log                    # Baseline Windows attack log
│   ├── win-atk-blocker.log        # Active firewall auto-quarantine proof log
│   ├── ipad.log                   # Apple Darwin BSD stack verification log
│   ├── phn.log                    # Android / Linux mobile stack verification log
│   ├── scan_100_ports.log         # 100-port scale probe log
│   ├── ssh_quiet.log              # SSH stealth reconnaissance log
│   ├── ssh_attack.log             # SSH loud mode log (trophy, payloads, voice alert)
│   ├── defense_win_test.log       # Multi-vector defense battery (Scenarios A-G, Windows)
│   └── defense_kali_test.log      # Multi-vector defense battery (Scenarios A-G, Kali Linux)
└── Imp/
    ├── common/
    │   ├── packet.py              # Raw frame builder/parser & RFC 1071 Internet checksums
    │   └── npcap.py               # Low-level ctypes bindings to Npcap C API
    ├── attacker/
    │   ├── main.py                # 5-phase pipeline orchestrator
    │   ├── scanner.py             # Phase 1: Raw SYN port scanner
    │   ├── banner.py              # Phase 2: Application banner grabber
    │   ├── fingerprint.py         # Phase 3: 7-technique heuristic OS fingerprinting engine
    │   └── exploits/              # Phase 4 & 5: Exploit modules & dynamic payload selector
    │       ├── os_payloads.py     # Phase 4: Dynamic OS-aware payload selector
    │       ├── ftp_anon.py        # Exploit 1: Anonymous FTP credential access
    │       ├── ftp_web_shell.py   # Exploit 2: Multi-stage FTP write -> Web shell CGI RCE
    │       ├── ftp_bounce.py      # Exploit 3: FTP bounce port pivoting & mitigation check
    │       ├── http_traversal.py  # Exploit 4: OS-aware HTTP directory traversal
    │       └── ssh_bruteforce.py  # Exploit 5: SSH dictionary brute-force (Quiet/Loud)
    ├── defense/
    │   ├── detector.py            # Multi-vector detector: fast/slow SYN windows, invalid TCP
    │   │                          #   flags (NULL/FIN/XMAS/SYN+FIN), honeypots, cross-platform
    │   │                          #   quarantine (netsh/iptables), TTL auto-release, JSON log
    │   └── main.py                # Defensive CLI entry point
    ├── victim/                    # Vulnerable lab services (FTP, HTTP with CGI)
    └── tests/                     # 68 automated unit tests (100% PASS)
        ├── test_packet.py         # Low-level frame encoders & checksum verification (5)
        ├── test_fingerprint.py    # 46 unit tests validating all 7 fingerprinting vectors
        ├── test_exploits.py       # 12 unit tests validating exploit safety & boundaries
        └── test_defense.py        # 5 unit tests validating multi-vector defense detector
```

---

## 🛡️ Operational Safety Rails

To ensure strictly ethical execution and eliminate network disruption risks, hardcoded safety rails are enforced throughout the codebase:
- **Private Subnets Only**: Rejects non-RFC 1918 targets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Strict Probe Ceiling**: Hard safety limit of **$\le 50$ ports per command** (`MAX_PROBES = 50`).
- **Mandatory Delay**: Minimum **$0.2s$ inter-probe rate-limiting** (default $0.5s$) to prevent network congestion.
- **Port Boundary Enforcement**: Input validation guarantees $1 \le \text{port} \le 65535$.
- **Web Shell Sandboxing**: The uploaded `shell.py` strictly restricts execution to a read-only command whitelist (`whoami`, `hostname`, `dir`, `pwd`, `ver`, `id`, `test`), rejecting arbitrary commands.
- **Autonomous Cleanup**: Exploit modules automatically issue cleanup requests (e.g. FTP `DELE shell.py`) immediately following execution, ensuring zero lingering forensic artifacts.

---

## 🧪 Automated Test Suite

Run the full suite of **68 automated unit tests** validating low-level packet crafting, heuristic models, exploit safety boundaries, and multi-vector defensive quarantine:
```powershell
python -m pytest Imp\tests\ -v
```
```text
============================== 68 passed in 0.19s ==============================
```

---

## 📚 Standards & Key References

- **RFC 793 / RFC 9293**: *Transmission Control Protocol* (Connection state machine, TCP flags & RST emission)
- **RFC 1071**: *Computing the Internet Checksum* (One's complement vector arithmetic)
- **RFC 6864**: *Updated Specification of the IPv4 ID Field* (Standardizes `IP ID = 0` on DF datagrams)
- **RFC 7323**: *TCP Extensions for High Performance* (Window scale factor & TCP Timestamp options)
- **RFC 3168**: *The Addition of Explicit Congestion Notification (ECN) to IP*
- **RFC 792 / RFC 1122**: *Internet Control Message Protocol (ICMP) & Host Requirements*
- **RFC 7230**: *Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing* (Header ordering analysis)
- **Fyodor (Gordon Lyon)**: *"Remote OS detection via TCP/IP Stack Fingerprinting"*, Phrack Magazine Issue 54 (1998)
- **Michal Zalewski (lcamtuf)**: *p0f v3 Passive OS Fingerprinting & TCP/IP Sequence Analysis*
- **MITRE ATT&CK**: T1046 (Network Service Discovery), T1078 (Valid Accounts), T1059 (Command and Scripting Interpreter)
- **OWASP Top 10**: A01:2021 (Broken Access Control — Path Traversal)
