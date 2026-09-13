# Final Empirical Verification Logs Suite

This directory isolates the **crucial, legitimate test logs** that capture the complete end-to-end operational picture of the custom port scanner, OS fingerprinting engine, exploit modules, and active defense mitigation across all tested hardware platforms, live LAN targets, and virtualized environments.

---

## 1. Summary Matrix of Core Logs

| # | Log File | Target Platform | Environment & IP | Tested Ports | Open / Closed / Filtered | Defense State | Exploits Executed | OS Fingerprint Attribution |
|---|---|---|---|---|---|---|---|---|
| **1** | [`win.log`](file:///final-log/win.log) | **Desktop Windows** | Windows 11 Pro (`192.168.0.116`) | `21, 22, 80, 81` | 2 Open (`21, 80`),<br>2 Closed (`22, 81`) | **OFF / Passive** (Standard detection) | **ON & SUCCESSFUL**<br>✓ FTP Anon (Port 21)<br>✓ HTTP Traversal (Port 80) | **Windows (60%)**<br>(SYN/ACK: TTL 128, WIN 65535, Windows Option Order) |
| **2** | [`win-atk-blocker.log`](file:///final-log/win-atk-blocker.log) | **Desktop Windows** (Active Defense) | Windows 11 Pro (`192.168.0.116`) | `21-24, 80-84` (9 ports) | 2 Open (`21, 80`),<br>**7 Filtered / Dropped** | **ON / Active Blocker**<br>(Auto-Quarantine Firewall) | **ON & MITIGATED**<br>✓ FTP logged in initially<br>✗ HTTP Traversal **FAILED** (Blocked) | **Windows (60%)**<br>(Pre-quarantine SYN/ACK captured before block) |
| **3** | [`kali.log`](file:///final-log/kali.log) | **Kali Linux VM** | Debian GNU/Linux Kernel 6.x (`192.168.56.101`) | `22, 80, 81, 8080` | Multi-scenario suite:<br>• 3 Closed (RST test)<br>• 3 Closed (ICMP test)<br>• 3 Open, 1 Closed | **OFF / Passive** | **OFF / Skipped**<br>(`--skip-exploits`) | **Linux (72%–76%)**<br>• Closed RST: 76% (ALL_ZERO IP ID)<br>• ICMP Fallback: 67%<br>• Full Stack: 72% (Debian Banners) |
| **4** | [`ipad.log`](file:///final-log/ipad.log) | **Apple iPad** | iPadOS 17 / Darwin BSD (`192.168.0.152`) | `80, 8080` | 1 Open (`80` VLC Web),<br>1 Closed (`8080`) | **OFF / Passive** | **OFF / Skipped**<br>(`--skip-exploits`) | **macOS / BSD (48%)**<br>(TTL 64, Darwin Option Order: WSCALE before TIMESTAMP) |
| **5** | [`phn.log`](file:///final-log/phn.log) | **Android Smartphone** | Android / Linux Kernel 5.x (`192.168.0.169`) | `2221, 2122` | 1 Open (`2221` WiFi FTP),<br>1 Closed (`2122`) | **OFF / Passive** | **OFF / Skipped**<br>(`--skip-exploits`) | **Linux (58%)**<br>(TTL 64, Linux Option Order: SACK before TIMESTAMP, IP ID = 0) |
| **6** | [`scan_100_ports.log`](file:///final-log/scan_100_ports.log) | **Live 100-Port Scale Test** | Windows 10/11 Target (`192.168.1.104`) | `100 Ports`<br>(2 batches of 50) | • **Batch 1**: 4 Open (`135, 139, 445, 1025`), 46 Closed<br>• **Batch 2**: 50 Closed | **OFF / Passive** (Firewall disabled) | **OFF / Skipped**<br>(`--skip-exploits`) | **Windows (71% & 69%)**<br>• Batch 1 (SYN/ACK): 71% (1001 Hz clock, Windows Option Order)<br>• Batch 2 (RST): 69% (Strict incremental IP ID, Win=0) |
| **7** | [`ssh_quiet.log`](file:///final-log/ssh_quiet.log) | **Windows Target** (SSH Quiet Mode) | Windows 11 (`192.168.1.104` — `AisheePC`) | `22` (SSH) | 1 Open (`22`) | **OFF / Passive** | **ON & SUCCESSFUL**<br>✓ SSH Brute Force (`test:test123`)<br>• Silent Recon (`whoami`, `hostname`, `ipconfig`, `ver`) | **Windows (75%)**<br>(SYN/ACK: TTL 128, OpenSSH banner, 1000 Hz clock, Strict incremental IP ID) |
| **8** | [`ssh_attack.log`](file:///final-log/ssh_attack.log) | **Windows Target** (SSH Loud Mode) | Windows 11 (`192.168.1.104` — `AisheePC`) | `22` (SSH) | 1 Open (`22`) | **OFF / Passive** | **ON & SUCCESSFUL**<br>✓ SSH Brute Force (`test:test123`)<br>• Spooky Trophy File (`PROOF_OF_ACCESS.txt`)<br>• 1000-Loop Payloads (`.exe`, `.bat`, `.py`)<br>• Physical Voice Alert on Speakers | **Windows (75%)**<br>(SYN/ACK: TTL 128, OpenSSH banner, 1000 Hz clock, Strict incremental IP ID) |

---

## 2. Detailed Breakdown of Each Log

### 1. `win.log` — Windows Full Attack Chain with Exploits
- **Purpose:** Demonstrates the baseline attack chain against an unprotected Windows target running vulnerable lab services.
- **Port States:** Shows both `OPEN` (FTP 21, HTTP 80) and `CLOSED` (22, 81 returning kernel TCP RST).
- **Service Banners:** Banners extracted for both LabFTP Server and VulnHTTP.
- **Fingerprinting:** Primary candidate is `Open-Port TCP SYN/ACK` with initial TTL=128, Windows TCP option ordering (`MSS`, `WSCALE`, `SACK_PERMITTED`, `TIMESTAMP`), and non-zero IP ID with DF bit set.
- **Exploits:** Both exploit modules executed and confirmed:
  - FTP Anonymous Login succeeded and read `/pub`.
  - HTTP Directory Traversal succeeded across 8 payloads (retrieved `win.ini` and `README.md`).

### 2. `win-atk-blocker.log` — Active Defense & Firewall Auto-Quarantine
- **Purpose:** Demonstrates the defensive auto-quarantine capability (10% bonus feature).
- **Behavior:** The Desktop defense engine was run with `--block --threshold 8 --window 10`. When the scanner probed its 8th port, the defense engine detected the scan pattern and dynamically created a Windows Defender Firewall rule:
  `CustomPortScanBlock_192_168_0_105`
- **Port States:** Subsequent ports (`22, 23, 24, 81, 82, 83, 84`) return `NO RESPONSE / POSSIBLY FILTERED` due to firewall dropping attacker packets.
- **Exploit Mitigation:** The HTTP Directory Traversal exploit **failed** because the TCP handshake could no longer complete.

### 3. `kali.log` — Kali Linux Virtual Machine Multi-Phase Battery
- **Purpose:** Documents exhaustive validation against an enterprise Linux OS (Debian / Kali Linux Kernel 6.x on VirtualBox).
- **Test 1 (Closed-Port RST):** All ports closed (`22, 80, 81`). Demonstrates OS fingerprinting when zero ports are open. Accurately identifies Linux (76%) via closed-port TCP RST (TTL=64, Window=0, RFC 6864 `IP ID = [0, 0, 0]` constant zero, and RFC 793 SYN+FIN flag drop).
- **Test 2 (Autonomous ICMP Fallback):** Explicitly evaluates `--prefer-icmp`. Proves OS attribution (Linux 67%) via ICMP Echo Reply Code 9 reflection and DF=0 bit clearing.
- **Test 3 (Multi-Service & Cross-Layer Correlation):** OpenSSH (`22`), Apache (`80`), and Python SimpleHTTP (`8080`). Fingerprints Linux (72%) with cross-layer banner matching against Debian GNU/Linux signatures and RFC 7230 header order analysis.

### 4. `ipad.log` — Apple iPad (Darwin / BSD Stack)
- **Purpose:** Validates fingerprinting against Apple's Darwin/BSD network stack in a mobile form factor.
- **Port States:** Port 80 Open (VLC for iOS WiFi Web Sharing), Port 8080 Closed.
- **Fingerprinting:** Identifies macOS / BSD (48% / 100% modern BSD tier).
- **Key Evidence:** Initial TTL=64, Apple Darwin signature option ordering putting `WSCALE` before `TIMESTAMP`, window scale factor 5, and RFC 7323 PRNG randomized timestamp offset.

### 5. `phn.log` — Android Mobile Device (Linux Kernel 5.x)
- **Purpose:** Validates fingerprinting against modern Android/Linux mobile stacks.
- **Port States:** Port 2221 Open (WiFi FTP Server app), Port 2122 Closed.
- **Fingerprinting:** Identifies Linux (58% / 100% modern Linux tier).
- **Key Evidence:** Initial TTL=64, RFC 6864 compliant `IP ID = 0` with DF bit set, and standard Linux option ordering putting `SACK_PERMITTED` before `TIMESTAMP`.

### 6. `scan_100_ports.log` — Extended 100-Port Comprehensive Verification
- **Purpose:** Demonstrates large-scale port scanning across 100 distinct ports (split into two sequential 50-port batches to comply with the safety limit `MAX_PROBES = 50`).
- **Target:** Real live Windows machine (`192.168.1.104`) scanned over physical Wi-Fi adapter with firewall disabled to evaluate native kernel stack behavior across wide port ranges.
- **Batch 1 (Low & System Ports 20–1723):**
  - **Open Ports Discovered (4):** Port 135 (MSRPC Endpoint Mapper), Port 139 (NetBIOS Session), Port 445 (Microsoft-DS / SMB), and Port 1025 (Dynamic RPC).
  - **Closed Ports (46):** All other 46 ports returned native kernel `TCP RST` packets (`CLOSED TTL=128 WIN=0`).
  - **Fingerprint Attribution:** Candidate `Open-Port TCP SYN/ACK` identified **Windows 10 / 11 / Server 2016+ (71% confidence)** with:
    - Initial TTL=128, TCP window=65535, DF=1.
    - Windows TCP option ordering: `['MSS', 'WSCALE', 'SACK_PERMITTED', 'TIMESTAMP']`.
    - Strict incremental IP ID sequence (avg delta: 1.3).
    - TCP timestamp clock frequency of ~1001.0 Hz (`HZ_1000`, 1ms tick rate).
    - Default Windows ECN negotiation behavior (`ECE=0, CWR=0` in SYN/ACK).
    - Windows rule-breaker invalid flag test (RST on open port).
    - Windows ICMP Code 0 normalization and 328-byte UDP quoting.
- **Batch 2 (High Ports, Web Apps, RPC & Cloud/Dev Services 1883–49164):**
  - **Closed Ports (50):** All 50 probed ports were genuinely closed, immediately emitting `CLOSED TTL=128 WIN=0`.
  - **Fingerprint Attribution:** Candidate `Closed-Port TCP RST` (Idea 1 Zero-Open-Port Detection) identified **Windows (69% confidence)** powered by strict incremental IP ID sequence (`[13207, 13208, ...]`, avg delta: 1.1), zero window size, and initial TTL 128.

### 7. `ssh_quiet.log` — Windows SSH Weak Credential Exploitation (Quiet / Stealth Mode)
- **Purpose:** Proves remote code execution (RCE) via SSH brute-force in a non-intrusive, covert manner suitable for quiet penetration testing and automated inventory auditing.
- **Target:** Live Windows 11 machine (`192.168.1.104` — `AisheePC`) running Microsoft OpenSSH for Windows (`SSH-2.0-OpenSSH_for_Windows_9.5`) on port 22.
- **Fingerprinting:** Candidate `Open-Port TCP SYN/ACK` identified **Windows (75% confidence)** via:
  - Initial TTL=128, TCP window=65535, DF=1.
  - Windows TCP option ordering: `['MSS', 'WSCALE', 'SACK_PERMITTED', 'TIMESTAMP']`.
  - Strict incremental IP ID sequence (`deltas: [2, 1]`).
  - Cross-layer banner signature correlation: `OpenSSH_for_Windows` matched Windows Microsoft OpenSSH signature.
  - Timestamp clock frequency: ~992.1 Hz (`HZ_1000`, standard 1ms Windows tick rate).
  - Invalid TCP flags (`SYN+FIN` rule-breaker): Elicited `RST` on open port (Flags `0x14`).
  - ICMP Code 0 normalization and 328-byte UDP quoting.
- **Exploit Execution (Quiet Mode):**
  - Brute-forced bounded 20-pair credential wordlist.
  - Successfully authenticated as `test:test123` on attempt 15.
  - Executed command-line reconnaissance:
    - `whoami` $\to$ `aisheepc\test`
    - `hostname` $\to$ `AisheePC`
    - `ipconfig` $\to$ `169.254.17.114, 169.254.58.27, 192.168.1.104`
    - `os_info` $\to$ `Microsoft Windows [Version 10.0.26200.9445]`
  - **Zero noise:** No files written to the desktop, zero audio alerts triggered.

### 8. `ssh_attack.log` — Windows SSH Weak Credential Exploitation (Loud / Full Attack Mode)
- **Purpose:** Demonstrates full multi-modal post-exploitation, dropping persistent interactive desktop payloads and triggering hardware-level audio alerts to prove undeniable control of the target machine.
- **Target:** Live Windows 11 machine (`192.168.1.104` — `AisheePC`) running OpenSSH on port 22.
- **Fingerprinting:** Identifies Windows (75% confidence) with identical high-confidence empirical features.
- **Exploit Execution (Loud Mode):**
  - Successfully authenticated as `test:test123` (attempt 15/20).
  - **Spooky Desktop Trophy:** Deployed `PROOF_OF_ACCESS.txt` on the Desktop with the security warning:
    > *"Abhishek and Turjo have taken over your computer for their Security project! You should be careful with SSH xd"*
  - **Interactive 1000-Loop Payloads (3 formats):** Base64-encoded and deployed 3 double-clickable executables directly onto `C:\Users\test\Desktop` and `C:\Users\Public\Desktop`:
    1. `HACKED.exe`: Native Windows executable compiled on the fly using Windows' built-in `csc.exe` compiler.
    2. `HACKED.bat`: Native Windows batch script.
    3. `hacked.py`: Python exploit script.
    *(When double-clicked, Windows opens a Command Prompt console with matrix neon-green font, streaming a 1000-iteration loop: `[1000/1000] YOU ARE HACKED BY ABHISHEK AND TURJO xd` with a typewriter animation before holding the terminal open).*
  - **Physical Speech Synthesizer Voice Alert:** Sent synthesized audio commands through the victim PC's sound card and physical speakers:
    > *"Warning. Abhishek and Turjo have taken over your computer for their Security project. You should be careful with S-S-H. haha."*
