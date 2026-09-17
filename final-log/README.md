# Empirical Verification Logs Suite

This directory consolidates the **definitive, empirical verification logs** capturing the complete end-to-end operational validation of the custom port scanner, OS fingerprinting engine, exploit modules, and active defense mitigation across all tested hardware platforms, live LAN targets, and virtualized operating systems.

---

## 1. Master Summary Matrix of Empirical Logs

| # | Log File | Target Platform | Environment & IP | Tested Ports | Open / Closed / Filtered | Defense State | Exploits Executed | OS Fingerprint Attribution |
|---|---|---|---|---|---|---|---|---|
| **1** | [`full-chain.log`](file:///final-log/full-chain.log) | **Windows 11 Desktop** (End-to-End Chain + Active Defense) | Physical LAN (`192.168.0.116`) | `21, 22, 80, 81` | • **Run 1**: 2 Open (`21, 80`), 2 Filtered<br>• **Run 2**: 2 Open, 2 Filtered $\to$ Quarantined | • **Run 1**: Passive<br>• **Run 2**: **Active Blocker ON** (`netsh` dynamic rule) | • **Run 1**: **3/4 Successful**<br>✓ FTP Anon (21)<br>✓ FTP Web Shell RCE (21+80)<br>✗ FTP Bounce (WFP blocked)<br>✓ HTTP Traversal (80)<br>• **Run 2**: **Severed Mid-Attack** | **Windows 10/11 (62%)**<br>(TTL 128, Win 65535, Strict incremental IP ID [27057, 27059, 27062], Windows Option Order, 1000 Hz Clock) |
| **2** | [`cross-platform-exploit.log`](file:///final-log/cross-platform-exploit.log) | **Adaptive Multi-OS Target Suite** (Win + Kali) | • Win 11 (`192.168.0.116`)<br>• Kali VM (`192.168.56.101`) | `21, 22, 80, 81` (Win)<br>`21, 22, 80` (Kali) | • Win: 2 Open, 2 Filtered<br>• Kali: 3 Open (`21, 22, 80`) | **OFF / Passive** | **Dynamic OS-Aware Exploits**:<br>• Win: `win.ini` + `whoami`<br>• Linux: `/etc/passwd` + `id`<br>Both: 3/4 successful (FTP Bounce mitigated) | • **Win**: Windows 11 (62%)<br>• **Kali**: Linux Kernel 6.x (66%) (ALL_ZERO IP ID `[0,0,0,0]`, OpenSSH Debian banner) |
| **3** | [`kali.log`](file:///final-log/kali.log) | **Kali Linux VM** (596-Line Exhaustive Battery) | Debian GNU/Linux Kernel 6.x (`192.168.56.101`) | `22, 80, 81, 8080` | Multi-scenario suite:<br>• 3 Closed (RST test)<br>• 3 Closed (ICMP test)<br>• 3 Open, 1 Closed | **OFF / Passive** | **OFF / Skipped**<br>(`--skip-exploits`) | **Linux (72%–76%)**<br>• Closed RST: 76% (ALL_ZERO IP ID)<br>• ICMP Fallback: 67% (Code 9 reflection)<br>• Full Stack: 72% (OpenSSH Debian, Apache, SimpleHTTP) |
| **4** | [`win.log`](file:///final-log/win.log) | **Desktop Windows** (Baseline Lab Run) | Windows 11 Pro (`192.168.0.116`) | `21, 22, 80, 81` | 2 Open (`21, 80`),<br>2 Closed (`22, 81`) | **OFF / Passive** | **ON & SUCCESSFUL**<br>✓ FTP Anon (Port 21)<br>✓ HTTP Traversal (Port 80) | **Windows (60%)**<br>(SYN/ACK: TTL 128, WIN 65535, Windows Option Order) |
| **5** | [`win-atk-blocker.log`](file:///final-log/win-atk-blocker.log) | **Desktop Windows** (Firewall Isolation Run) | Windows 11 Pro (`192.168.0.116`) | `21-24, 80-84` (9 ports) | 2 Open (`21, 80`),<br>**7 Filtered / Dropped** | **ON / Active Blocker**<br>(Auto-Quarantine Firewall) | **ON & MITIGATED**<br>✓ FTP logged in initially<br>✗ HTTP Traversal **FAILED** (Blocked) | **Windows (60%)**<br>(Pre-quarantine SYN/ACK captured before block) |
| **6** | [`ipad.log`](file:///final-log/ipad.log) | **Apple iPad** (Darwin / BSD Stack) | iPadOS 17 (`192.168.0.152`) | `80, 8080` | 1 Open (`80` VLC Web),<br>1 Closed (`8080`) | **OFF / Passive** | **OFF / Skipped**<br>(`--skip-exploits`) | **macOS / BSD (48%)**<br>(TTL 64, Darwin Option Order: WSCALE before TIMESTAMP, WScale=5, PRNG TS offsets) |
| **7** | [`phn.log`](file:///final-log/phn.log) | **Android Smartphone** (Mobile Linux 5.x) | Android 14 (`192.168.0.169`) | `2221, 2122` | 1 Open (`2221` WiFi FTP),<br>1 Closed (`2122`) | **OFF / Passive** | **OFF / Skipped**<br>(`--skip-exploits`) | **Linux (58%)**<br>(TTL 64, Linux Option Order: SACK before TIMESTAMP, IP ID = 0 with DF bit set) |
| **8** | [`scan_100_ports.log`](file:///final-log/scan_100_ports.log) | **Live 100-Port Scale Test** | Windows 10/11 Target (`192.168.1.104`) | `100 Ports`<br>(2 batches of 50) | • **Batch 1**: 4 Open (`135, 139, 445, 1025`), 46 Closed<br>• **Batch 2**: 50 Closed | **OFF / Passive** (Firewall disabled) | **OFF / Skipped**<br>(`--skip-exploits`) | **Windows (71% & 69%)**<br>• Batch 1 (SYN/ACK): 71% (1001 Hz clock, Windows Option Order)<br>• Batch 2 (RST): 69% (Strict incremental IP ID, Win=0) |
| **9** | [`ssh_quiet.log`](file:///final-log/ssh_quiet.log) | **Windows Target** (SSH Quiet Mode) | Windows 11 (`192.168.1.104` — `AisheePC`) | `22` (SSH) | 1 Open (`22`) | **OFF / Passive** | **ON & SUCCESSFUL**<br>✓ SSH Brute Force (`test:test123`)<br>• Silent Recon (`whoami`, `hostname`, `ipconfig`, `ver`) | **Windows (75%)**<br>(SYN/ACK: TTL 128, OpenSSH banner, 1000 Hz clock, Strict incremental IP ID) |
| **10** | [`ssh_attack.log`](file:///final-log/ssh_attack.log) | **Windows Target** (SSH Loud Mode) | Windows 11 (`192.168.1.104` — `AisheePC`) | `22` (SSH) | 1 Open (`22`) | **OFF / Passive** | **ON & SUCCESSFUL**<br>✓ SSH Brute Force (`test:test123`)<br>• Spooky Trophy File (`PROOF_OF_ACCESS.txt`)<br>• 1000-Loop Payloads (`.exe`, `.bat`, `.py`)<br>• Physical Voice Alert on Speakers | **Windows (75%)**<br>(SYN/ACK: TTL 128, OpenSSH banner, 1000 Hz clock, Strict incremental IP ID) |
| **11** | [`defense_kali_test.log`](file:///final-log/defense_kali_test.log) | **Kali Linux VM** (Multi-Vector Defense & Netfilter Mitigation) | Debian GNU/Linux Kernel 6.x (`192.168.56.101`) | Probed across `21, 22, 80, 81, 135, 139, 443, 445, 8080` + 20 ports | Multi-Scenario Suite:<br>• Fast scan: 3 Open, 5 Closed $\to$ Dropped<br>• Canary: Trapped on Port 81<br>• Stealth: Trapped on Port 123 | **ON / Linux Netfilter**<br>(Dynamic `iptables -I INPUT ... -j DROP` with Auto-Release TTL) | **SEVERED / MITIGATED**<br>• Banner grabs timed out (0/3)<br>• OS probes dropped<br>• Exploit execution prevented | **Linux (55%–68%)**<br>(Attacker severing confirmed before reconnaissance completion) |
| **12** | [`defense_win_test.log`](file:///final-log/defense_win_test.log) | **Windows 11 Desktop** (Multi-Vector Defense & Advanced Firewall) | Windows 11 Pro (`192.168.0.116`) | Probed across `21, 22, 80, 81, 135, 139, 443, 445, 8080` + 20 ports | Multi-Scenario Suite:<br>• Fast scan: 6 Open, 2 Closed $\to$ Quarantined<br>• Canary: Trapped on Port 81<br>• Stealth: Trapped on Port 123 | **ON / Windows Firewall**<br>(Dynamic `netsh advfirewall` inbound block with Auto-Release TTL) | **SEVERED / MITIGATED**<br>• Banners timed out post-block<br>• Handshakes aborted<br>• Exploit execution prevented | **Windows (71%–75%)**<br>(TTL 128, Win 65535, Strict incremental IP IDs `[34387...]`, 1001 Hz clock) |
| **13** | [`win-icmp.log`](file:///final-log/win-icmp.log) | **Windows 11 Desktop** (Autonomous ICMP Echo Fallback Verification) | Windows 11 Pro (`192.168.0.116`) | `21, 80, 81` | 3 Filtered / No Response (Firewall Active) | **ON / Windows Firewall** (Inbound drop) | **OFF / Skipped**<br>(`--skip-exploits`) | **Windows (94%)**<br>(ICMP Echo Reply: TTL 128, Code 9 normalized to Code 0, DF clear, IP ID 52494) |

---

## 2. In-Depth Technical Breakdown of Each Log

### 1. `full-chain.log` — Full Attack Chain & Active Defense Auto-Quarantine
- **Target Topology:** Windows 11 Desktop (`192.168.0.116`) probed from Windows 11 Laptop (`192.168.0.105`) over physical 802.11 Wi-Fi LAN.
- **Phased Workflow:**
  - **Phase 1 (SYN Scanning):** Probed ports `21, 22, 80, 81`. Ports 21 (FTP) and 80 (HTTP) returned `OPEN TTL=128 WIN=65535`.
  - **Phase 2 (Banner Grabbing):** Successfully extracted `LabFTP Server Ready` and `VulnHTTP/1.0 (Lab Demo)`.
  - **Phase 3 (OS Fingerprinting):** Scored Windows at **62% confidence** (71% Windows 10/11 tier) via TTL 128, window size 65535, strict incremental IP ID sequence (`[27057, 27059, 27062]`, average delta 2.5), TCP timestamp clock at ~1000 Hz, ECN flags ignored (`ECE=0, CWR=0`), and ICMP Code 9 probe normalized to Code 0.
  - **Phase 4 (Dynamic Payload Selection):** Automatically adapted payload profiles to Windows: traversal targeted `windows\win.ini` and RCE command targeted `whoami`.
  - **Phase 5 (Multi-Exploit Battery Execution):**
    - **Exploit 1 (FTP Anonymous Login):** `SUCCESS` — Authenticated as anonymous, listed directory via PASV mode, identified `/pub` and `/uploads`.
    - **Exploit 2 (FTP Write $\to$ Web Shell $\to$ HTTP CGI RCE):** `SUCCESS` — Uploaded `shell.py` into `uploads/`, issued HTTP GET `/uploads/shell.py?cmd=whoami`, successfully executed `whoami` returning `homed01\turjo`, and immediately cleaned up forensic footprint via `FTP DELE shell.py`.
    - **Exploit 3 (FTP Bounce Attack):** `FAILED (Mitigated)` — Probed bounce reflection against `192.168.0.116:80`. Rejected by Windows host network stack (`[WinError 10053] An established connection was aborted by the software in your host machine`), confirming modern kernel/WFP firewall mitigation against unauthorized third-party PORT socket pivoting.
    - **Exploit 4 (OS-Aware HTTP Traversal):** `SUCCESS` — 3 traversal payloads succeeded (standard backslash `..\win.ini`, forward-slash bypass `../../win.ini`, and URL-encoded `..%5c..%5cwin.ini`), exfiltrating Windows `win.ini` configuration.
- **Run 2 (Active Defense Auto-Quarantine — 10% Bonus):**
  - Desktop defense engine ran `defense/main.py --threshold 8 --window 10 --block`.
  - Upon observing 10 SYN packets across 5 distinct ports within the sliding window, the detector dynamically executed `netsh advfirewall firewall add rule name=CustomPortScanBlock_192_168_0_105 dir=in action=block remoteip=192.168.0.105 protocol=TCP profile=any`.
  - The attacker was instantly severed mid-attack: Exploit 1 completed, but Exploits 2, 3, and 4 experienced connection timeouts (`WinError 10060`), proving complete dynamic neutralization of the attack chain.

---

### 2. `cross-platform-exploit.log` — Dynamic OS-Aware Exploitation Across Operating Systems
- **Purpose:** Directly validates Phase 4 (OS-Aware Payload Selection) and the full multi-stage exploitation chain across heterogeneous operating systems:
  1. **Windows 11 Desktop (`192.168.0.116`):**
     - Fingerprinted as Windows (62%).
     - Traversal automatically adapted to Windows paths (`windows\win.ini`). Exfiltrated `[fonts] Arial=arial.ttf`.
     - Web Shell RCE dynamically dispatched `whoami`, returning `homed01\turjo`.
  2. **Kali Linux VM (`192.168.56.101`):**
     - Fingerprinted as Linux (66%, 100% modern Linux kernel tier).
     - Traversal automatically adapted to POSIX paths (`/etc/passwd`). Exfiltrated `root:x:0:0:root:/root:/usr/bin/zsh`.
     - Web Shell RCE dynamically dispatched Unix command `id`, returning `uid=0(root) gid=0(root) groups=0(root)`.
- **Comparative Findings:** Confirms that the engine is not a static scanner; it closes the loop between reconnaissance (OS fingerprint) and weaponization (targeted payload selection).

---

### 3. `kali.log` — Kali Linux Virtual Machine Multi-Phase Battery (596 Lines)
- **Target Topology:** Debian GNU/Linux 6.x VM (`192.168.56.101`) over VirtualBox Host-Only Ethernet Adapter (`\Device\NPF_{97791388-568A-4124-AB80-5BF4BC58551D}`).
- **Test 1 (Closed-Port Only RST Fingerprinting — Idea 1):**
  - Probed closed ports `22, 80, 81` with zero running services.
  - Evaluates fingerprinting when **no open ports exist**.
  - Attributed to **Linux (76% confidence)** based on:
    - Initial TTL = 64.
    - RST window size = 0.
    - Constant zero IP ID sequence (`IP ID = [0, 0, 0]` with DF=0, conforming to RFC 6864).
    - RFC 793 rule-breaker test: SYN+FIN probe silently dropped without emitting a response.
- **Test 2 (Autonomous ICMP Fallback Probing — Idea 6):**
  - Evaluates `--prefer-icmp` fallback mode.
  - Attributed to **Linux (67% confidence)** via ICMP Echo Reply Code 9 reflection and DF=0 clearing.
- **Test 3 (Multi-Service & Cross-Layer Banner Correlation — Idea 7.1):**
  - Probed OpenSSH (`22`), Apache (`80`), and Python SimpleHTTP (`8080`).
  - Attributed to **Linux (72% confidence)** combining network stack metrics with Debian GNU/Linux distribution banner signatures and RFC 7230 HTTP header ordering.

---

### 4. `win.log` — Windows Full Attack Chain with Exploits
- **Purpose:** Demonstrates the baseline attack chain against an unprotected Windows target running vulnerable lab services.
- **Port States:** Shows both `OPEN` (FTP 21, HTTP 80) and `CLOSED` (22, 81 returning kernel TCP RST).
- **Service Banners:** Banners extracted for both LabFTP Server and VulnHTTP.
- **Fingerprinting:** Primary candidate is `Open-Port TCP SYN/ACK` with initial TTL=128, Windows TCP option ordering (`MSS`, `WSCALE`, `SACK_PERMITTED`, `TIMESTAMP`), and non-zero IP ID with DF bit set.
- **Exploits:** Both baseline exploit modules executed and confirmed:
  - FTP Anonymous Login succeeded and read `/pub`.
  - HTTP Directory Traversal succeeded across multiple payloads (retrieved `win.ini`).

---

### 5. `win-atk-blocker.log` — Active Defense & Firewall Auto-Quarantine Run
- **Purpose:** Demonstrates defensive auto-quarantine capability (10% bonus feature) under high probe volume.
- **Behavior:** The Desktop defense engine was run with `--block --threshold 8 --window 10`. When the scanner probed its 8th port, the defense engine detected the scan pattern and dynamically created a Windows Defender Firewall rule:
  `CustomPortScanBlock_192_168_0_105`
- **Port States:** Subsequent ports (`22, 23, 24, 81, 82, 83, 84`) return `NO RESPONSE / POSSIBLY FILTERED` due to firewall dropping attacker packets.
- **Exploit Mitigation:** The HTTP Directory Traversal exploit failed because the TCP handshake could no longer complete.

---

### 6. `ipad.log` — Apple iPad (Darwin / BSD Stack)
- **Purpose:** Validates fingerprinting against Apple's Darwin/BSD network stack in a mobile form factor.
- **Port States:** Port 80 Open (VLC for iOS WiFi Web Sharing), Port 8080 Closed.
- **Fingerprinting:** Identifies macOS / BSD (48% / 100% modern BSD tier).
- **Key Evidence:** Initial TTL=64, Apple Darwin signature option ordering putting `WSCALE` before `TIMESTAMP`, window scale factor 5, and RFC 7323 PRNG randomized timestamp offset.

---

### 7. `phn.log` — Android Mobile Device (Linux Kernel 5.x)
- **Purpose:** Validates fingerprinting against modern Android/Linux mobile stacks.
- **Port States:** Port 2221 Open (WiFi FTP Server app), Port 2122 Closed.
- **Fingerprinting:** Identifies Linux (58% / 100% modern Linux tier).
- **Key Evidence:** Initial TTL=64, RFC 6864 compliant `IP ID = 0` with DF bit set, and standard Linux option ordering putting `SACK_PERMITTED` before `TIMESTAMP`.

---

### 8. `scan_100_ports.log` — Extended 100-Port Comprehensive Verification
- **Purpose:** Demonstrates large-scale port scanning across 100 distinct ports (split into two sequential 50-port batches to comply with the safety limit `MAX_PROBES = 50`).
- **Target:** Real live Windows machine (`192.168.1.104`) scanned over physical Wi-Fi adapter with firewall disabled to evaluate native kernel stack behavior across wide port ranges.
- **Batch 1 (Low & System Ports 20–1723):**
  - **Open Ports Discovered (4):** Port 135 (MSRPC Endpoint Mapper), Port 139 (NetBIOS Session), Port 445 (Microsoft-DS / SMB), and Port 1025 (Dynamic RPC).
  - **Closed Ports (46):** All other 46 ports returned native kernel `TCP RST` packets (`CLOSED TTL=128 WIN=0`).
  - **Fingerprint Attribution:** Candidate `Open-Port TCP SYN/ACK` identified **Windows 10 / 11 / Server 2016+ (71% confidence)**.
- **Batch 2 (High Ports, Web Apps, RPC & Cloud/Dev Services 1883–49164):**
  - **Closed Ports (50):** All 50 probed ports were genuinely closed, immediately emitting `CLOSED TTL=128 WIN=0`.
  - **Fingerprint Attribution:** Candidate `Closed-Port TCP RST` (Idea 1 Zero-Open-Port Detection) identified **Windows (69% confidence)** powered by strict incremental IP ID sequence (`[13207, 13208, ...]`, avg delta: 1.1), zero window size, and initial TTL 128.

---

### 9. `ssh_quiet.log` — Windows SSH Weak Credential Exploitation (Quiet / Stealth Mode)
- **Purpose:** Proves remote code execution (RCE) via SSH brute-force in a non-intrusive, covert manner suitable for quiet penetration testing and automated inventory auditing.
- **Target:** Live Windows 11 machine (`192.168.1.104` — `AisheePC`) running Microsoft OpenSSH for Windows (`SSH-2.0-OpenSSH_for_Windows_9.5`) on port 22.
- **Fingerprinting:** Candidate `Open-Port TCP SYN/ACK` identified **Windows (75% confidence)** via TTL 128, strict incremental IP IDs, and banner match for Microsoft OpenSSH.
- **Exploit Execution (Quiet Mode):**
  - Brute-forced bounded 20-pair credential wordlist.
  - Successfully authenticated as `test:test123` on attempt 15.
  - Executed command-line reconnaissance:
    - `whoami` $\to$ `aisheepc\test`
    - `hostname` $\to$ `AisheePC`
    - `ipconfig` $\to$ `169.254.17.114, 169.254.58.27, 192.168.1.104`
    - `os_info` $\to$ `Microsoft Windows [Version 10.0.26200.9445]`
  - **Zero noise:** No files written to the desktop, zero audio alerts triggered.

---

### 10. `ssh_attack.log` — Windows SSH Weak Credential Exploitation (Loud / Full Attack Mode)
- **Purpose:** Demonstrates full multi-modal post-exploitation, dropping persistent interactive desktop payloads and triggering hardware-level audio alerts to prove undeniable control of the target machine.
- **Target:** Live Windows 11 machine (`192.168.1.104` — `AisheePC`) running OpenSSH on port 22.
- **Fingerprinting:** Identifies Windows (75% confidence) with identical high-confidence empirical features.
- **Exploit Execution (Loud Mode):**
  - Successfully authenticated as `test:test123` (attempt 15/20).
  - **Spooky Desktop Trophy:** Deployed `PROOF_OF_ACCESS.txt` on the Desktop:
    > *"Abhishek and Turjo have taken over your computer for their Security project! You should be careful with SSH xd"*
  - **Interactive 1000-Loop Payloads (3 formats):** Base64-encoded and deployed 3 double-clickable executables directly onto `C:\Users\test\Desktop` and `C:\Users\Public\Desktop`:
    1. `HACKED.exe`: Native Windows executable compiled on the fly using Windows' built-in `csc.exe` compiler.
    2. `HACKED.bat`: Native Windows batch script.
    3. `hacked.py`: Python exploit script.
    *(When double-clicked, Windows opens a Command Prompt console with matrix neon-green font, streaming a 1000-iteration loop: `[1000/1000] YOU ARE HACKED BY ABHISHEK AND TURJO xd` with a typewriter animation before holding the terminal open).*
  - **Physical Speech Synthesizer Voice Alert:** Sent synthesized audio commands through the victim PC's sound card and physical speakers:
    > *"Warning. Abhishek and Turjo have taken over your computer for their Security project. You should be careful with S-S-H. haha."*

---

### 11. `defense_kali_test.log` — Kali Linux Multi-Vector Defense & Netfilter Suite (Scenarios A–G)
- **Target Topology:** Debian GNU/Linux Kernel 6.x VM (`192.168.56.101`) over VirtualBox Host-Only Ethernet Adapter (`eth0`, libpcap `/usr/lib/x86_64-linux-gnu/libpcap.so.0.8`).
- **Victim Defense Engine:** `sudo python3 defense/main.py --adapter eth0` with native Linux Netfilter dynamic rule injection (`iptables -I INPUT -s <IP> -p tcp -j DROP`).
- **Scenario A (Fast SYN Scan Detection):**
  - Probed ports `21, 22, 80, 135, 139, 443, 445, 8080`.
  - On the 8th packet (port 8080), fast sliding window ($W_1 = 10.0s$, threshold 8 SYNs across 5 distinct ports) tripped immediately:
    `[ALERT] 192.168.56.1 | fast port scan (SYN=8, distinct ports=8 within 10.0s)`.
  - Kernel firewall rule `CustomPortScanBlock_192_168_56_1` injected; subsequent banner grabs timed out completely.
- **Scenario B (Canary Honeyport Trap — Decoy Port 81 ⭐):**
  - Probed ports `21, 22, 80, 81, 135, ...`.
  - Without waiting for rate thresholds, touching unassigned decoy port 81 triggered zero-delay quarantine on packet 4:
    `[ALERT] 192.168.56.1 | hit canary honeyport (81)`.
  - Subsequent probes returned `NO RESPONSE / POSSIBLY FILTERED`.
- **Scenario C (Low-and-Slow Stealth Scan — Slow Window $W_2 = 60.0s$):**
  - Attacker used `--delay 2.5` to space 20 probes across 50 seconds to evade the 10-second fast window ($window\_count \le 4$).
  - The 60-second slow sliding window caught the 20th packet (port 123):
    `[ALERT] 192.168.56.1 | slow stealth scan (SYN=20 within 60.0s)`.
- **Scenario D (Invalid Flag Anomaly Probing — RFC 793 SYN+FIN):**
  - OS fingerprinting probe emitted ambiguous `SYN+FIN` (0x03) on port 21.
  - Trapped immediately as a critical anomaly:
    `[CRITICAL ALERT] 192.168.56.1 -> 192.168.56.101:21 | invalid TCP flag combination (SYN+FIN (Rule-Breaker), 0x03) on port 21`.
- **Scenario E (Trusted Whitelist Protection):**
  - Host whitelisted via `--whitelist 192.168.56.1`.
  - Attacker ran aggressive scan: `window_count=0 distinct_ports=0` recorded for all packets; zero blocks or alerts triggered.
- **Scenario F (Self-Healing Auto-Release Quarantine):**
  - Dedicated background daemon thread (`threading.Thread`) monitored TTL independently of incoming packets.
  - Exactly 60.0 seconds after quarantine, the engine released the block without manual intervention:
    `[MITIGATION] Released quarantine block on 192.168.56.1 (TTL 60s elapsed)`.
- **Scenario G (SOC Incident Audit & Netfilter Drop Counters):**
  - `defense_incident_log.json` verified with complete ISO timestamps, attacker IPs, trigger reasons, and TTLs.
  - `sudo iptables -L INPUT -n -v` verified kernel packet drop counter progressing dynamically (`12 -> 13 -> 14 -> 15 -> 16 pkts`).

---

### 12. `defense_win_test.log` — Windows 11 Desktop Multi-Vector Defense & Advanced Firewall Suite (Scenarios A–G)
- **Target Topology:** Windows 11 Desktop (`192.168.0.116`) probed from Windows 11 Laptop (`192.168.0.105`) over Physical LAN (Wi-Fi / Ethernet Subnet `192.168.0.0/24`).
- **Victim Defense Engine:** `python defense\main.py --adapter "\Device\NPF_{439707FA-9208-4AF9-BEDE-002C5F9EE7CB}"` with dynamic Windows Defender Firewall rule injection (`netsh advfirewall firewall add rule name=CustomPortScanBlock_* dir=in action=block remoteip=* protocol=TCP profile=any`).
- **Scenario A (Fast SYN Scan Detection):**
  - Probed ports `21, 22, 80, 135, 139, 443, 445, 8080`.
  - Tripped on packet 8: `[ALERT] 192.168.0.105 | fast port scan (SYN=8, distinct ports=8 within 10.0s)` and injected firewall rule `CustomPortScanBlock_192_168_0_105 (Windows)`.
- **Scenario B (Canary Honeyport Trap — Decoy Port 81 ⭐):**
  - Zero-delay severance on packet 4 touching Port 81 (`hit canary honeyport (81)`).
  - Automatically released after 60s TTL: `[MITIGATION] Released quarantine block on 192.168.0.105 (TTL 60s elapsed)`.
- **Scenario C (Low-and-Slow Stealth Scan — Slow Window $W_2 = 60.0s$):**
  - Attacker spaced 20 probes by 2.5s delay. Fast window remained $\le 4$.
  - Slow sliding window accumulated 20 SYNs and severed the host on packet 20 (port 123) with 90s quarantine TTL.
- **Scenario D (Invalid Flag Anomaly Probing — RFC 793 SYN+FIN):**
  - Caught Phase 3 `SYN+FIN` rule-breaker probe on port 21 on the very first observation. Quarantined for 300s TTL.
- **Scenario E (Trusted Whitelist Protection):**
  - Whitelisted laptop IP (`192.168.0.105`). Full 8-port scan completed with zero alerts and all service banners grabbed cleanly.
- **Scenario F (Self-Healing Auto-Release):**
  - Verified dynamic removal of Windows Firewall rule via `netsh advfirewall firewall delete rule name=CustomPortScanBlock_*`. Host re-established ping reachability.
- **Scenario G (SIEM Incident JSON Audit):**
  - Audited `defense_incident_log.json` confirming 5 persistent incident records spanning fast scan, canary honeyport, slow stealth, and invalid flag vectors.

### 13. `win-icmp.log` — Windows 11 Desktop Autonomous ICMP Echo Fallback Verification
- **Target Topology:** Windows 11 Desktop (`192.168.0.116`) probed from Windows 11 Laptop (`192.168.0.105`) with Windows Defender Firewall actively dropping/filtering all incoming TCP SYN probes.
- **Operational Findings:**
  - Probed TCP ports `21, 80, 81` all returned `NO RESPONSE / POSSIBLY FILTERED`.
  - With zero open or closed ports available for TCP SYN/ACK or RST analysis, the fingerprinting engine autonomously pivoted to the **ICMP Echo Reply Candidate**.
  - Windows 11 responded to the ICMP probe, normalizing non-standard Code 9 to Code 0 with initial TTL 128 and Don't-Fragment (DF) bit clear.
  - Successfully classified the target as **Windows at 94% confidence** (47% Win 7/8, 47% Win 10/11) without requiring a single open TCP port.

---

## 3. Codebase Feature Coverage Verification Matrix

The table below cross-references every single module, scanning mode, fingerprinting heuristic, exploit, and defense vector in the codebase with the specific log file demonstrating empirical proof of its correctness.

| Category | Specific Feature / Code Module | Verified Log Evidence | Empirical Result Observed |
|---|---|---|---|
| **Port Scanning** | TCP SYN Half-Open Scan (`scanner/syn_scan.py`) | [`full-chain.log`](file:///final-log/full-chain.log), [`scan_100_ports.log`](file:///final-log/scan_100_ports.log) | Detected OPEN (SYN/ACK), CLOSED (RST), and FILTERED (Drops) |
| **Port Scanning** | High-Volume Batch Probing (`scanner/`) | [`scan_100_ports.log`](file:///final-log/scan_100_ports.log) | Probed 100 ports over two 50-port batches adhering to safety limits |
| **Port Scanning** | Service Banner Grabbing (`scanner/banner.py`) | [`full-chain.log`](file:///final-log/full-chain.log), [`kali.log`](file:///final-log/kali.log), [`ssh_quiet.log`](file:///final-log/ssh_quiet.log) | FTP (`LabFTP`), HTTP (`VulnHTTP`, `Apache`), SSH (`OpenSSH 9.5`, `Debian-5`) |
| **Fingerprinting (Idea 1)** | Closed-Port TCP RST Quoting & TTL (`fingerprint/rules.py`) | [`kali.log`](file:///final-log/kali.log) (Test 1), [`scan_100_ports.log`](file:///final-log/scan_100_ports.log) | Zero-open-port OS attribution: Linux (76%) & Windows (69%) |
| **Fingerprinting (Idea 2)** | IP ID Sequence Generation Analysis (`fingerprint/engine.py`) | [`kali.log`](file:///final-log/kali.log), [`full-chain.log`](file:///final-log/full-chain.log) | `ALL_ZERO` (`[0,0,0,0]`) on Linux; `STRICT_INCREMENTAL` (`deltas: [2, 3]`) on Windows |
| **Fingerprinting (Idea 3)** | TCP Timestamp Clock Frequency & Uptime (`fingerprint/engine.py`) | [`full-chain.log`](file:///final-log/full-chain.log), [`ipad.log`](file:///final-log/ipad.log), [`ssh_quiet.log`](file:///final-log/ssh_quiet.log) | ~1000 Hz / 1ms tick rate detected on Windows; randomized offsets on iPadOS |
| **Fingerprinting (Idea 4)** | RFC 3168 ECN Negotiation Probing (`fingerprint/engine.py`) | [`full-chain.log`](file:///final-log/full-chain.log), [`cross-platform-exploit.log`](file:///final-log/cross-platform-exploit.log) | ECN flags ignored (`ECE=0, CWR=0`) on Windows; reflected on Linux/Darwin |
| **Fingerprinting (Idea 5)** | Ambiguous TCP Flags (SYN+FIN Rule-Breaker) (`fingerprint/engine.py`) | [`full-chain.log`](file:///final-log/full-chain.log), [`ssh_quiet.log`](file:///final-log/ssh_quiet.log) | Silently dropped by Unix; RST emitted by Windows |
| **Fingerprinting (Idea 6)** | ICMP Echo Reply Quoting & Fallback (`fingerprint/engine.py`) | [`kali.log`](file:///final-log/kali.log) (Test 2), [`win-icmp.log`](file:///final-log/win-icmp.log), [`full-chain.log`](file:///final-log/full-chain.log) | Code 9 reflection on Linux (67%); Code 0 normalization on Windows (94%) |
| **Fingerprinting (Idea 7.1)** | Cross-Layer Banner Correlation (`fingerprint/cross_layer.py`) | [`kali.log`](file:///final-log/kali.log), [`ssh_quiet.log`](file:///final-log/ssh_quiet.log) | Debian OpenSSH matched Linux distro; Microsoft OpenSSH matched Windows |
| **Exploitation (Idea 7.2)** | Phase 4 Dynamic OS-Aware Payload Selection (`attacker/payload_selector.py`) | [`cross-platform-exploit.log`](file:///final-log/cross-platform-exploit.log), [`full-chain.log`](file:///final-log/full-chain.log) | Windows selected `win.ini` + `whoami`; Linux selected `/etc/passwd` + `id` |
| **Exploitation (Module 1)** | FTP Anonymous Login & Directory Traversal (`exploits/ftp_anon.py`) | [`full-chain.log`](file:///final-log/full-chain.log), [`cross-platform-exploit.log`](file:///final-log/cross-platform-exploit.log) | Successfully read `/pub` and `/uploads` without credentials |
| **Exploitation (Module 2)** | Multi-Stage FTP Write $\to$ Web Shell CGI RCE (`exploits/ftp_webshell.py`) | [`full-chain.log`](file:///final-log/full-chain.log), [`cross-platform-exploit.log`](file:///final-log/cross-platform-exploit.log) | Verified write, uploaded `shell.py`, executed RCE (`turjo` / `root`), cleaned up |
| **Exploitation (Module 3)** | FTP Bounce Internal Port Pivoting & Mitigation (`exploits/ftp_bounce.py`) | [`full-chain.log`](file:///final-log/full-chain.log), [`cross-platform-exploit.log`](file:///final-log/cross-platform-exploit.log) | Caught and reported host-level mitigation (`WinError 10053` WFP abortion) |
| **Exploitation (Module 4)** | OS-Aware HTTP Path Traversal (`exploits/http_traversal.py`) | [`full-chain.log`](file:///final-log/full-chain.log), [`cross-platform-exploit.log`](file:///final-log/cross-platform-exploit.log) | Extracted Windows `win.ini` and Linux `/etc/passwd` across encoded payloads |
| **Exploitation (Module 5)** | SSH Dictionary Brute-Force & Multi-Modal Post-Ex (`exploits/ssh_bruteforce.py`) | [`ssh_quiet.log`](file:///final-log/ssh_quiet.log), [`ssh_attack.log`](file:///final-log/ssh_attack.log) | Cracked `test:test123`, quiet reconnaissance, 1000-loop payloads, voice alert |
| **Active Defense (Dual Windows)** | Fast ($W_1=10s$) & Slow ($W_2=60s$) SYN Sliding Windows (`defense/detector.py`) | [`defense_kali_test.log`](file:///final-log/defense_kali_test.log) (A, C), [`defense_win_test.log`](file:///final-log/defense_win_test.log) (A, C) | Caught fast scans at 8 SYNs; caught slow spaced probes (`--delay 2.5`) at 20 SYNs |
| **Active Defense (Canary Trap)** | Decoy Canary Honeyports (`defense/detector.py` `--canary-ports 81`) | [`defense_kali_test.log`](file:///final-log/defense_kali_test.log) (B), [`defense_win_test.log`](file:///final-log/defense_win_test.log) (B) | Instant quarantine on probe 4 touching Port 81 without waiting for thresholds |
| **Active Defense (Flag Filter)** | Rule-Breaker Invalid Flag Anomaly Inspection (`defense/detector.py`) | [`defense_kali_test.log`](file:///final-log/defense_kali_test.log) (D), [`defense_win_test.log`](file:///final-log/defense_win_test.log) (D) | Caught RFC 793 `SYN+FIN (0x03)` probe immediately; injected 300s quarantine |
| **Active Defense (Whitelist)** | Trusted Host / Gateway Exemption (`defense/detector.py` `--whitelist`) | [`defense_kali_test.log`](file:///final-log/defense_kali_test.log) (E), [`defense_win_test.log`](file:///final-log/defense_win_test.log) (E) | `window_count=0 distinct_ports=0`; exempted trusted hosts from quarantine |
| **Active Defense (Auto-Release)** | Self-Healing TTL Daemon Thread (`defense/main.py` `--block-ttl`) | [`defense_kali_test.log`](file:///final-log/defense_kali_test.log) (F), [`defense_win_test.log`](file:///final-log/defense_win_test.log) (F) | Background thread deleted firewall rules at exactly 60s TTL on idle network |
| **Active Defense (Firewalls)** | Cross-Platform Linux Netfilter (`iptables`) & Windows Defender (`netsh`) | [`defense_kali_test.log`](file:///final-log/defense_kali_test.log), [`defense_win_test.log`](file:///final-log/defense_win_test.log) | Dynamic injection and deletion of inbound DROP/BLOCK rules across both OSes |
| **Active Defense (SIEM Audit)** | Machine-Readable Incident Logging (`defense/detector.py`) | [`defense_kali_test.log`](file:///final-log/defense_kali_test.log) (G), [`defense_win_test.log`](file:///final-log/defense_win_test.log) (G) | Recorded ISO timestamps, attacker IPs, reasons, rules, and TTLs in JSON |
| **Unit Test Suite** | 68 Automated Test Cases (`Imp/tests/`) | Test suite execution (`pytest`) | **68/68 Passed (100%)** covering parsing, scoring, exploits, and defense engine |
