# Complete End-to-End Testing Workflow & Command Cheat Sheet

**Course:** CSE 406 — Computer Security Sessional  
**Project:** Port Scanning with OS Fingerprinting, Exploits & Defense Mitigation (Tool 8)  
**Date:** September 12, 2026  
**Network State:**
* **Laptop (Attacker):** `192.168.0.105` (Wi-Fi: `\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}`)
* **Desktop (Victim):** `192.168.0.116` (Ethernet: `\Device\NPF_{439707FA-9208-4AF9-BEDE-002C5F9EE7CB}`)

---

## 0. Pre-Flight Preparation (Do This First!)

### On Laptop:
1. Open **Administrator PowerShell**.
2. Navigate to project root and pull latest teammate changes:
   ```powershell
   cd "e:\4-1 Course Works\portscan-os"
   git pull
   ```
3. Verify all automated unit tests pass:
   ```powershell
   cd Imp
   python -m pytest tests\ -v
   ```
   *(All 19 tests should PASS in ~0.05s, including RST and IP ID tests)*

### On Desktop:
1. Open **Administrator PowerShell**.
2. Pull latest git commits:
   ```powershell
   cd "g:\4-1\portscan-os"
   git pull
   ```
3. Clear any lingering firewall rules from previous test sessions:
   ```powershell
   netsh advfirewall firewall delete rule name=CustomPortScanBlock*
   ```

---

## 1. Desktop (Victim) Setup — 3 Split Terminals

Open **3 separate Administrator PowerShell windows** (or split tabs in Windows Terminal) on Desktop:

### Terminal 1: Vulnerable FTP Server
```powershell
cd "g:\4-1\portscan-os\Imp"
python victim\ftp_server.py --port 21
```
*Expected log:* `[FTP] Vulnerable FTP server listening on 0.0.0.0:21`

---

### Terminal 2: Vulnerable HTTP Server
```powershell
cd "g:\4-1\portscan-os\Imp"
python victim\http_server.py --port 80
```
*Expected log:* `[HTTP] Vulnerable HTTP server listening on 0.0.0.0:80`

---

### Terminal 3: Defense Engine (Choose Scenario A or B)

#### Scenario A: Standard Passive Detection (No blocking)
*(Use this for normal testing of all phases, banners, and exploits without getting locked out)*
```powershell
cd "g:\4-1\portscan-os\Imp"
python defense\main.py --adapter "\Device\NPF_{439707FA-9208-4AF9-BEDE-002C5F9EE7CB}" --threshold 8 --window 10
```

#### Scenario B: Active Mitigation Testing (With Auto-Blocking)
*(Use this when demonstrating the 10% bonus active firewall quarantine)*
```powershell
cd "g:\4-1\portscan-os\Imp"
python defense\main.py --adapter "\Device\NPF_{439707FA-9208-4AF9-BEDE-002C5F9EE7CB}" --threshold 8 --window 10 --block
```

---

### Terminal 4: OpenSSH Server (For SSH Weak Credential Exploit Testing)
*(Run in an Administrator PowerShell on Desktop / Victim to prepare for Phase 5 SSH Exploit)*
```powershell
# 1. Start Windows OpenSSH Server service
Start-Service sshd

# 2. Create the vulnerable lab test account with weak credentials
net user test test123 /add

# 3. (Optional) Grant admin rights to test user so desktop files appear on all screens
net localgroup administrators test /add
```
*Expected status:* Service `sshd` is running on port 22 (`Get-Service sshd` shows `Running`).

> **Victim Cleanup (After Testing):**
> When testing is complete, restore the victim machine to its clean baseline:
> ```powershell
> Stop-Service sshd
> net user test /delete
> ```

---

## 2. Laptop (Attacker) Execution — Step-by-Step

On your Laptop, open an **Administrator PowerShell** and run the following commands:

```powershell
cd "e:\4-1 Course Works\portscan-os\Imp"
```

---

### TEST 1: Full Attack Chain (Mixed Open & Closed Ports Run) ⭐
*(Make sure Desktop has FTP and HTTP servers running in separate terminals, and firewall is disabled on all profiles)*

```powershell
python attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 21 22 80 81
```

#### What You Will See in the Output (Verified Empirical Log):
1. **Target MAC Resolution:** Resolves Desktop MAC (`d8:5e:d3:99:09:6c`) via ARP.
2. **Phase 1 (SYN Scan):**
   - Port 21: `OPEN` (TTL=128, WIN=65535) — FTP server response
   - Port 22: `CLOSED` (TTL=128, WIN=0) — Closed port TCP RST from Windows kernel
   - Port 80: `OPEN` (TTL=128, WIN=65535) — HTTP server response
   - Port 81: `CLOSED` (TTL=128, WIN=0) — Closed port TCP RST from Windows kernel
3. **Phase 2 (Banner Grabbing):**
   - Automatically skips closed ports (22, 81) and queries open ports:
   - Port 21: `LabFTP Server (Vulnerable Demo) Ready`
   - Port 80: `VulnHTTP/1.0 (Lab Demo)`
4. **Phase 3 (OS Fingerprinting):**
   - `Candidate  : Open-Port TCP SYN/ACK` *(SYN/ACK prioritized over RST for rich TCP options)*
   - `Likely OS  : Windows`
   - `Version    : Windows 10 / 11 / Server 2016+` (69% tier match)
   - `TTL        : 128 (initial 128, ~0 hop(s))`
   - `DF bit     : set`
   - `IP ID      : 58906` *(non-zero with DF set, characteristic of Windows/BSD)*
   - `Options    : ('MSS', 1460)`
5. **Phase 5 (Exploits):**
   - `FTP Anonymous Login (port 21)` $\to$ `SUCCESS ✓` (reads root directory `pub/`)
   - `HTTP Directory Traversal (port 80)` $\to$ `SUCCESS ✓` (8 payloads succeeded, reads `win.ini` and `README.md`)
6. **Final Summary:**
   ```text
   ═════════════════════════════════════════════════════════════════
     ATTACK SUMMARY
   ═════════════════════════════════════════════════════════════════
     Ports scanned : 4
     Open          : 2
     Closed        : 2
     Filtered/NR   : 0
     Banners found : 2/2
     OS guess      : Windows (59%)
     Exploits      : 2/2 successful
       ✓ FTP Anonymous Login (port 21)
       ✓ HTTP Directory Traversal (port 80)
   ═════════════════════════════════════════════════════════════════
   ```

> **Safety Reminder:** After completing attack testing, stop the vulnerable servers (`Ctrl+C`) and re-enable Windows Defender Firewall on Desktop:
> ```powershell
> netsh advfirewall set allprofiles state on
> ```

---

### TEST 2: Active Defense & Firewall Auto-Blocking (Bonus Demonstration)

This 2-step test proves the active defense and firewall quarantine:

#### Step 2.1: Trigger the Block
1. On Desktop Terminal 3, run **Scenario B** (with `--block`):
   ```powershell
   python defense\main.py --adapter "\Device\NPF_{439707FA-9208-4AF9-BEDE-002C5F9EE7CB}" --threshold 8 --window 10 --block
   ```
2. On Laptop, run the full attack:
   ```powershell
   python attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 21 22 80 443
   ```
3. Observe Desktop Terminal 3:
   ```text
   [ALERT] Possible TCP port scan from 192.168.0.105
   [MITIGATION] Blocked TCP traffic from 192.168.0.105
                Firewall rule: CustomPortScanBlock_192_168_0_105
   ```

#### Step 2.2: Empirical Proof of Block (Re-Scan Blocked Target)
Immediately run a quick scan on previously open ports 21 and 80 from Laptop:
```powershell
python attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 21 80
```

#### Result: Complete Blackout
```text
     21  NO RESPONSE / POSSIBLY FILTERED
     80  NO RESPONSE / POSSIBLY FILTERED

  [PHASE 3] OS Fingerprinting
  No SYN/ACK was observed — OS fingerprint not available.

  ATTACK SUMMARY
  Ports scanned : 2
  Open          : 0
  Filtered/NR   : 2
  Banners found : 0/0
```
*(Ports 21 and 80 are now completely dropped by Desktop's Windows Firewall!)*

---

### TEST 3: Closed-Port (RST) Fingerprinting (Zero-Open-Port OS Detection) ⭐

This test proves that our scanner can accurately detect the victim OS even when **no ports are open** on the target.

#### Step 3.1: Desktop Preparation (Allow TCP RST Responses)
By default, Windows Defender Firewall silently drops incoming SYNs to closed ports (`FILTERED`), which prevents the OS stack from responding. To allow the native Windows kernel to emit legitimate TCP RST frames:

On **Desktop (Admin PowerShell)**:
```powershell
# Temporarily disable firewall on all profiles (Domain, Private, Public)
netsh advfirewall set allprofiles state off
```
*(Make sure no victim HTTP/FTP servers are running on the scanned ports, so all probed ports are genuinely closed).*

#### Step 3.2: Run Closed-Port Scan on Laptop
Probe ports that have no listening services (e.g., ports `80`, `81`, `82`):
```powershell
python attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 80 81 82 --skip-banners --skip-exploits
```

#### Step 3.3: Verified Empirical Output
```text
─────────────────────────────────────────────────────────────────
     80  CLOSED                         TTL=128 WIN=0
     81  CLOSED                         TTL=128 WIN=0
     82  CLOSED                         TTL=128 WIN=0

  [PHASE 2] Banner grabbing skipped (--skip-banners)

═════════════════════════════════════════════════════════════════
  [PHASE 3] OS Fingerprinting
═════════════════════════════════════════════════════════════════
  Candidate  : Closed-Port TCP RST
  Likely OS  : Windows
  Confidence : 93%
  Version    : Windows family (closed-port RST; open port required for build-tiering)
  TTL        : 128 (initial 128, ~0 hop(s))
  Window     : 0
  DF bit     : set
  IP ID      : 58730
  Options    : none
  Probability:
    Windows           93%  ##################
    macOS / BSD        7%  #
    Linux              0%
    Network device     0%
  Evidence   :
    - Probe response: TCP RST (Closed-Port Fingerprinting)
    - TCP window is 0 (standard closed-port RST response)
    - RST with initial TTL 128 and window 0 strongly indicates Windows stack
    - IP ID is non-zero (58730) with DF set (characteristic of Windows/BSD)

  [PHASE 5] Exploit execution skipped (--skip-exploits)

═════════════════════════════════════════════════════════════════    
  ATTACK SUMMARY
═════════════════════════════════════════════════════════════════    
  Ports scanned : 3
  Open          : 0
  Closed        : 3
  Filtered/NR   : 0
  Banners found : 0/0
  OS guess      : Windows (93%)
═════════════════════════════════════════════════════════════════    
```

#### Why This Works (Report / Defense Presentation Points):
- **RFC 793 / 9293 Compliance:** When a SYN hits a closed TCP port, the kernel stack responds with a `TCP_RST`.
- **Windows Characteristic:** Microsoft Windows consistently emits closed-port RST packets with **Initial TTL = 128** and **Window Size = 0**.
- **RFC 6864 IP ID Distinction:** Modern Linux kernels strictly set `IP ID = 0` on datagrams with the DF bit set. Windows kernels, as captured above, emit an incrementing or non-zero IP ID (`58730`), giving 93% high-confidence attribution to Windows.
- **Contrast with Filtered:** If the firewall drops packets, zero bytes return $\to$ `FILTERED` (Stealth Host / Black Hole). Once the packet reaches the TCP stack, the RST enables passive OS fingerprinting!

#### Step 3.4: Restore Desktop Firewall Security (Safety First!)
Once testing the closed-port RST behavior is complete, immediately re-enable Windows Defender Firewall on Desktop:
```powershell
netsh advfirewall set allprofiles state on
```

---

### TEST 4: SSH Weak Credential Exploitation — Quiet Mode (Stealth Recon) ⭐

This test evaluates non-intrusive post-exploitation over an encrypted SSH tunnel. It proves valid authentication and gathers basic reconnaissance without creating user-visible files or generating audio alerts on the victim machine.

#### Step 4.1: Run Quiet Attack From Laptop
```powershell
# Run from project root in Administrator PowerShell:
.\scripts\test_ssh_attack.ps1 quiet
```
*(Or pass `-Mode quiet`)*

#### Step 4.2: Verified Output Lifecycle
1. **Phase 1 (SYN Port Scan):** Port 22 discovered `OPEN` (TTL=128, WIN=65535).
2. **Phase 2 (Service Banner Grabbing):** Grabs service banner:
   `✓ 22 SSH → SSH-2.0-OpenSSH_for_Windows_9.5`
3. **Phase 3 (OS Fingerprinting):** Identifies Windows (75% confidence) via TCP options, strict incremental IP ID sequence, and 1000 Hz timestamp frequency.
4. **Phase 5 (SSH Weak Credential Attack):**
   - Brute-forces bounded top-20 dictionary.
   - Cracks credentials `test:test123` on attempt 15.
   - Executes silent command-line reconnaissance:
     - `whoami` $\to$ `aisheepc\test`
     - `hostname` $\to$ `AisheePC`
     - `ipconfig` $\to$ `169.254.17.114, 169.254.58.27, 192.168.1.104`
     - `os_info` $\to$ `Microsoft Windows [Version 10.0.26200.9445]`
5. **Log File:** Saved cleanly to [`final-log/ssh_quiet.log`](file:///final-log/ssh_quiet.log).

---

### TEST 5: SSH Weak Credential Exploitation — Loud Mode (Spooky Payloads & Voice Alert) ⭐

This test demonstrates full interactive post-exploitation capabilities with multi-modal physical and visual proof of remote code execution (RCE) on the victim machine.

#### Step 5.1: Run Loud Attack From Laptop
```powershell
# Run from project root in Administrator PowerShell:
.\scripts\test_ssh_attack.ps1 loud
# (or simply .\scripts\test_ssh_attack.ps1, as loud is the default mode)
```

#### Step 5.2: What Happens on the Victim Machine
1. **Remote Execution:** Logs in via SSH as `test:test123`.
2. **Desktop Trophy File:** Drops `PROOF_OF_ACCESS.txt` on the Desktop (`C:\Users\test\Desktop` & `C:\Users\Public\Desktop`):
   ```text
   ====================================================================
     [!] CRITICAL SECURITY ALERT: SYSTEM COMPROMISED
   ====================================================================

     Abhishek and Turjo have taken over your computer for their Security project!
     You should be careful with SSH xd

     Victim Host : AisheePC
     User Account: test
     Timestamp   : 2026-09-13 23:56:30
     Status      : Remote Code Execution Confirmed
   ====================================================================
   ```
3. **Interactive 1000-Loop Payloads:** Deploys 3 double-clickable executables/scripts:
   - `HACKED.exe`: Real Windows executable compiled on the fly via Windows' native `csc.exe`.
   - `HACKED.bat`: Native Windows batch executable.
   - `hacked.py`: Python exploit script.
   *(When double-clicked by anyone on the victim machine, a Command Prompt window pops open, text turns Matrix neon-green, and a loop streams 1000 times: `[1000/1000] YOU ARE HACKED BY ABHISHEK AND TURJO xd` with a typewriter animation!)*
4. **Spooky Audio Voice Alert:** Calls Windows' native Speech Synthesizer API (`System.Speech.Synthesis`) through the victim device's sound card/speakers:
   > *"Warning. Abhishek and Turjo have taken over your computer for their Security project. You should be careful with S-S-H. haha."*
5. **Log File:** Saved cleanly to [`final-log/ssh_attack.log`](file:///final-log/ssh_attack.log).

---

## 3. Standalone / Targeted Commands (For Quick Checks)

### Standalone Closed-Port RST Fingerprint Scan:
```powershell
python attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 80 81 82 --skip-banners --skip-exploits
```

### Standalone HTTP Traversal Test:
```powershell
python attacker\exploits\http_traversal.py --target 192.168.0.116 --port 80
```

### Standalone FTP Anonymous Exploit:
```powershell
python attacker\exploits\ftp_anon.py --target 192.168.0.116 --port 21
```

### Standalone SSH Attack (Automated Runner):
```powershell
# Quiet Mode (Recon Only)
.\scripts\test_ssh_attack.ps1 quiet

# Loud Mode (Spooky Payloads + Voice Alert)
.\scripts\test_ssh_attack.ps1 loud
```

### Standalone Banner Grabbing:
```powershell
python attacker\banner.py --target 192.168.0.116 --ports 21 22 80
```

### Standalone SYN Scanner (Skip Banners and Exploits):
```powershell
python attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 21 22 80 --skip-banners --skip-exploits
```

---

## 4. Reset & Cleanup Commands

When done testing or to unblock the Laptop on Desktop:

### On Desktop (Admin PowerShell):
1. Stop the defense terminal with `Ctrl+C`.
2. To manually verify/remove the firewall rule if needed:
   ```powershell
   # Check if rule exists
   netsh advfirewall firewall show rule name=CustomPortScanBlock*

   # Delete rule
   netsh advfirewall firewall delete rule name=CustomPortScanBlock*
   ```
3. Re-enable Windows Defender Firewall on all profiles:
   ```powershell
   netsh advfirewall set allprofiles state on
   ```
4. To stop HTTP or FTP servers: Press `Ctrl+C` in their respective windows.
5. To stop OpenSSH Server & clean up lab test account:
   ```powershell
   Stop-Service sshd
   net user test /delete
   Remove-Item C:\Users\test -Recurse -Force -ErrorAction SilentlyContinue
   ```

---

## 5. Quick Reference Table of Command Flags

| Flag | Allowed Values | Explanation |
| :--- | :--- | :--- |
| `--adapter` | Npcap GUID string | Network interface to inject raw packets. |
| `--target` | IPv4 address | Single private IPv4 destination. |
| `--ports` | Space-separated ints | Ports to probe (Safety limit: $\le 50$). |
| `--delay` | Float ($\ge 0.2$) | Inter-probe delay (default: `0.5s`). |
| `--timeout` | Float ($0.1$ to $10.0$) | Response listen timeout per probe (default: `1.5s`). |
| `--skip-banners` | Switch flag | Skip Phase 2 application banner grabbing. |
| `--skip-exploits`| Switch flag | Skip Phase 5 exploit execution. |
| `--exploit-delay`| Float | Delay between exploit attempts (default: `1.0s`). |
| `--ssh-mode` | `quiet`, `loud` | SSH exploit mode: `quiet` (silent recon) or `loud` (payloads + voice). |
| `--block` | Switch flag (Defense) | Enable dynamic Windows Firewall auto-quarantine. |
| `--threshold` | Int ($\ge 2$) (Defense) | Number of SYN probes within window to alert (default: `8`). |
| `--window` | Float ($> 0$) (Defense) | Sliding window interval in seconds (default: `10.0s`). |

---

## 6. Final Empirical Multi-OS & Defense Verification Suite (Verified Live Runs) ⭐

This section provides the complete, independently documented record of the final empirical verification runs across all real hardware devices on the LAN (`192.168.0.0/24`).

### Summary of Cross-Device Coverage

| Device | Real Operating System | IP Address | Ports Tested | Detected OS & Confidence | Empirical Confirmation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Desktop** | Windows 11 Pro | `192.168.0.116` | `21 22 80 81` | **Windows (60%)** | TTL 128, Windows Option Order, Exploits 2/2 OK |
| **Desktop** | Windows 11 (with Blocker) | `192.168.0.116` | `21-24, 80-84` | **Windows (60%)** | 7 Ports Filtered, HTTP Exploit Blocked (FAILED ✗) |
| **Desktop** | Windows 11 (SSH Quiet) | `192.168.1.104` | `22` | **Windows (75%)** | Port 22 Open, `OpenSSH_for_Windows` banner, Silent Recon OK |
| **Desktop** | Windows 11 (SSH Loud) | `192.168.1.104` | `22` | **Windows (75%)** | Port 22 Open, Trophy File, 1000-Loop Payloads, Voice Alert OK |
| **Apple iPad** | iPadOS 17+ (Darwin / BSD) | `192.168.0.152` | `80 81` | **macOS / BSD (48% / 100% Tier)** | TTL 64, Darwin Option Order (`WSCALE` before `TIMESTAMP`) |
| **Android Phone** | Android (Linux Kernel 5.x) | `192.168.0.169` | `2221 2122` | **Linux (58% / 100% Tier)** | TTL 64, Linux Option Order, `IP ID = 0` (RFC 6864) |
| **Android Phone**| Android (Closed Ports Only)| `192.168.0.169` | `2121 2122` | **Linux (67% Closed RST)** | TTL 64, Window 0, `IP ID = 0` via TCP RST |

---

### Run 6.1: Windows Desktop Standard Attack Chain

* **Target:** `192.168.0.116` (Desktop)
* **Services Running:** `victim/ftp_server.py` (port 21) & `victim/http_server.py` (port 80)
* **Command:**
  ```powershell
  python attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 21 22 80 81
  ```
* **Empirical Log:**
  ```text
  ─────────────────────────────────────────────────────────────────
       21  OPEN                           TTL=128 WIN=65535
       22  CLOSED                         TTL=128 WIN=0
       80  OPEN                           TTL=128 WIN=65535
       81  CLOSED                         TTL=128 WIN=0

    [PHASE 2] Service Banner Grabbing
    ✓    21  FTP      → LabFTP Server (Vulnerable Demo) Ready
    ✓    80  HTTP     → VulnHTTP/1.0 (Lab Demo)

    [PHASE 3] OS Fingerprinting
    Candidate  : Open-Port TCP SYN/ACK
    Likely OS  : Windows
    Confidence : 60%
    Version    : Windows 10 / 11 / Server 2016+ (71% tier)
    TTL        : 128 (initial 128, ~0 hop(s))
    Window     : 65535
    DF bit     : set
    IP ID      : 60211
    Options    : ('MSS', 1460), ('NOP',), ('WSCALE', 8), ('SACK_PERMITTED',), ('TIMESTAMP', ...)
    Evidence   :
      - initial TTL 128 is characteristic of Windows
      - TCP option order ['MSS', 'WSCALE', 'SACK_PERMITTED', 'TIMESTAMP'] matches Windows layout
      - IP ID is non-zero (60211) with DF set (characteristic of Windows/BSD)

    [PHASE 5] Exploit Execution
    [EXPLOIT] FTP Anonymous Login (port 21)       → Status: SUCCESS ✓
    [EXPLOIT] HTTP Directory Traversal (port 80) → Status: SUCCESS ✓ (8 payloads succeeded)

    ATTACK SUMMARY: 4 scanned | 2 open | 2 closed | Exploits: 2/2 successful
  ```

---

### Run 6.2: Active Defense & Windows Firewall Auto-Quarantine

* **Target:** `192.168.0.116` (Desktop)
* **Victim Terminal (Desktop Admin PowerShell):**
  ```powershell
  netsh advfirewall set allprofiles state on
  python defense\main.py --adapter "<DESKTOP_ADAPTER>" --threshold 8 --window 10 --block
  ```
* **Attacker Terminal (Laptop PowerShell):**
  ```powershell
  python attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 21 22 23 24 80 81 82 83 84
  ```
* **Empirical Outcome:**
  1. **Defense Alert:** When the 8th port was probed, Desktop defense triggered:
     ```text
     [ALERT] Possible TCP port scan from 192.168.0.105
     [MITIGATION] Blocked TCP traffic from 192.168.0.105
                  Firewall rule: CustomPortScanBlock_192_168_0_105
     ```
  2. **Attacker Scan Drops:** Subsequent closed ports were completely dropped:
     ```text
     22  NO RESPONSE / POSSIBLY FILTERED
     23  NO RESPONSE / POSSIBLY FILTERED
     24  NO RESPONSE / POSSIBLY FILTERED
     81  NO RESPONSE / POSSIBLY FILTERED
     82  NO RESPONSE / POSSIBLY FILTERED
     83  NO RESPONSE / POSSIBLY FILTERED
     84  NO RESPONSE / POSSIBLY FILTERED
     ```
  3. **Exploit Mitigation Proof:** HTTP Directory Traversal was blocked and failed due to dropped TCP connections:
     ```text
     [EXPLOIT] HTTP Directory Traversal (port 80)
     Status   : FAILED ✗
     Detail   : All 12 traversal payloads failed. Server may not be vulnerable or files not present.
     ```
  4. **Timing Impact:** Scan time increased from 5.4s to **1m 18.3s** due to TCP connection timeouts enforced by the Windows Filtering Platform.

---

### Run 6.3: Apple iPad (iPadOS 17 / Darwin BSD Stack)

* **Target:** `192.168.0.152` (iPad 9th Generation)
* **Service Running:** VLC for iOS — "Sharing via WiFi" enabled on port 80
* **Command:**
  ```powershell
  python attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.152 --ports 80 81 --skip-exploits
  ```
* **Empirical Log:**
  ```text
  ─────────────────────────────────────────────────────────────────
       80  OPEN                           TTL= 64 WIN=65535
       81  CLOSED                         TTL= 64 WIN=0

    [PHASE 2] Service Banner Grabbing
    ✓    80  HTTP     → HTTP/1.1 200 OK (VLC Web Sharing)

    [PHASE 3] OS Fingerprinting
    Candidate  : Open-Port TCP SYN/ACK
    Likely OS  : macOS / BSD
    Confidence : 48%
    Version    : macOS / modern BSD (100% tier)
    TTL        : 64 (initial 64, ~0 hop(s))
    Window     : 65535
    DF bit     : set
    Options    : ('MSS', 1460), ('NOP',), ('WSCALE', 5), ('NOP',), ('NOP',), ('TIMESTAMP', ...), ('SACK_PERMITTED',)
    Evidence   :
      - initial TTL 64 (~64 observed, 0 hop(s))
      - TCP window 65535 matches Unix-like stacks
      - TCP option order ['MSS', 'WSCALE', 'TIMESTAMP', 'SACK_PERMITTED'] matches a known macOS / BSD layout
      - Apple Darwin layout puts WSCALE before TIMESTAMP

    ATTACK SUMMARY: 2 scanned | 1 open | 1 closed | OS: macOS / BSD (48%)
  ```

---

### Run 6.4: Android Phone (Linux Modern Kernel with Open Port)

* **Target:** `192.168.0.169` (Android Smartphone)
* **Service Running:** WiFi FTP Server app listening on port 2221
* **Command:**
  ```powershell
  python attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.169 --ports 2221 2122 --skip-exploits
  ```
* **Empirical Log:**
  ```text
  ─────────────────────────────────────────────────────────────────
     2221  OPEN                           TTL= 64 WIN=65535
     2122  CLOSED                         TTL= 64 WIN=0

    [PHASE 2] Service Banner Grabbing
    ✓  2221  Unknown  → 220 Service ready for new user.

    [PHASE 3] OS Fingerprinting
    Candidate  : Open-Port TCP SYN/ACK
    Likely OS  : Linux
    Confidence : 58%
    Version    : Linux modern kernel (3.x / 4.x / 5.x+) [100% tier]
    TTL        : 64 (initial 64, ~0 hop(s))
    Window     : 65535
    DF bit     : set
    IP ID      : 0
    Options    : ('MSS', 1460), ('SACK_PERMITTED',), ('TIMESTAMP', 3118032441, 1), ('NOP',), ('WSCALE', 8)
    Probability:
      Linux             58%  ###########
      macOS / BSD       30%  ######
      Windows           12%  ##
    Evidence   :
      - initial TTL 64 (~64 observed, 0 hop(s))
      - TCP option order ['MSS', 'SACK_PERMITTED', 'TIMESTAMP', 'WSCALE'] matches a known Linux layout
      - IP ID is 0 with DF set (RFC 6864 standard Linux characteristic)
      - SACK permitted before Timestamp distinguishes Linux from Apple Darwin

    ATTACK SUMMARY: 2 scanned | 1 open | 1 closed | OS: Linux (58%)
  ```

---

### Run 6.5: Android Phone (Closed-Port RST Only)

* **Target:** `192.168.0.169` (Android Smartphone with no active services)
* **Command:**
  ```powershell
  python attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.169 --ports 2121 2122 --skip-exploits
  ```
* **Empirical Log:**
  ```text
  ─────────────────────────────────────────────────────────────────
     2121  CLOSED                         TTL= 64 WIN=0
     2122  CLOSED                         TTL= 64 WIN=0

    [PHASE 3] OS Fingerprinting
    Candidate  : Closed-Port TCP RST
    Likely OS  : Linux
    Confidence : 67%
    Version    : Linux family (closed-port RST)
    TTL        : 64 (initial 64)
    Window     : 0
    DF bit     : set
    IP ID      : 0
    Probability:
      Linux             67%  #############
      macOS / BSD       33%  ######
      Windows            0%
    Evidence   :
      - Probe response: TCP RST (Closed-Port Fingerprinting)
      - TCP window is 0
      - RST with initial TTL 64 indicates Linux/macOS/BSD stack
      - IP ID is 0 with DF set (RFC 6864, characteristic of Linux)
  ```

---

### Run 6.6: Windows Live SSH Weak Credential Exploitation (Quiet & Loud Modes)

* **Target:** `192.168.1.104` (Windows 11 Target PC — `AisheePC`)
* **Service Running:** Windows OpenSSH Server daemon (`sshd.exe`) listening on port 22
* **Attack Suite:** [scripts/test_ssh_attack.ps1](file:///scripts/test_ssh_attack.ps1)

#### Sub-Run 6.6.1: Quiet Mode (Stealth Reconnaissance)
* **Command:**
  ```powershell
  .\scripts\test_ssh_attack.ps1 quiet
  ```
* **Empirical Log Excerpt ([final-log/ssh_quiet.log](file:///final-log/ssh_quiet.log)):**
  ```text
  ─────────────────────────────────────────────────────────────────
       22  OPEN                           TTL=128 WIN=65535

    [PHASE 2] Service Banner Grabbing
    ✓    22  SSH      → SSH-2.0-OpenSSH_for_Windows_9.5

    [PHASE 3] OS Fingerprinting
    Candidate  : Open-Port TCP SYN/ACK
    Likely OS  : Windows
    Confidence : 75%
    Version    : Windows 10 / 11 / Server 2016+

    [PHASE 5] Exploit Execution
    [EXPLOIT] SSH Weak Credentials (port 22)
    Status   : SUCCESS ✓
    Detail   : Logged in as test:test123 (attempt 15/20)
    Attempts : 15
    Commands :
      whoami   → aisheepc\test
      hostname → AisheePC
      ipconfig → 169.254.17.114, 169.254.58.27, 192.168.1.104
      os_info  → Microsoft Windows [Version 10.0.26200.9445]
  ```

#### Sub-Run 6.6.2: Loud Mode (Spooky Payloads & Voice Alert)
* **Command:**
  ```powershell
  .\scripts\test_ssh_attack.ps1 loud
  ```
* **Empirical Log Excerpt ([final-log/ssh_attack.log](file:///final-log/ssh_attack.log)):**
  ```text
    [PHASE 5] Exploit Execution
    [EXPLOIT] SSH Weak Credentials (port 22)
    Status   : SUCCESS ✓
    Detail   : Logged in as test:test123 (attempt 15/20)
    Attempts : 15
    Commands :
      whoami          → aisheepc\test
      hostname        → AisheePC
      ipconfig        → 169.254.17.114, 169.254.58.27, 192.168.1.104
      os_info         → Microsoft Windows [Version 10.0.26200.9445]
      desktop_proof   → Spooky trophy file PROOF_OF_ACCESS.txt created on Desktop
      hacked_payloads → Interactive payloads (HACKED.exe, HACKED.bat, hacked.py) created on Desktop
      voice_alert     → Spooky voice alert played on victim speakers
  ```
* **Physical & Visual Demonstration Results:**
  1. `PROOF_OF_ACCESS.txt` created with security alert attribution: *"Abhishek and Turjo have taken over your computer for their Security project. You should be careful with SSH xd"*.
  2. `HACKED.exe`, `HACKED.bat`, and `hacked.py` dropped on the Desktop. Double-clicking any launches an animated Matrix-green 1000-iteration loop in a Command Prompt console.
  3. Physical speakers on the target machine synthesize and speak the voice warning aloud.

---

## 7. Advanced OS Fingerprinting Extensions Workflow (All 7 Ideas) ⭐

This section provides the complete reference and operational testing guide for all seven advanced fingerprinting extensions developed in `Imp/common/` and `Imp/attacker/`. All techniques operate entirely through raw packet crafting using Python's native `struct` library and direct Npcap framing—**strictly zero Scapy or Nmap binaries**.

### 7.0 Overview of the 7 Extension Features

| # | Feature / Idea | Category | RFC Standards | Key Signatures Detected |
|---|---|---|---|---|
| **১** | **RST Packet Fingerprinting** | Passive TCP | RFC 793 / RFC 9293 | Closed-port RST TTL, window size (0 vs non-zero), and flags. |
| **৭.১**| **Banner-to-Fingerprint Cross-Correlation** | Application Layer | RFC 7230 / RFC 4253 | Server banners (IIS, Apache, Ubuntu, vsftpd) & HTTP header ordering (`Server` vs `Date`). |
| **২** | **Sequential IP ID Multi-Probe Tracking** | Passive IPv4 | RFC 6864 / RFC 791 | Multi-probe sequences: `ALL_ZERO` (Linux), `STRICT_INCREMENTAL` (Windows), `RANDOM_POSITIVE` (Darwin BSD). |
| **৩** | **TCP Timestamp Clock & Uptime Estimation** | Passive TCP Options | RFC 7323 | Clock frequency ($\Delta TSval / \Delta t$) ~1000Hz (Windows), ~250Hz/100Hz (Linux), and PRNG random offset (Apple Darwin). |
| **৪** | **RFC 3168 ECN Active Reflection Probe** | Active TCP Probing | RFC 3168 | `ECE`+`CWR` SYN probe: Windows ignores (`0x12`), Linux/Darwin reflect `ECE` (`0x52`), Firewalls drop. |
| **৫** | **Ambiguous / Invalid TCP Flags ("Rule-Breaker")** | Active TCP Probing | RFC 793 State Machine | `SYN+FIN`: Windows sends RST on open port (RFC 793 violation); Linux drops on open, RST on closed; Darwin BSD drops both. |
| **৬** | **ICMP/UDP Battery & Firewall Fallback** | Active ICMP / UDP | RFC 792 / RFC 1122 | Echo `Code 9` normalization (Windows Code 0), Darwin `DF=1` on ICMP, UDP U1 quoting length (Windows 328B vs Darwin 28B). |

---

### 7.1 Automated Unit Test Suite (Full Test Coverage)

Every single feature, mathematical parser, and heuristic rule is rigorously validated against a comprehensive pytest test suite containing **51 automated unit tests**.

```powershell
cd "e:\4-1 Course Works\portscan-os\Imp"
python -m pytest tests\ -v
```

#### Test Suite Breakdown:
- **`NormaliseTtlTests` (3 tests):** Normalization of initial TTL across network hops (32, 64, 128, 255).
- **`FingerprintTests` (5 tests):** Baseline confidence, score distribution, and backward-compatible dictionary keys.
- **`VersionTierTests` (4 tests):** Granular build-tiering for Windows (11/10 vs 7/XP) and Linux (modern vs legacy).
- **`ClosedPortRstTests` (2 tests):** Idea 1 closed-port TCP RST heuristics.
- **`IpIdHeuristicTests` (2 tests):** Single-packet RFC 6864 zero vs non-zero IP ID heuristics.
- **`BannerCrossLayerTests` (5 tests):** Idea 7.1 banner matching (IIS, Ubuntu SSH, iOS VLC, Cisco) and HTTP header ordering.
- **`IpIdSequenceTrackingTests` (5 tests):** Idea 2 multi-probe sequential analysis (`ALL_ZERO`, `STRICT_INCREMENTAL`, `RANDOM_POSITIVE`).
- **`TcpTimestampClockTests` (5 tests):** Idea 3 clock rates (1000Hz, 250Hz), Apple PRNG randomization, and uptime calculation.
- **`EcnProbeFingerprintTests` (5 tests):** Idea 4 RFC 3168 ECN reflection states (`ECN_SUPPORTED`, `ECN_IGNORED`, `ECN_DROPPED`).
- **`InvalidFlagsFingerprintTests` (5 tests):** Idea 5 SYN+FIN responses across Windows, Linux, and Darwin BSD archetypes.
- **`IcmpUdpFingerprintTests` (5 tests):** Idea 6 ICMP Echo Code reflection/normalization, UDP quoting length, and autonomous firewall fallback.
- **`PacketTests` (5 tests):** Low-level packet builders (SYN, UDP, ICMP Echo, Internet Checksum, TCP Options parser).

**Result:** `51 passed in ~0.08s (100% PASS)`

---

### 7.2 The 3-Tier Hierarchical Fallback Architecture

To maximize intelligence while retaining robust fault tolerance, the engine employs a three-tier candidate prioritization hierarchy:

```
                  [ 1. Inbound TCP SYN Probes Executed ]
                                     │
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ Tier 1: Open-Port TCP SYN/ACK       │  ◄── [PRIMARY CANDIDATE]
                  │ (MSS, Window, Options, TSval, WScale│       Full OS + Build Version Tiering
                  └─────────────────────────────────────┘
                                     │
                        (No open ports found ❌)
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ Tier 2: Closed-Port TCP RST         │  ◄── [FIRST FALLBACK]
                  │ (RST TTL, Win=0, DF, IP ID Seq)     │       RFC 793 Compliant Detection
                  └─────────────────────────────────────┘
                                     │
                  (All ports Filtered / No Response ❌)
                                     ▼
                  ┌─────────────────────────────────────┐
                  │ Tier 3: ICMP Echo Reply             │  ◄── [ULTIMATE FALLBACK]
                  │ (Echo TTL, DF=1 Darwin, Code 0 Norm)│       Bypasses Personal Stealth Firewalls
                  └─────────────────────────────────────┘
```

*Note: The `--prefer-icmp` CLI flag allows testers to force Tier 3 evaluation directly for demonstration purposes.*

---

### 7.3 Live Empirical Testing Across All 3 Target Devices

#### Device A: Windows 11 Desktop (`192.168.0.116`)

##### 1. Full Stack Scan (Open Ports 21, 80 & Closed Ports 22, 81)
```powershell
python -u attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 21 22 80 81 --skip-exploits
```
* **Key Observations:**
  - **Candidate:** `Open-Port TCP SYN/ACK`
  - **OS & Confidence:** **Windows (72%)** [Highest recorded for open ports!]
  - **Version Tiers:** 71% Windows 10/11/Server 2016+, 29% Windows 7/8.
  - **Timestamp Clock:** ~972.5 Hz (`HZ_1000`), Uptime: ~1h 30m.
  - **IP ID Sequence:** `[25998, 25999, 26001, 26002, 26004, 26006]` $\implies$ `STRICT_INCREMENTAL` (+1, +2 pattern).
  - **ECN Probe:** `ECN_IGNORED` (`Flags: 0x12` - Windows does not negotiate ECN on passive SYN/ACK by default).
  - **Invalid Flags (SYN+FIN):** `RST on Open Port (Flags=0x14)` $\implies$ Windows actively violates RFC 793 by resetting valid connections.
  - **ICMP/UDP:** Windows normalizes `Code 9 -> Code 0` on Echo Reply, U1 quotes entire `328B` payload.

##### 2. Real Firewall Stealth Mode Test (Filtered Ports 22, 81 with Windows Firewall ON)
```powershell
python -u attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.116 --ports 22 81 --skip-exploits
```
* **Key Observations:**
  - **Phase 1 Status:** Ports 22 and 81 return `NO RESPONSE / POSSIBLY FILTERED` (Windows Defender stealth drop).
  - **Candidate:** `ICMP Echo Reply` (Autonomous Firewall Fallback triggered!).
  - **OS & Confidence:** **Windows (94%)** (ICMP Code 0 normalized, TTL=128, DF=0).

---

#### Device B: Android Smartphone (`192.168.0.169` — Linux Kernel 5.x)

##### 1. Active Service Scan (FTP Server on Port 2221, Closed Port 2122)
```powershell
python -u attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.169 --ports 2221 2122 --skip-exploits
```
* **Key Observations:**
  - **Candidate:** `Open-Port TCP SYN/ACK`
  - **OS & Confidence:** **Linux (60%)** [100% Modern Linux Tier].
  - **IP ID Sequence:** `[0, 0, 0]` $\implies$ `ALL_ZERO` with DF=1 (RFC 6864 Linux signature).
  - **ECN Probe:** `ECN_SUPPORTED` (`ECE reflected: True, Flags: 0x52`).
  - **Invalid Flags (SYN+FIN):** Dropped on Open Port, RST on Closed Port $\implies$ RFC 793 compliant Linux/Unix archetype.
  - **ICMP/UDP:** `Code 9` reflected verbatim, DF=0, TTL=64, UDP probe silently filtered.

##### 2. Closed Ports Pure RST Scan (Ports 12345, 54321)
```powershell
python -u attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.169 --ports 12345 54321 --skip-exploits
```
* **Key Observations:**
  - **Candidate:** `Closed-Port TCP RST`
  - **OS & Confidence:** **Linux (76%)** (RST initial TTL=64, Win=0, IP ID Sequence `[0, 0]`).

##### 3. Preferred ICMP Candidate Demo (Bypassing TCP)
```powershell
python -u attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.169 --ports 12345 54321 --skip-exploits --prefer-icmp
```
* **Key Observations:**
  - **Candidate:** `ICMP Echo Reply`
  - **OS & Confidence:** **Linux (67%)** (ICMP Code 9 reflected, TTL=64, DF=0).

---

#### Device C: Apple iPad (`192.168.0.152` — iPadOS 17 / Darwin BSD)

##### 1. Active Service Scan (HTTP VLC Server on Port 80, Closed Port 8080)
```powershell
python -u attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.152 --ports 80 8080 --skip-exploits
```
* **Key Observations:**
  - **Candidate:** `Open-Port TCP SYN/ACK`
  - **OS & Confidence:** **macOS / BSD (64%)** [100% Modern Darwin Tier].
  - **Option Order:** `['MSS', 'NOP', 'WSCALE', 'NOP', 'NOP', 'TIMESTAMP', 'SACK_PERMITTED']` $\implies$ Darwin puts `WSCALE` before `TIMESTAMP`.
  - **Timestamp Clock:** `Randomized offset (RFC 7323 Darwin PRNG)` $\implies$ Timestamp jumps exceed 10,000,000 per RFC 7323 privacy hardening.
  - **ECN Probe:** `ECN_SUPPORTED` (`ECE reflected: True, Flags: 0x52`).
  - **Invalid Flags (SYN+FIN):** `Total Drop on Open & Closed` $\implies$ Darwin packet filter / kernel hygiene silently discards illegal combinations.
  - **ICMP/UDP:** **`DF=1` set on ICMP Echo Reply** (RFC 6864 zero IP ID compliance), `Code 9` reflected, UDP U1 quotes exactly **28 Bytes** (RFC 792 minimum).

##### 2. Closed Ports Pure RST Scan (Ports 12345, 54321)
```powershell
python -u attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.152 --ports 12345 54321 --skip-exploits
```
* **Key Observations:**
  - **Candidate:** `Closed-Port TCP RST`
  - **OS & Confidence:** **macOS / BSD (67%)** (RST TTL=64, Win=0, IP ID Sequence `[23100, 63025]` `RANDOM_POSITIVE`).

##### 3. Preferred ICMP Candidate Demo (Bypassing TCP)
```powershell
python -u attacker\main.py --adapter "\Device\NPF_{A1D23BF4-3809-4F50-9ED3-9E25625DA229}" --target 192.168.0.152 --ports 12345 54321 --skip-exploits --prefer-icmp
```
* **Key Observations:**
  - **Candidate:** `ICMP Echo Reply`
  - **OS & Confidence:** **macOS / BSD (63%)** (DF=1 on ICMP, Code 9 reflected, U1 quotes 28B).

---

### 7.4 Multi-Step Progression Matrix Across the Entire Project

```
Step 0 (Baseline)  ──► Step 1 (Banner 7.1) ──► Step 2 (IP ID 2)       ──► Step 3 (TSval 3)       ──► Step 4 (ECN 4)         ──► Step 5 (Flags 5)       ──► Step 6 (ICMP/UDP 6)
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Windows: 60%       ──► Windows: 62%        ──► Windows: 62% (STRICT) ──► Windows: 62% (1000Hz) ──► Windows: 65% (ECN Ign)  ──► Windows: 69% (RST Open) ──► Windows: 72% (Code Norm + 328B)
Linux: 58%         ──► Linux: 58%          ──► Linux: 60% (ALL_ZERO) ──► Linux: 56% (Timer)   ──► Linux: 55% (ECN Supp) ──► Linux: 56% (RFC Drop)  ──► Linux: 60% (Code Refl + DF=0)
macOS/BSD: 48%     ──► macOS/BSD: 48%      ──► macOS/BSD: 53% (+5%)  ──► macOS/BSD: 59% (+6%)  ──► macOS/BSD: 57% (ECN Supp) ──► macOS/BSD: 60% (Total Drop)──► macOS/BSD: 64% (DF=1 + 28B min)
Unit Tests: 19 PASS──► Unit Tests: 24 PASS ──► Unit Tests: 29 PASS   ──► Unit Tests: 34 PASS   ──► Unit Tests: 39 PASS     ──► Unit Tests: 44 PASS    ──► Unit Tests: 51 PASS
```

---

### 7.5 Project Log Files Reference

The following step-by-step logs document every execution run:
- **`logs/step0.log`:** Baseline SYN scan & RST fingerprinting.
- **`logs/step1.log`:** Idea 7.1 Banner-to-Fingerprint cross-layer correlation.
- **`logs/step2.log`:** Idea 2 Sequential IP ID tracking (`ALL_ZERO`, `STRICT_INCREMENTAL`, `RANDOM_POSITIVE`).
- **`logs/step3.log`:** Idea 3 TCP Timestamp clock frequency and system uptime calculation.
- **`logs/step4.log`:** Idea 4 RFC 3168 ECN active reflection probing.
- **`logs/step5.log`:** Idea 5 Ambiguous/Invalid TCP flags (`SYN+FIN`) "Rule-Breaker" probing.
- **`logs/step6.log`:** Idea 6 ICMP Echo Code reflection, UDP U1 quoting length, and autonomous fallback.
- **`logs/step6_icmp_only.log`:** Pure ICMP Echo Reply candidate runs across all three targets under stealth firewall conditions.


