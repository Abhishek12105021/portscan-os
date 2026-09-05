# How to Run — Step-by-Step Command Guide

This guide covers everything needed to run the project in
[portscan_project_windows/](portscan_project_windows/), from installing Python
to executing the attacker, victim, and defense scripts. Follow it on **both**
machines (attacker + victim) in your private lab network/VMs.

---

## 0. Requirements Recap

- Two Windows machines (physical PCs or VMs, e.g. VirtualBox/Hyper-V/VMware)
  on the **same private LAN or host-only/internal network**.
- Administrator access on both.
- This project sends raw Ethernet/IPv4/TCP frames, so it will **not** work
  over localhost/loopback — you need two real network endpoints that can see
  each other's MAC addresses (same L2 segment).

---

## 1. Install Python 3.11+ (skip if already installed)

Check first:

```powershell
python --version
```

If this prints `Python 3.11.x` or newer, skip to Section 2.

If Python is **not installed** or is too old:

1. Download the installer from the official source:
   `https://www.python.org/downloads/windows/`
   (choose "Windows installer (64-bit)" for the latest 3.11.x or 3.12.x)

2. Run the installer with these options:
   - **Check "Add python.exe to PATH"** at the bottom of the first screen —
     this is critical, do not skip it.
   - Click "Install Now" (or "Customize installation" → keep defaults →
     also check "Install for all users" if you want it system-wide).

3. Alternatively, install silently from an Administrator PowerShell if you
   already have the `.exe` downloaded:

   ```powershell
   Start-Process -FilePath "python-3.11.9-amd64.exe" -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
   ```

4. Or install via `winget` (Windows Package Manager, built into Windows 10/11):

   ```powershell
   winget install -e --id Python.Python.3.11
   ```

5. **Close and reopen** your terminal after installing so the updated PATH
   takes effect, then verify:

   ```powershell
   python --version
   pip --version
   ```

---

## 2. Install Npcap (both machines)

Npcap provides raw packet I/O on Windows; this project's `common/npcap.py`
binds to it via `ctypes`.

1. Download Npcap from the official site: `https://npcap.com/#download`
2. Run the installer **as Administrator**.
3. During installation, **check "Install Npcap in WinPcap API-compatible
   Mode"** if the installer offers that checkbox.
4. Finish the install, reboot if the installer asks you to.

---

## 3. Get the Project Files onto Both Machines

Copy (or share via network drive / USB) the entire
`portscan_project_windows/` folder to both the attacker and victim machines.

Then open an **Administrator PowerShell** and move into the project folder:

```powershell
cd "E:\4-1\Security Lab\Project\portscan_project_windows"
```

(Adjust the path if you copied it elsewhere, e.g. `cd C:\lab\portscan_project_windows`.)

---

## 4. Create a Virtual Environment (recommended, optional)

This keeps `paramiko` isolated from your system Python.

```powershell
python -m venv venv
```

Activate it:

```powershell
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks the script with an execution-policy error, run once
(as Administrator):

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

then re-run the `Activate.ps1` command above. Your prompt should now show
`(venv)` at the start.

To leave the venv later: `deactivate`

---

## 5. Install Python Dependencies

With the venv activated (or system-wide if you skipped Section 4):

```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

This installs `paramiko` (only used by the SSH brute-force exploit). Verify:

```powershell
pip show paramiko
```

---

## 6. Find the Npcap Adapter Name (both machines)

```powershell
python tools\list_npcap_adapters.py
```

This lists available Npcap-visible network adapters. Copy the exact name
string printed for your active Ethernet/Wi-Fi adapter — you will pass it as
`--adapter "<NAME>"` in every command below.

---

## 7. Find the Victim's IP Address (on the victim machine)

```powershell
ipconfig
```

Note the `IPv4 Address` under the adapter that matches the one you picked in
Section 6 (e.g. `192.168.56.101`).

---

## 8. Start the Vulnerable Victim Services (on the victim machine)

Open two separate Administrator PowerShell windows (or use background jobs),
`cd` into the project folder in each, activate the venv if you created one,
then run:

**Terminal A — FTP server:**
```powershell
python victim\ftp_server.py
```

**Terminal B — HTTP server:**
```powershell
python victim\http_server.py
```

Leave both running. See [victim/README.md](portscan_project_windows/victim/README.md)
for any server-specific flags.

---

## 9. Start the Defense/Detector (on the victim machine)

Open a **third** Administrator PowerShell window on the victim, `cd` into the
project folder, activate venv if used, then:

```powershell
python defense\main.py --adapter "<NPCAP ADAPTER NAME>" --threshold 8 --window 10
```

To also enable temporary Windows Firewall auto-blocking of detected scanners:

```powershell
python defense\main.py --adapter "<NPCAP ADAPTER NAME>" --threshold 8 --window 10 --block
```

Leave this running; it will print alerts to the console when it detects a
scan pattern. Press `Ctrl+C` to stop it (this also removes any firewall rules
it created if `--block` was used).

---

## 10. (Optional) Start Wireshark Capture (on the victim machine)

1. Open Wireshark, select the same adapter you used in Section 6.
2. Start capturing.
3. Useful display filters:
   - Initial SYN: `tcp.flags.syn == 1 && tcp.flags.ack == 0`
   - SYN/ACK: `tcp.flags.syn == 1 && tcp.flags.ack == 1`
   - RST: `tcp.flags.reset == 1`

---

## 11. Run the Attacker Toolchain (on the attacker machine)

Open an Administrator PowerShell, `cd` into the project folder, activate venv
if used, then run the full orchestrated attack chain:

```powershell
python attacker\main.py --adapter "<NPCAP ADAPTER NAME>" --target 192.168.56.101 --ports 21 22 80 443
```

Replace `192.168.56.101` with the victim's actual IP from Section 7, and
adjust the `--ports` list as needed (max 50 probes per run — this is a hard
safety limit built into the scanner).

This single command chains, in order:
1. TCP SYN port scan (`attacker/scanner.py`)
2. Service banner grabbing (`attacker/banner.py`)
3. OS fingerprinting (`attacker/fingerprint.py`)
4. Exploits against any matching open services:
   - FTP anonymous login (`attacker/exploits/ftp_anon.py`)
   - SSH weak-credential brute force (`attacker/exploits/ssh_bruteforce.py`) — requires `paramiko`
   - HTTP path traversal (`attacker/exploits/http_traversal.py`)

### Running individual phases instead (optional)

If you want to run just one phase manually instead of the full chain, check
each script's `--help` for its exact flags, e.g.:

```powershell
python attacker\scanner.py --help
python attacker\banner.py --help
python attacker\fingerprint.py --help
python attacker\exploits\ftp_anon.py --help
python attacker\exploits\ssh_bruteforce.py --help
python attacker\exploits\http_traversal.py --help
```

---

## 12. Stopping Everything / Cleanup

On the victim:
- Press `Ctrl+C` in the defense terminal (Section 9) — removes any firewall
  rules it created.
- Press `Ctrl+C` in the FTP/HTTP server terminals (Section 8).

If a firewall rule was left behind after an abrupt termination, check and
remove it manually:

```powershell
netsh advfirewall firewall show rule name=CustomPortScanBlock*
netsh advfirewall firewall delete rule name="<exact rule name from above>"
```

---

## 13. Running the Unit Tests (optional, either machine)

```powershell
cd "E:\4-1\Security Lab\Project\portscan_project_windows"
pip install pytest
python -m pytest tests\ -v
```

---

## 14. Quick Reference — Full Command Sequence

```powershell
# --- one-time setup, both machines ---
winget install -e --id Python.Python.3.11
# install Npcap manually from https://npcap.com/#download (WinPcap-compatible mode)
cd "E:\4-1\Security Lab\Project\portscan_project_windows"
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
python tools\list_npcap_adapters.py

# --- victim machine ---
python victim\ftp_server.py                       # terminal A
python victim\http_server.py                      # terminal B
python defense\main.py --adapter "Ethernet0" --threshold 8 --window 10   # terminal C
ipconfig                                           # note victim IP

# --- attacker machine ---
python attacker\main.py --adapter "Ethernet0" --target 192.168.56.101 --ports 21 22 80 443
```

---

## Safety Reminder

Only run this against machines you own or have explicit permission to test,
on an isolated private lab network. The scanner enforces a hard cap of 50
probes per run and never scans an IP range — do not modify it to do so.
