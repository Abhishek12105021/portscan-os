# Victim Setup — Simulated Vulnerable Services

These are **intentionally vulnerable** services designed to be exploited by the
attack toolkit during the lab demonstration.

> **WARNING**: Do NOT run these on a production network or any machine
> accessible from the Internet. Use only in an isolated lab environment.

## Quick Start

Open **three** separate Administrator terminals on the victim machine.

### Terminal 1 — Vulnerable FTP Server (port 21)

```powershell
cd portscan_project_windows
python victim\ftp_server.py --port 21
```

The FTP server:
- Allows **anonymous login** (USER anonymous, PASS anything)
- Serves files from `./ftp_root/`
- Creates sample files automatically on first run

### Terminal 2 — Vulnerable HTTP Server (port 80)

```powershell
cd portscan_project_windows
python victim\http_server.py --port 80
```

The HTTP server:
- Has **NO path traversal protection** — `../` sequences are not sanitised
- Serves files from `./web_root/`
- Creates a sample `index.html` on first run

### Terminal 3 — Defense Detector (optional)

```powershell
cd portscan_project_windows
python defense\main.py --adapter "<NPCAP ADAPTER>" --threshold 8 --window 10
```

## SSH Setup (for SSH exploit)

For the SSH weak credential exploit, you need an SSH server running on the
victim with a test account that has a weak password.

### Option A — Windows OpenSSH

1. Install OpenSSH Server:
   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   ```

2. Start the service:
   ```powershell
   Start-Service sshd
   Set-Service -Name sshd -StartupType Automatic
   ```

3. Create a test user with a weak password:
   ```powershell
   net user test test123 /add
   ```

4. After the demo, remove the test user:
   ```powershell
   net user test /delete
   ```

### Option B — Skip SSH Exploit

If SSH setup is too complex, the scanner will simply report "SSH Weak
Credentials: FAILED — all credential pairs failed" and continue with
the other exploits.

## What Gets Created

On first run, the servers create these sample files:

```
ftp_root/
    pub/
        readme.txt              ← "If you can read this, the exploit worked!"
        data/
            credentials.txt     ← Fake credentials for demo

web_root/
    index.html                  ← Simple welcome page
```

## Running the Attack

From the attacker machine:

```powershell
cd portscan_project_windows
python attacker\main.py ^
    --adapter "<NPCAP ADAPTER>" ^
    --target <VICTIM_IP> ^
    --ports 21 22 80 443 445 3389
```

## Cleanup

After the demo:
1. Stop all servers (Ctrl+C in each terminal)
2. Delete the test SSH user if created (`net user test /delete`)
3. Remove `ftp_root/` and `web_root/` directories if desired
4. Any Windows Firewall rules created by the defense detector are
   automatically removed on Ctrl+C
