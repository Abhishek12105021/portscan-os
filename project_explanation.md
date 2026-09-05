# Project Explanation — Understanding the Port Scanner Toolkit

> A plain-language walkthrough of the entire CSE406 Security Lab Project #8

---

## What Is This Project?

Imagine you're a security professional (or an attacker). You're standing outside a building (a computer) and you want to know:

1. **Which doors are open?** → Port Scanning
2. **What's behind each door?** → Banner Grabbing
3. **What kind of building is it?** → OS Fingerprinting
4. **Can I walk through any unlocked door?** → Exploit Execution
5. **How does the building's security guard react?** → Defense Detection

This project builds ALL of these capabilities **from scratch** in Python, running on Windows.

---

## The Big Picture — Attack Chain

```
Step 1: SCAN          Step 2: IDENTIFY        Step 3: FINGERPRINT
  "Which ports         "What software           "What OS is
   are open?"           is running?"              running?"
     │                     │                        │
     ▼                     ▼                        ▼
  Send SYN             Connect to               Analyze TTL,
  packets to           open ports,              window size,
  each port            read banners             TCP options
     │                     │                        │
     └─────────────────────┴────────────────────────┘
                           │
                           ▼
                    Step 4: EXPLOIT
                  "Can I break in using
                   what I've learned?"
                       │
           ┌───────────┼───────────┐
           ▼           ▼           ▼
      FTP Anon     SSH Weak    HTTP Path
      Login        Password    Traversal
```

---

## Part 1: Port Scanning — "Knocking on Doors"

### What is a port?

A **port** is like a numbered door on a computer. Each network service listens on a specific port:

| Port | Service | What It Does |
|------|---------|-------------|
| 21 | FTP | File transfer |
| 22 | SSH | Secure remote login |
| 80 | HTTP | Web pages |
| 443 | HTTPS | Encrypted web pages |
| 445 | SMB | Windows file sharing |
| 3389 | RDP | Windows Remote Desktop |

There are 65,535 possible ports. Most are closed (no service listening).

### How does our scanner work?

We use a technique called **SYN scanning** (also known as "half-open" or "stealth" scanning).

**Normal TCP connection** (like your browser connecting to a website):
```
Your computer  ──── SYN ────────►  Server     "Hey, let's talk"
Your computer  ◄─── SYN/ACK ────  Server     "OK, I'm ready"
Your computer  ──── ACK ────────►  Server     "Great, connected!"
                                               ↑ This is the 3-way handshake
```

**Our SYN scan** — we STOP after step 2:
```
Our scanner    ──── SYN ────────►  Target     "Hey, let's talk"
Our scanner    ◄─── SYN/ACK ────  Target     "OK, I'm ready"
Our scanner    (doesn't reply)                 ← Port is OPEN!
```

If the port is **closed**, the target sends back a RST (reset) instead:
```
Our scanner    ──── SYN ────────►  Target     "Hey, let's talk"
Our scanner    ◄─── RST ─────────  Target     "Go away, nothing here"
                                               ← Port is CLOSED
```

If the port is **filtered** (blocked by a firewall), we get nothing:
```
Our scanner    ──── SYN ────────►  Target     "Hey, let's talk"
Our scanner    ... silence ...                 ← Port is FILTERED
```

### Why is this "from scratch"?

The key requirement of this project is that we **build our own packets byte by byte**. We don't use Nmap or Scapy (which are ready-made tools).

Our code manually constructs:
- **Ethernet header** (14 bytes) — MAC addresses + "this is IPv4"
- **IPv4 header** (20 bytes) — IP addresses + "this is TCP"
- **TCP header** (20 bytes) — port numbers + SYN flag

We even compute the **checksums** ourselves using the Internet checksum algorithm (RFC 1071). The only external tool we use is **Npcap**, which is just a driver that lets us send/receive raw packets on Windows — it doesn't know anything about scanning.

### Safety limits

Our scanner has strict safety limits:
- Only scans **one specific private IP** (not the internet)
- Maximum **50 ports** per run
- Minimum **0.5 second delay** between probes
- This is NOT a denial-of-service tool

---

## Part 2: Banner Grabbing — "Reading the Door Signs"

After we know which ports are open, we want to know **what software** is listening.

Many services announce themselves when you connect. For example:

- **FTP**: `220 vsftpd 3.0.3` — tells us it's vsftpd version 3.0.3
- **SSH**: `SSH-2.0-OpenSSH_8.2p1` — tells us it's OpenSSH version 8.2
- **HTTP**: `Server: Apache/2.4.49` — tells us it's Apache version 2.4.49

This information is called a **banner**. We grab it by:
1. Opening a normal TCP connection to the port
2. Reading whatever the service sends us (or sending a probe for HTTP)
3. Parsing out the service name and version

### Why does this matter?

Because specific software versions have **known vulnerabilities**. If we know "Apache 2.4.49" is running, we can look up CVEs (Common Vulnerabilities and Exposures) for that exact version.

---

## Part 3: OS Fingerprinting — "What Kind of Building?"

Different operating systems implement TCP/IP slightly differently. By examining the response packets, we can guess what OS the target is running.

### Key differences we look at:

**TTL (Time To Live):**
- Windows sets initial TTL = **128**
- Linux sets initial TTL = **64**
- macOS sets initial TTL = **64**

**TCP Window Size:**
- Windows typically uses **64240** or **65535**
- Linux typically uses **29200** or **65160**

**TCP Options ordering:**
- Windows: MSS, NOP, WSCALE, NOP, NOP, SACK
- Linux: MSS, SACK, Timestamp, NOP, WSCALE

### How confident can we be?

Not 100%. These are **heuristics** (educated guesses). Firewalls, NAT devices, and custom configurations can change these values. We report results like "Windows family, 81% confidence" — never "definitely Windows 10 Build 19044."

The foundational research on this technique was published by Fyodor (creator of Nmap) in Phrack Magazine Issue 54 (1998), and the core principles haven't changed.

---

## Part 4: Exploits — "Walking Through Unlocked Doors"

This is where reconnaissance becomes action. Using the information from scanning, banner grabbing, and OS fingerprinting, we attempt three proof-of-concept exploits.

### Exploit 1: FTP Anonymous Login

**What it exploits**: Misconfigured FTP servers that allow login without credentials.

**How it works**:
```
1. Connect to port 21
2. Send: USER anonymous
3. Send: PASS anonymous@example.com
4. If the server says "230 Login successful" → we're in!
5. List files, download data — proof of unauthorized access
```

**Real-world relevance**: FTP misconfiguration is extremely common. The MITRE ATT&CK framework documents this as technique T1078 (Valid Accounts — Default Credentials).

### Exploit 2: SSH Weak Credentials

**What it exploits**: SSH servers that allow password login with weak/default passwords.

**How it works**:
```
1. Connect to port 22
2. Try a small list of common username/password pairs:
   - admin / admin
   - root / root
   - test / test123
   - user / password
   ... (10 pairs total)
3. If any pair works → we have remote shell access!
4. Run commands like 'whoami' to prove access
```

**Real-world relevance**: Weak credentials are the #1 cause of breaches. Tools like Hydra automate this at scale, but we use a small bounded wordlist for demonstration.

### Exploit 3: HTTP Directory Traversal

**What it exploits**: Web servers that don't properly validate file paths.

**How it works**:
```
1. Connect to port 80
2. Send: GET /../../../../etc/passwd HTTP/1.0
3. The "../" sequences climb UP the directory tree
4. If the server returns file contents → we can read any file!
```

**Visual explanation**:
```
Web root:  /var/www/html/
Request:   /var/www/html/../../../../etc/passwd
Resolves:  /etc/passwd  ← OUTSIDE the web root!
```

**Real-world relevance**: This is OWASP Top 10 vulnerability A01:2021 — Broken Access Control. A famous example is CVE-2021-41773 in Apache 2.4.49.

---

## Part 5: Defense — "The Security Guard"

### Detection: How does it spot a scan?

Our detector watches ALL incoming TCP traffic and looks for a pattern:

> "Is one source IP sending SYN packets to MANY different ports in a SHORT time?"

**Algorithm**:
- For each source IP, keep a sliding window of recent SYN events
- Track: how many SYNs? How many DIFFERENT destination ports?
- If both numbers exceed thresholds → **ALERT!**

**Why the dual condition?** A legitimate user might make 20 rapid connections to port 443 (loading a web page with many resources). That's not a scan. But 20 connections to 20 DIFFERENT ports? That's suspicious.

### Mitigation: What happens when a scan is detected?

If the `--block` flag is enabled, the detector creates a Windows Firewall rule:

```
netsh advfirewall firewall add rule
    name="CustomPortScanBlock_192_168_1_10"
    dir=in action=block remoteip=192.168.1.10
```

This immediately blocks ALL TCP traffic from the attacker. The rule is automatically cleaned up when the detector exits.

---

## How Everything Fits Together — Demo Flow

```
┌──────────── VICTIM MACHINE ─────────────┐
│                                          │
│  Terminal 1: Defense detector running    │
│  Terminal 2: Wireshark capturing         │
│  Services: FTP (21), SSH (22), HTTP (80) │
│                                          │
└────────────────────┬─────────────────────┘
                     │ Private LAN
┌────────────────────┴─────────────────────┐
│                                          │
│  ATTACKER MACHINE                        │
│                                          │
│  $ python attacker/main.py               │
│     --adapter "\\Device\\NPF_{...}"      │
│     --target 192.168.1.25                │
│     --ports 21 22 80 443 445 3389        │
│                                          │
│  Output:                                 │
│    Phase 1: Port 21 OPEN, 22 OPEN...     │
│    Phase 2: FTP vsftpd 3.0.3...         │
│    Phase 3: Windows family, 81%          │
│    Phase 5: FTP anon → SUCCESS!          │
│             SSH brute → SUCCESS!         │
│             HTTP traversal → SUCCESS!     │
│                                          │
└──────────────────────────────────────────┘

Meanwhile, on the victim:
  [ALERT] Port scan detected from 192.168.1.10!
  [MITIGATION] Blocked TCP from 192.168.1.10
```

---

## Key Concepts Glossary

| Term | Meaning |
|------|---------|
| **SYN** | TCP flag that initiates a connection ("synchronize") |
| **SYN/ACK** | Response confirming willingness to connect |
| **RST** | Response rejecting the connection ("reset") |
| **ACK** | Acknowledgment flag completing the handshake |
| **TTL** | Time To Live — how many network hops before packet dies |
| **MSS** | Maximum Segment Size — largest TCP payload the sender can handle |
| **Window Size** | How much data the receiver can buffer |
| **SACK** | Selective Acknowledgment — TCP optimization option |
| **Banner** | Text string a service sends to identify itself |
| **CVE** | Common Vulnerabilities and Exposures — standardized vulnerability ID |
| **Npcap** | Windows packet capture/injection driver |
| **Half-open scan** | SYN scan that doesn't complete the TCP handshake |
| **Fingerprinting** | Identifying an OS or service from network behavior |
| **Path traversal** | Using `../` to access files outside intended directory |

---

## Project Files Quick Reference

| File | What It Does |
|------|-------------|
| `common/packet.py` | Builds and parses raw Ethernet/IPv4/TCP packets |
| `common/npcap.py` | Talks to the Npcap driver for packet I/O |
| `attacker/scanner.py` | SYN port scanner (Phase 1) |
| `attacker/banner.py` | Banner grabber (Phase 2) |
| `attacker/fingerprint.py` | OS fingerprinting engine (Phase 3) |
| `attacker/exploits/ftp_anon.py` | FTP anonymous login exploit |
| `attacker/exploits/ssh_bruteforce.py` | SSH weak credential exploit |
| `attacker/exploits/http_traversal.py` | HTTP path traversal exploit |
| `attacker/main.py` | Orchestrator — runs all phases |
| `defense/detector.py` | Port scan detection algorithm |
| `defense/main.py` | Defense entry point |
| `victim/ftp_server.py` | Simulated vulnerable FTP server |
| `victim/http_server.py` | Simulated vulnerable HTTP server |

---

## References

1. **Fyodor (Gordon Lyon)**, "Remote OS detection via TCP/IP Stack Fingerprinting," *Phrack Magazine*, Issue 54, 1998 — The foundational paper on OS fingerprinting that our heuristic engine is based on.

2. **RFC 793** — Transmission Control Protocol — The official specification of TCP, including the three-way handshake, flags (SYN, ACK, RST), and checksum computation that our scanner implements.

3. **RFC 791** — Internet Protocol — The IPv4 specification defining the header fields (TTL, protocol, checksum) that our packet builder constructs.

4. **RFC 1071** — Computing the Internet Checksum — The algorithm we implement in `packet.py` for both IPv4 and TCP checksums.

5. **RFC 4987** — TCP SYN Flooding Attacks and Common Mitigations — Background on SYN-based attacks and defenses like SYN cookies, relevant to our defense module.

6. **Nmap Reference Guide — OS Detection** (https://nmap.org/book/man-os-detection.html) — Explains how Nmap uses up to 16 probes and a signature database for OS detection. Our fingerprinter uses a simplified version of the same principles.

7. **MITRE ATT&CK T1046** — Network Service Scanning (https://attack.mitre.org/techniques/T1046/) — The formal classification of port scanning as a reconnaissance technique.

8. **MITRE ATT&CK T1078** — Valid Accounts (https://attack.mitre.org/techniques/T1078/) — Covers default/weak credential exploitation, which our SSH and FTP exploits demonstrate.

9. **OWASP Top 10 — A01:2021 Broken Access Control** (https://owasp.org/Top10/A01_2021-Broken_Access_Control/) — Covers path traversal vulnerabilities like the one our HTTP exploit demonstrates.

10. **CVE-2017-0144 (EternalBlue)** — A real-world example of the port-scan → service-identification → exploit chain, where scanning port 445 led to SMB exploitation. Referenced as context for why port scanning matters.

11. **CVE-2021-41773 (Apache 2.4.49 Path Traversal)** — A real-world path traversal vulnerability in Apache, directly relevant to our HTTP traversal exploit.

12. **Npcap Documentation** (https://npcap.com/) — The Windows packet capture library our project uses for raw packet I/O.

13. **Python `socket` module documentation** (https://docs.python.org/3/library/socket.html) — Standard library used for banner grabbing and exploit connections.

14. **Paramiko documentation** (https://www.paramiko.org/) — The SSH library used in our SSH credential exploit module.
