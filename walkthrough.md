# Walkthrough — Repository Structure

This document lists what is in the repository and what each file contains.
It is a map, not a design or usage guide — see the files themselves (linked
below) for content.

## Root

| Path | Contents |
|------|----------|
| [design_report.md](design_report.md) | Formal submission-ready design report: overview, topology, timing diagrams, packet/frame structure, implementation plan, expected outcome, defense idea, appendix/references. |
| [project_explanation.md](project_explanation.md) | Plain-language explanation of the whole project (analogies, diagrams, glossary, references) — supplementary study material, same subject as `design_report.md` for a less formal audience. |
| [HOW_TO_RUN.md](HOW_TO_RUN.md) | Step-by-step command guide to install dependencies and run the attacker/victim/defense components. |
| [walkthrough.md](walkthrough.md) | This file. |
| [CSE406ProjectJan2026.pdf](CSE406ProjectJan2026.pdf) | Original project/assignment specification handed out for the course. |
| `.gitignore` | Git ignore rules for the whole repository. |

## Imp/ — implementation

```
Imp/
├── README.md              # Short project overview, safety boundary, directory listing
├── REPORT_NOTES.md         # What data to observe during experiments + what tools to use
├── requirements.txt        # Python dependencies (paramiko)
├── common/
│   ├── packet.py           # Ethernet/IPv4/TCP frame construction, parsing, checksums
│   └── npcap.py            # ctypes bindings to the Npcap driver (raw packet I/O)
├── attacker/
│   ├── main.py             # Orchestrator — chains scan → banner → fingerprint → exploits
│   ├── scanner.py          # Phase 1: TCP SYN port scanner
│   ├── banner.py           # Phase 2: service banner grabbing
│   ├── fingerprint.py      # Phase 3: OS fingerprinting heuristic
│   └── exploits/
│       ├── ftp_anon.py         # Exploit: FTP anonymous login
│       ├── ssh_bruteforce.py   # Exploit: SSH weak-credential login (uses paramiko)
│       └── http_traversal.py   # Exploit: HTTP path traversal
├── defense/
│   ├── main.py             # Defense entry point (CLI)
│   └── detector.py         # Sliding-window SYN-scan detector + optional firewall block
├── victim/
│   ├── ftp_server.py       # Simulated vulnerable FTP server (anonymous login enabled)
│   ├── http_server.py      # Simulated vulnerable HTTP server (no traversal protection)
│   └── README.md           # Setup instructions for the victim demo services
├── tools/
│   └── list_npcap_adapters.py  # Lists Npcap-visible network adapters
└── tests/
    └── test_packet.py      # Unit tests for packet construction/parsing
```
