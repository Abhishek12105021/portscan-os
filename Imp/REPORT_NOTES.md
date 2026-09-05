# Demo / Report Notes

## Data to observe during experimentation

Attacker side:
- scan command line and output (open/closed/no-response per port)
- fingerprint output (predicted OS family, confidence, evidence fields)
- packet count and timing per probe

Victim side:
- Wireshark capture (SYN, SYN/ACK, RST)
- defense detector console output (alert time, source IP, SYN/port counts)
- Windows Firewall rule state (only when testing `--block` mitigation)

Per-packet fields to record:
- IPv4: TTL, checksum
- TCP: flags, window size, options (MSS, window scale, SACK, timestamp), checksum

## Tools to use

- Custom scanner / fingerprinter / defense scripts in `Imp/attacker` and `Imp/defense` (the implementation under test)
- Wireshark — capture and screenshot evidence only, not part of the attack
- `netstat -an` on the victim — ground truth for actual open/closed ports
- Windows Firewall / `netsh advfirewall` — verify `--block` mitigation and clean up rules

## Fingerprint limitations

The OS result is a heuristic. A few TCP fields do not uniquely identify a
modern OS release. State this explicitly. Improve accuracy by collecting
known-good captures from each permitted test OS and extending the signature
rules based on your own measurements.
