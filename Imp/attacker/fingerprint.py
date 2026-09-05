"""
Transparent heuristic OS fingerprinting.

This is intentionally a small, self-authored signature engine, not a copy of
a database from a scanning product. It uses packet characteristics collected
by our parser.

Important: exact OS versions cannot always be distinguished from a few TCP
fields. The engine therefore reports a confidence and an honest version
family rather than pretending the result is exact.
"""

from common.packet import parse_tcp_options


def fingerprint(info):
    options = parse_tcp_options(info.get("options", b""))

    names = [x[0] for x in options]
    mss = next((x[1] for x in options if x[0] == "MSS"), None)
    wscale = next((x[1] for x in options if x[0] == "WSCALE"), None)

    ttl = info.get("ttl", 0)
    window = info.get("window", 0)

    scores = {
        "Windows family": 0,
        "Linux family": 0,
        "Other/unknown": 0,
    }

    reasons = []

    # TTL is a weak feature: it is affected by network hops.
    if ttl >= 110:
        scores["Windows family"] += 2
        reasons.append(f"high initial-TTL candidate ({ttl})")
    elif ttl <= 70:
        scores["Linux family"] += 2
        reasons.append(f"low initial-TTL candidate ({ttl})")

    # Common SYN/ACK window characteristics. These are heuristics only.
    if window in (64240, 65535):
        scores["Windows family"] += 1
        reasons.append(f"Windows-like TCP window ({window})")

    if window in (64240, 29200, 65160, 65535):
        scores["Linux family"] += 1
        reasons.append(f"common Unix/Linux TCP window ({window})")

    if mss == 1460:
        reasons.append("MSS=1460")

    if "SACK_PERMITTED" in names:
        reasons.append("SACK permitted")

    if "TIMESTAMP" in names:
        reasons.append("TCP timestamp present")

    if wscale is not None:
        reasons.append(f"window scale={wscale}")

    # Resolve the intentionally overlapping weak heuristics by TTL first.
    if ttl >= 110:
        likely = "Windows family"
        confidence = min(95, 65 + scores["Windows family"] * 8)
        version = "Windows 10/11 family (exact release not reliably distinguishable)"
    elif ttl <= 70:
        likely = "Linux family"
        confidence = min(95, 65 + scores["Linux family"] * 8)
        version = "Linux kernel family (exact distribution/version not reliably distinguishable)"
    else:
        likely = "Unknown"
        confidence = 30
        version = "Unknown"

    return {
        "os": likely,
        "confidence": confidence,
        "version": version,
        "ttl": ttl,
        "window": window,
        "options": options,
        "reasons": reasons,
    }
