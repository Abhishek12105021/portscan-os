"""
Transparent, probabilistic OS fingerprinting.

This is a self-authored signature engine, not a copy of a scanning product's
database. It analyses the passive characteristics of a single SYN/ACK (or RST)
returned by the target and produces a *probability distribution* over operating
system families, together with the evidence behind each score.

Why probabilistic rather than a single hard answer:
    No small set of TCP/IP fields uniquely identifies a modern OS release.
    Real fingerprinters (nmap, p0f, Xprobe2) therefore weigh several features
    "in concert" and report a best guess with a confidence, not a certainty.
    We do the same, honestly.

Features analysed (grounded in the project's rsc/ references):
    - Initial TTL, normalised to the nearest standard value (32/64/128/255)
      so intervening router hops do not corrupt the reading.
    - TCP window size (SYN/ACK advertised window).
    - IPv4 Don't-Fragment (DF) bit.
    - TCP options actually present: MSS value, window scale, SACK-permitted,
      timestamp.
    - The *order* of the TCP options, which is one of the strongest single
      discriminators between stacks (e.g. Windows vs Linux lay options out
      differently).

Each OS family accumulates weighted evidence; the totals are normalised into
percentages so the caller sees a ranked distribution, not just one label.
"""

import re

from common.packet import parse_tcp_options, TCP_RST, TCP_SYN, TCP_ACK, TCP_ECE, TCP_CWR


# ---------------------------------------------------------------------------
# Reference data (from rsc/Default_TTL_Values.jpg and the SANS / Hackercool
# fingerprinting papers). These are documented, well-known defaults — not a
# lifted signature database.
# ---------------------------------------------------------------------------

# Standard initial TTL values. Observed TTL is rounded UP to the nearest of
# these, because TTL only ever decreases in transit (one per hop).
STANDARD_TTLS = (32, 64, 128, 255)

# The OS families we score. "Network device" catches routers/appliances that
# commonly ship a 255 initial TTL.
OS_CLASSES = (
    "Windows",
    "Linux",
    "macOS / BSD",
    "Network device",
)

# Typical SYN/ACK advertised windows. A window may appear for more than one
# family; overlaps are intentional and resolved by the other features.
WINDOW_SIGNATURES = {
    "Windows": {8192, 16384, 64240, 65535},
    "Linux": {5840, 14600, 29200, 64240, 65160, 65535},
    "macOS / BSD": {65535, 33304, 33456},
    "Network device": {4128, 4096, 8192},
}

# Common SYN/ACK TCP option orderings, expressed as the ordered sequence of
# option *kinds* (NOP/EOL padding removed). These are broad, defensible
# families rather than exact per-build fingerprints.
#   Windows 10/11 : MSS, NOP, WSCALE, SACK_PERMITTED  -> M,W,S
#   Linux (modern): MSS, SACK_PERMITTED, TIMESTAMP, NOP, WSCALE -> M,S,T,W
#   macOS/BSD     : MSS, NOP, WSCALE, NOP, NOP, TIMESTAMP, SACK_PERMITTED
OPTION_ORDER_SIGNATURES = {
    "Windows": [
        ("MSS", "WSCALE", "SACK_PERMITTED"),
        ("MSS", "NOP", "WSCALE", "NOP", "NOP", "SACK_PERMITTED"),
        ("MSS", "NOP", "WSCALE", "SACK_PERMITTED", "TIMESTAMP"),
        ("MSS", "WSCALE", "SACK_PERMITTED", "TIMESTAMP"),
    ],
    "Linux": [
        ("MSS", "SACK_PERMITTED", "TIMESTAMP", "WSCALE"),
        ("MSS", "SACK_PERMITTED", "TIMESTAMP", "NOP", "WSCALE"),
    ],
    "macOS / BSD": [
        ("MSS", "NOP", "WSCALE", "NOP", "NOP", "TIMESTAMP", "SACK_PERMITTED"),
        ("MSS", "WSCALE", "TIMESTAMP", "SACK_PERMITTED"),
    ],
}

# Human-readable version hints per family, chosen honestly (family, not build).
VERSION_HINTS = {
    "Windows": "Windows 10 / 11 / Server family "
               "(exact release not reliably distinguishable)",
    "Linux": "Linux kernel family "
             "(exact distribution/version not reliably distinguishable)",
    "macOS / BSD": "macOS or a BSD-derived stack",
    "Network device": "Router / firewall / embedded network appliance",
}


# ---------------------------------------------------------------------------
# Cross-layer Application Banner Signatures (Idea 7.1)
# ---------------------------------------------------------------------------
# High-confidence application banner signatures (RFC 7230, RFC 4253) that
# corroborate lower-layer TCP/IP stack heuristics.
BANNER_SIGNATURES = [
    # (os_class, [ (pattern, weight, desc, optional_tier_hint), ... ])
    (
        "Windows",
        [
            (r"Microsoft-IIS\/10\b", 4.5, "Microsoft-IIS/10.0 web server", "Windows 10 / 11 / Server 2016+"),
            (r"Microsoft-IIS\/(?:7\.[50]|8\.[05])\b", 4.5, "Microsoft-IIS 7.x/8.x web server", "Windows 7 / 8 / Vista / Server 2008-2012"),
            (r"Microsoft-IIS\b", 4.0, "Microsoft-IIS web server", "Windows 10 / 11 / Server 2016+"),
            (r"Microsoft-HTTPAPI", 4.0, "Microsoft HTTPAPI stack", None),
            (r"Microsoft FTP Service", 4.0, "Microsoft Windows FTP Service", None),
            (r"Microsoft ESMTP MAIL Service", 4.0, "Microsoft Exchange / Windows SMTP", None),
            (r"OpenSSH_for_Windows", 4.0, "Microsoft Windows OpenSSH port", "Windows 10 / 11 / Server 2016+"),
            (r"\bWindows\b", 3.0, "Explicit Windows platform indicator", None),
            (r"\bWin32\b", 3.0, "Win32 platform indicator", None),
            (r"\bWin64\b", 3.0, "Win64 platform indicator", None),
        ],
    ),
    (
        "Linux",
        [
            (r"\bUbuntu\b", 4.0, "Ubuntu Linux distribution", "Linux modern kernel (3.x / 4.x / 5.x+)"),
            (r"\bDebian\b", 4.0, "Debian GNU/Linux distribution", "Linux modern kernel (3.x / 4.x / 5.x+)"),
            (r"\bCentOS\b", 4.0, "CentOS Linux distribution", "Linux modern kernel (3.x / 4.x / 5.x+)"),
            (r"\bRed Hat\b", 4.0, "Red Hat Enterprise Linux", "Linux modern kernel (3.x / 4.x / 5.x+)"),
            (r"\bRHEL\b", 4.0, "RHEL Linux distribution", "Linux modern kernel (3.x / 4.x / 5.x+)"),
            (r"\bFedora\b", 4.0, "Fedora Linux distribution", "Linux modern kernel (3.x / 4.x / 5.x+)"),
            (r"\bAlpine Linux\b", 4.0, "Alpine Linux distribution", "Linux modern kernel (3.x / 4.x / 5.x+)"),
            (r"\bArch Linux\b", 4.0, "Arch Linux distribution", "Linux modern kernel (3.x / 4.x / 5.x+)"),
            (r"\bSUSE\b", 4.0, "SUSE Linux distribution", "Linux modern kernel (3.x / 4.x / 5.x+)"),
            (r"\bvsftpd\b", 3.0, "vsftpd (Very Secure FTP Daemon - Linux standard)", "Linux modern kernel (3.x / 4.x / 5.x+)"),
            (r"\bProFTPD\b", 2.5, "ProFTPD Unix daemon", None),
            (r"Apache\/(?:\S+)\s+\((?:Unix|Linux)\)", 3.0, "Apache HTTP Server on Unix/Linux", None),
            (r"\bdropbear\b", 2.5, "Dropbear lightweight SSH (embedded Linux)", None),
        ],
    ),
    (
        "macOS / BSD",
        [
            (r"\bDarwin\b", 4.0, "Apple Darwin kernel banner", "macOS / modern BSD"),
            (r"\bFreeBSD\b", 4.0, "FreeBSD operating system banner", "macOS / modern BSD"),
            (r"\bOpenBSD\b", 4.0, "OpenBSD operating system banner", "macOS / modern BSD"),
            (r"\bNetBSD\b", 4.0, "NetBSD operating system banner", "macOS / modern BSD"),
            (r"\bVLC(?: Web Sharing| for (?:iOS|macOS))\b", 3.0, "VLC iOS / macOS Web Sharing service", "macOS / modern BSD"),
            (r"\bApple\b", 3.5, "Apple Darwin platform indicator", "macOS / modern BSD"),
        ],
    ),
    (
        "Network device",
        [
            (r"\bCisco\b", 4.5, "Cisco IOS / network appliance", "Router / firewall / embedded"),
            (r"\bMikroTik\b", 4.0, "MikroTik RouterOS", "Router / firewall / embedded"),
            (r"\bRouterOS\b", 4.0, "MikroTik RouterOS", "Router / firewall / embedded"),
            (r"\bOpenWrt\b", 3.5, "OpenWrt embedded router Linux", "Router / firewall / embedded"),
            (r"\bZyXEL\b", 4.0, "ZyXEL network appliance", "Router / firewall / embedded"),
            (r"\bHuawei\b", 4.0, "Huawei network appliance", "Router / firewall / embedded"),
            (r"\bFortinet\b", 4.0, "Fortinet firewall appliance", "Router / firewall / embedded"),
            (r"\bJuniper\b", 4.0, "Juniper Junos appliance", "Router / firewall / embedded"),
        ],
    ),
]


def _check_http_header_order(raw_bytes):
    """Check RFC 7230 HTTP response header ordering quirks."""
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None
    server_idx = text.lower().find("\r\nserver:")
    if server_idx == -1:
        server_idx = text.lower().find("\nserver:")
    date_idx = text.lower().find("\r\ndate:")
    if date_idx == -1:
        date_idx = text.lower().find("\ndate:")

    if server_idx != -1 and date_idx != -1:
        if server_idx < date_idx:
            return ("Windows", 0.5, "HTTP response header 'Server' precedes 'Date' (common in IIS/embedded)")
        else:
            return ("Linux", 0.5, "HTTP response header 'Date' precedes 'Server' (RFC standard Unix layout)")
    return None


def _evaluate_banners(banners):
    """Evaluate application banners (Idea 7.1) for cross-layer OS evidence.

    Returns:
        scores: dict of cls -> float
        reasons: list of str
        evidence_items: list of dict
        tier_hint: (os_class, tier_name) or None
    """
    scores = {cls: 0.0 for cls in OS_CLASSES}
    reasons = []
    evidence_items = []
    tier_hint = None

    if not banners:
        return scores, reasons, evidence_items, tier_hint

    for b in banners:
        if isinstance(b, str):
            port = 0
            service = "Service"
            version_str = b
            raw_bytes = b.encode("utf-8")
        elif isinstance(b, dict):
            port = b.get("port", 0)
            service = b.get("service", "Service")
            version_str = b.get("version", "")
            raw_bytes = b.get("raw_banner", b"")
        else:
            continue

        if not version_str or version_str.startswith("(connect failed") or version_str == "(no banner)":
            continue

        search_text = f"{version_str}\n{raw_bytes.decode('utf-8', errors='replace')}"

        # Match against signature table
        for os_class, patterns in BANNER_SIGNATURES:
            for pattern, weight, desc, opt_tier in patterns:
                m = re.search(pattern, search_text, re.IGNORECASE)
                if m:
                    scores[os_class] += weight
                    matched_str = m.group(0)
                    reason_msg = (
                        f"Cross-layer banner on port {port} ({service}) matches {os_class} "
                        f"signature '{matched_str}' ({desc})"
                    )
                    reasons.append(reason_msg)
                    evidence_items.append({
                        "port": port,
                        "service": service,
                        "os": os_class,
                        "matched": matched_str,
                        "weight": weight,
                        "description": desc,
                    })
                    if opt_tier and tier_hint is None:
                        tier_hint = (os_class, opt_tier)
                    break

        # Check HTTP header order if raw HTTP response available
        if service == "HTTP" and raw_bytes:
            header_quirk = _check_http_header_order(raw_bytes)
            if header_quirk:
                os_cls, weight, desc = header_quirk
                scores[os_cls] += weight
                reasons.append(f"Port {port} (HTTP): {desc}")
                evidence_items.append({
                    "port": port,
                    "service": "HTTP",
                    "os": os_cls,
                    "matched": "Header Order",
                    "weight": weight,
                    "description": desc,
                })

    return scores, reasons, evidence_items, tier_hint


# ---------------------------------------------------------------------------
# Within-family version TIERS.
#
# Individual OS *releases* (e.g. Windows 7 vs 8 vs 10 vs 11) are NOT reliably
# separable from passive TCP/IP fields: modern Windows releases share TTL 128,
# DF set, the same M,W,S option layout, and overlapping windows. We therefore
# report the coarse tiers the fields CAN support, each with its own score, and
# surface a range when tiers tie. This is deliberately honest, not a claim of
# exact-build detection.
#
# Each tier is a list of (feature_predicate, weight, human_reason). The
# predicate receives a small feature dict.
# ---------------------------------------------------------------------------

def _tier(pred, weight, reason):
    return (pred, weight, reason)


VERSION_TIERS = {
    "Windows": {
        "Windows 9x / 2000 (legacy)": [
            _tier(lambda f: f["initial_ttl"] == 32, 3.0,
                  "initial TTL 32 is a legacy Windows 9x-era signature"),
            _tier(lambda f: not f["has_ts"], 0.2, "no TCP timestamp"),
        ],
        "Windows 7 / 8 / Vista / Server 2008-2012": [
            _tier(lambda f: f["initial_ttl"] == 128, 1.5,
                  "initial TTL 128 (Windows)"),
            _tier(lambda f: f["window"] in (8192, 8760, 16384), 2.0,
                  "advertised window typical of Win7/8-era default (8192)"),
            _tier(lambda f: f["wscale"] in (0, 2, 8), 0.5,
                  "window scale in Win7/8 range"),
        ],
        "Windows 10 / 11 / Server 2016+": [
            _tier(lambda f: f["initial_ttl"] == 128, 1.5,
                  "initial TTL 128 (Windows)"),
            _tier(lambda f: f["window"] in (64240, 65535), 2.0,
                  "advertised window 64240/65535 typical of Win10/11"),
            _tier(lambda f: f["wscale"] == 8, 1.0,
                  "window scale 8 typical of modern Windows"),
            _tier(lambda f: f["mss"] == 1460, 0.3, "MSS 1460"),
        ],
    },
    "Linux": {
        "Linux 2.4 / 2.6 (older kernel)": [
            _tier(lambda f: f["window"] in (5840, 5792), 2.5,
                  "small window (5840) typical of older 2.4/2.6 kernels"),
            _tier(lambda f: f["wscale"] in (0, 2), 0.5,
                  "low window scale of older kernels"),
        ],
        "Linux modern kernel (3.x / 4.x / 5.x+)": [
            _tier(lambda f: f["window"] in (29200, 64240, 65160, 14600), 2.5,
                  "window typical of modern Linux kernels"),
            _tier(lambda f: f["wscale"] in (7, 8, 10), 1.0,
                  "window scale of modern Linux kernels"),
            _tier(lambda f: f["has_ts"], 0.5, "TCP timestamp present"),
        ],
    },
    "macOS / BSD": {
        "macOS / modern BSD": [
            _tier(lambda f: f["initial_ttl"] == 64, 1.5, "initial TTL 64"),
            _tier(lambda f: f["has_ts"], 1.0, "TCP timestamp present"),
        ],
    },
    "Network device": {
        "Router / firewall / embedded": [
            _tier(lambda f: f["initial_ttl"] == 255, 2.0, "initial TTL 255"),
        ],
    },
}


def refine_version(family, feats, tier_hint=None):
    """Score the sub-tiers within a family and return a ranked list.

    Returns (label, [(tier_name, percent), ...]) where `label` is the best
    tier, or a joined range if the top tiers tie closely. Everything is
    honest: if features cannot separate tiers, they come back near-equal.
    """
    tiers = VERSION_TIERS.get(family)
    if not tiers:
        return VERSION_HINTS.get(family, "Unknown"), []

    scores = {}
    tier_reasons = {}
    for name, rules in tiers.items():
        s = 0.0
        rs = []
        for pred, weight, reason in rules:
            try:
                if pred(feats):
                    s += weight
                    rs.append(reason)
            except (KeyError, TypeError):
                continue
        if tier_hint and tier_hint == name:
            s += 3.0
            rs.append(f"banner evidence strongly correlates with {name}")
        scores[name] = s
        tier_reasons[name] = rs

    total = sum(scores.values())
    if total <= 0:
        # No tier evidence: present all tiers as equally possible.
        n = len(scores)
        ranked = [(name, round(100 / n)) for name in scores]
        return " or ".join(scores.keys()), ranked

    ranked = sorted(
        ((name, round(100 * s / total)) for name, s in scores.items()),
        key=lambda kv: kv[1],
        reverse=True,
    )

    # If the top two tiers are within 12 points, report both as a range.
    if len(ranked) > 1 and ranked[0][1] - ranked[1][1] < 12:
        label = f"{ranked[0][0]}  or  {ranked[1][0]}"
    else:
        label = ranked[0][0]

    return label, ranked


# ---------------------------------------------------------------------------
# Feature helpers
# ---------------------------------------------------------------------------

def normalise_ttl(ttl):
    """Round an observed TTL up to the nearest standard initial TTL.

    Returns (initial_ttl, estimated_hops). If the observed TTL already exceeds
    the largest standard value we cannot normalise, so we return it unchanged
    with 0 hops.
    """
    for standard in STANDARD_TTLS:
        if ttl <= standard:
            return standard, standard - ttl
    return ttl, 0


def _option_kind_sequence(options):
    """Ordered list of option-kind names with NOP/EOL padding stripped."""
    sequence = []
    for entry in options:
        name = entry[0]
        if name in ("NOP", "EOL"):
            continue
        sequence.append(name)
    return sequence


def _orders_match(observed, reference):
    """True if the observed option order matches a reference order, ignoring
    NOP/EOL padding in the reference too (so both are compared on substance)."""
    ref = [k for k in reference if k not in ("NOP", "EOL")]
    return observed == ref


# ---------------------------------------------------------------------------
# IP ID Sequence Generation Analysis (Idea 2)
# ---------------------------------------------------------------------------

def classify_ipid_sequence(ip_ids, df=True):
    """
    Classify a sequence of 16-bit IPv4 Identification (IP ID) values across multiple probes.

    Pattern Archetypes:
      - ALL_ZERO: All packets have IP ID == 0 (RFC 6864, Linux standard when DF=1)
      - CONSTANT_NONZERO: All packets have identical non-zero ID (embedded/switches)
      - STRICT_INCREMENTAL: Small consecutive step deltas (1 <= delta <= 10, classic Windows/legacy)
      - BROKEN_INCREMENTAL: Moderate positive steps (1 <= delta <= 1000, Windows with background traffic)
      - RANDOM_POSITIVE: Wide pseudorandom variation or jumps (modern Windows per-socket pools or Darwin BSD)

    Returns:
        dict with:
            'class': str ('ALL_ZERO', 'STRICT_INCREMENTAL', 'BROKEN_INCREMENTAL',
                          'RANDOM_POSITIVE', 'CONSTANT_NONZERO', 'SINGLE_SAMPLE', or 'UNKNOWN')
            'deltas': list of int
            'scores': dict of {os_class: float}
            'reason': str or None
            'description': str
    """
    if not ip_ids:
        return {
            "class": "UNKNOWN",
            "deltas": [],
            "scores": {},
            "reason": None,
            "description": "No IP ID observations",
        }

    # Ensure all values are 16-bit unsigned ints
    clean_ids = [int(x) & 0xFFFF for x in ip_ids]

    if len(clean_ids) == 1:
        val = clean_ids[0]
        if df and val == 0:
            return {
                "class": "ALL_ZERO",
                "deltas": [],
                "scores": {"Linux": 1.5},
                "reason": "IP ID is 0 with DF set (RFC 6864, characteristic of Linux)",
                "description": "Single sample IP ID=0 (RFC 6864)",
            }
        elif df and val > 0:
            return {
                "class": "RANDOM_POSITIVE",
                "deltas": [],
                "scores": {"Windows": 0.8, "macOS / BSD": 0.4},
                "reason": f"IP ID is non-zero ({val}) with DF set (characteristic of Windows/BSD)",
                "description": f"Single sample non-zero ({val})",
            }
        else:
            return {
                "class": "SINGLE_SAMPLE",
                "deltas": [],
                "scores": {},
                "reason": f"IP ID is {val} (DF bit clear)",
                "description": f"Single sample ({val})",
            }

    # Calculate 16-bit modular deltas: (id[i] - id[i-1]) mod 65536
    deltas = [(clean_ids[i] - clean_ids[i - 1]) % 65536 for i in range(1, len(clean_ids))]

    # Pattern 1: Constant Zero (Linux RFC 6864)
    if all(x == 0 for x in clean_ids):
        if df:
            scores = {"Linux": 2.5}
            reason = f"IP ID sequence is constant zero {clean_ids} with DF set (RFC 6864, strong Linux indicator)"
        else:
            scores = {"Linux": 1.5}
            reason = f"IP ID sequence is constant zero {clean_ids}"
        return {
            "class": "ALL_ZERO",
            "deltas": deltas,
            "scores": scores,
            "reason": reason,
            "description": "Constant Zero (RFC 6864)",
        }

    # Pattern 2: Constant Non-zero (Embedded / Network Device)
    if all(x == clean_ids[0] for x in clean_ids) and clean_ids[0] > 0:
        return {
            "class": "CONSTANT_NONZERO",
            "deltas": deltas,
            "scores": {"Network device": 2.5, "macOS / BSD": 0.5},
            "reason": f"IP ID sequence is constant non-zero ({clean_ids[0]}) (common in network appliances)",
            "description": f"Constant Non-zero ({clean_ids[0]})",
        }

    # Pattern 3: Strictly Incremental (1 <= delta <= 10)
    if all(1 <= d <= 10 for d in deltas):
        avg_d = sum(deltas) / len(deltas)
        scores = {"Windows": 2.5, "Network device": 1.0, "macOS / BSD": 0.5}
        reason = f"IP ID sequence is strictly incremental (deltas: {deltas}, avg: {avg_d:.1f}) (Windows sequential/global counter)"
        return {
            "class": "STRICT_INCREMENTAL",
            "deltas": deltas,
            "scores": scores,
            "reason": reason,
            "description": f"Strictly Incremental (avg delta: {avg_d:.1f})",
        }

    # Pattern 4: Broken / Drifted Incremental (1 <= delta <= 1000)
    if all(1 <= d <= 1000 for d in deltas):
        avg_d = sum(deltas) / len(deltas)
        scores = {"Windows": 2.0, "Network device": 1.0, "macOS / BSD": 0.5}
        reason = f"IP ID sequence is incremental with traffic drift (deltas: {deltas}, avg: {avg_d:.1f}) (Windows counter under background traffic)"
        return {
            "class": "BROKEN_INCREMENTAL",
            "deltas": deltas,
            "scores": scores,
            "reason": reason,
            "description": f"Incremental with Drift (avg delta: {avg_d:.1f})",
        }

    # Pattern 5: Randomized / Large Jumps (Darwin BSD / Modern Windows per-socket pool)
    scores = {"Windows": 1.5, "macOS / BSD": 1.5}
    reason = f"IP ID sequence is randomized non-zero (deltas: {deltas}) (characteristic of modern Windows per-socket pool or Darwin/BSD)"
    return {
        "class": "RANDOM_POSITIVE",
        "deltas": deltas,
        "scores": scores,
        "reason": reason,
        "description": "Randomized Non-zero",
    }


# ---------------------------------------------------------------------------
# TCP Timestamp Clock Frequency & System Uptime Analysis (Idea 3)
# ---------------------------------------------------------------------------

def _format_uptime(seconds: float) -> str:
    """Format seconds into human-readable days, hours, minutes."""
    sec = int(seconds)
    days = sec // 86400
    hours = (sec % 86400) // 3600
    minutes = (sec % 3600) // 60
    if days > 0:
        return f"{days} day(s), {hours} hour(s), {minutes} min(s)"
    elif hours > 0:
        return f"{hours} hour(s), {minutes} min(s)"
    else:
        return f"{minutes} min(s)"


def analyze_tcp_timestamps(ts_samples):
    """
    Analyze TCP Timestamp (RFC 7323 / RFC 1323) values across timed probes.

    Parameters:
        ts_samples: list of (recv_time, tsval) tuples.
                    recv_time is in seconds (e.g. time.monotonic()),
                    tsval is a 32-bit unsigned int.

    Returns:
        dict with:
            'class': str ('HZ_1000', 'HZ_250', 'HZ_100', 'HZ_10', 'RANDOM_OFFSET', 'SINGLE_SAMPLE', 'NONE')
            'rate': float or None (estimated clock rate in Hz)
            'uptime_seconds': float or None
            'uptime_str': str or None
            'scores': dict of {os_class: float}
            'reason': str or None
            'description': str
    """
    if not ts_samples:
        return {
            "class": "NONE",
            "rate": None,
            "uptime_seconds": None,
            "uptime_str": None,
            "scores": {},
            "reason": None,
            "description": "No timestamp samples observed",
        }

    # Clean and filter samples
    samples = [(float(t), int(val) & 0xFFFFFFFF) for t, val in ts_samples if val is not None]

    if len(samples) < 2:
        val = samples[0][1]
        return {
            "class": "SINGLE_SAMPLE",
            "rate": None,
            "uptime_seconds": None,
            "uptime_str": None,
            "scores": {},
            "reason": f"TCP timestamp TSval={val} observed (single probe, frequency unmeasured)",
            "description": f"Single sample TSval={val}",
        }

    # Calculate intervals
    rates = []
    has_large_jump = False

    for i in range(1, len(samples)):
        dt = samples[i][0] - samples[i - 1][0]
        if dt <= 0:
            continue
        # 32-bit modular delta
        d_ts = (samples[i][1] - samples[i - 1][1]) % (2**32)

        # Check for RFC 7323 cryptographic randomization or backward jump
        # On randomized stacks (like Apple Darwin), jumps are typically > 10,000,000
        if d_ts > 10000000 or (d_ts / dt) > 100000:
            has_large_jump = True
            break
        rates.append(d_ts / dt)

    if has_large_jump or not rates:
        # Apple Darwin / iOS 15+ / iPadOS 17+ / modern BSD randomized offset
        return {
            "class": "RANDOM_OFFSET",
            "rate": None,
            "uptime_seconds": None,
            "uptime_str": None,
            "scores": {"macOS / BSD": 2.5},
            "reason": "TCP timestamp uses randomized initial offsets (RFC 7323, characteristic of Apple Darwin / iOS / macOS)",
            "description": "Randomized Initial Offset (RFC 7323 Darwin PRNG)",
        }

    avg_rate = sum(rates) / len(rates)
    latest_tsval = samples[-1][1]

    # Classify clock frequency
    if 700 <= avg_rate <= 1400:
        cls_name = "HZ_1000"
        scores = {"Windows": 2.0, "Linux": 1.0}
        desc = f"~1000 Hz ({avg_rate:.1f} Hz)"
        reason = f"TCP timestamp clock frequency ~{avg_rate:.1f} Hz matches modern Windows 10/11 (1000 Hz / 1ms tick) or Linux low-latency"
    elif 180 <= avg_rate <= 350:
        cls_name = "HZ_250"
        scores = {"Linux": 2.5}
        desc = f"~250 Hz ({avg_rate:.1f} Hz)"
        reason = f"TCP timestamp clock frequency ~{avg_rate:.1f} Hz matches standard Linux (CONFIG_HZ=250)"
    elif 70 <= avg_rate <= 150:
        cls_name = "HZ_100"
        scores = {"Linux": 1.5, "Windows": 1.0}
        desc = f"~100 Hz ({avg_rate:.1f} Hz)"
        reason = f"TCP timestamp clock frequency ~{avg_rate:.1f} Hz matches 100 Hz timer (traditional Linux / classic Windows)"
    elif 5 <= avg_rate <= 25:
        cls_name = "HZ_10"
        scores = {"Windows": 2.0}
        desc = f"~10 Hz ({avg_rate:.1f} Hz)"
        reason = f"TCP timestamp clock frequency ~{avg_rate:.1f} Hz matches legacy Windows 10 Hz timer"
    else:
        cls_name = "HZ_OTHER"
        scores = {}
        desc = f"{avg_rate:.1f} Hz"
        reason = f"TCP timestamp clock frequency ~{avg_rate:.1f} Hz"

    # Uptime estimation
    uptime_sec = latest_tsval / avg_rate if avg_rate > 0 else 0
    # Sanity check: if uptime is under 365 days, format it; if astronomical, it might have an offset
    if 0 < uptime_sec < (365 * 86400):
        uptime_str = _format_uptime(uptime_sec)
    else:
        uptime_str = f"> 1 year or offset ({int(uptime_sec // 86400)} days)"

    return {
        "class": cls_name,
        "rate": avg_rate,
        "uptime_seconds": uptime_sec,
        "uptime_str": uptime_str,
        "scores": scores,
        "reason": reason,
        "description": desc,
    }


# ---------------------------------------------------------------------------
# RFC 3168 Explicit Congestion Notification (ECN) Probe Analysis (Idea 4)
# ---------------------------------------------------------------------------

def evaluate_ecn(ecn_info):
    """
    Evaluate server response to an active RFC 3168 ECN probe (SYN with ECE and CWR set).

    Parameters:
        ecn_info (dict or None): Dictionary describing the ECN probe outcome,
            containing:
              - 'tested': bool
              - 'flags': int (response TCP flags)
              - 'dropped': bool (optional)
              - 'reason': str (optional)
            or None if no probe was performed.

    Returns:
        dict with:
            'status': str ('ECN_SUPPORTED', 'ECN_IGNORED', 'ECN_DROPPED',
                           'ECN_REJECTED_RST', or 'NOT_TESTED')
            'flags': int or None
            'ece_reflected': bool
            'cwr_reflected': bool
            'scores': dict of {os_class: float}
            'reason': str or None
            'description': str
    """
    if not ecn_info or not ecn_info.get("tested"):
        return {
            "status": "NOT_TESTED",
            "flags": None,
            "ece_reflected": False,
            "cwr_reflected": False,
            "scores": {},
            "reason": None,
            "description": "ECN probe not performed (no open port or disabled)",
        }

    if ecn_info.get("dropped"):
        return {
            "status": "ECN_DROPPED",
            "flags": None,
            "ece_reflected": False,
            "cwr_reflected": False,
            "scores": {"Network device": 2.0},
            "reason": "ECN probe dropped without response (typical of strict firewall or legacy network filter)",
            "description": "ECN probe dropped",
        }

    flags = ecn_info.get("flags", 0)
    ece = bool(flags & TCP_ECE)
    cwr = bool(flags & TCP_CWR)

    if flags & TCP_RST:
        return {
            "status": "ECN_REJECTED_RST",
            "flags": flags,
            "ece_reflected": ece,
            "cwr_reflected": cwr,
            "scores": {"Network device": 1.5, "Linux": 0.5},
            "reason": f"ECN probe rejected with TCP RST (flags=0x{flags:02x})",
            "description": "ECN probe rejected (RST)",
        }

    # Standard RFC 3168 negotiation:
    # Server indicates ECN support by returning SYN/ACK with ECE set and CWR cleared.
    if (flags & TCP_SYN) and (flags & TCP_ACK):
        if ece and not cwr:
            return {
                "status": "ECN_SUPPORTED",
                "flags": flags,
                "ece_reflected": True,
                "cwr_reflected": False,
                "scores": {"Linux": 2.0, "macOS / BSD": 2.0},
                "reason": "RFC 3168 ECN negotiation supported (ECE reflected, CWR=0 in SYN/ACK) -- characteristic of Linux & Apple Darwin",
                "description": "ECN Supported (ECE reflected, Flags=0x52)",
            }
        elif not ece and not cwr:
            return {
                "status": "ECN_IGNORED",
                "flags": flags,
                "ece_reflected": False,
                "cwr_reflected": False,
                "scores": {"Windows": 2.0},
                "reason": "RFC 3168 ECN flags ignored (ECE=0, CWR=0 in SYN/ACK) -- characteristic of default Windows TCP/IP stack",
                "description": "ECN Ignored (Flags=0x12, Default Windows Stack)",
            }
        else:
            return {
                "status": "ECN_UNUSUAL",
                "flags": flags,
                "ece_reflected": ece,
                "cwr_reflected": cwr,
                "scores": {},
                "reason": f"ECN probe elicited unusual TCP flag combination: 0x{flags:02x}",
                "description": f"ECN Unusual Flags (0x{flags:02x})",
            }

    return {
        "status": "ECN_OTHER",
        "flags": flags,
        "ece_reflected": ece,
        "cwr_reflected": cwr,
        "scores": {},
        "reason": f"ECN probe returned unexpected response (flags=0x{flags:02x})",
        "description": f"Flags=0x{flags:02x}",
    }


# ---------------------------------------------------------------------------
# Ambiguous / Invalid TCP Flags Probe Analysis (Idea 5)
# ---------------------------------------------------------------------------

def evaluate_invalid_flags(invalid_flags_info):
    """
    Evaluate server response to ambiguous or invalid TCP flag combinations (Idea 5: Rule-Breaker Test).
    Standard RFC 793 / 9293 specification dictates that TCP listening sockets (open ports)
    silently drop incoming packets with illegal flag combinations (such as SYN+FIN, NULL, or Xmas)
    that lack an ACK bit.

    Windows TCP/IP stacks famously violate this specification by generating an RST/ACK (Flags=0x14)
    response to invalid probes even on OPEN listening ports.

    Linux / Unix stacks adhere strictly to RFC 793 and silently drop invalid packets on open ports.
    On closed ports, Linux returns RST/ACK, whereas Apple Darwin (iOS/iPadOS/macOS) drops SYN+FIN
    on both open and closed ports without responding.

    Parameters:
        invalid_flags_info (dict or None): Dictionary with probe results:
            - 'tested': bool
            - 'probe': str (e.g. 'SYN+FIN')
            - 'open_port_responded': bool
            - 'open_port_flags': int or None
            - 'open_port_ttl': int or None
            - 'closed_port_responded': bool (optional)
            - 'closed_port_flags': int or None (optional)

    Returns:
        dict with:
            'status': str ('WINDOWS_RST_ON_INVALID', 'UNIX_SILENT_DROP', 'DARWIN_TOTAL_DROP', or 'NOT_TESTED')
            'probe': str or None
            'scores': dict of {os_class: float}
            'reason': str or None
            'description': str
    """
    if not invalid_flags_info or not invalid_flags_info.get("tested"):
        return {
            "status": "NOT_TESTED",
            "probe": None,
            "scores": {},
            "reason": None,
            "description": "Invalid flags probe not performed",
        }

    probe = invalid_flags_info.get("probe", "SYN+FIN")
    open_resp = invalid_flags_info.get("open_port_responded", False)
    open_flags = invalid_flags_info.get("open_port_flags")
    closed_resp = invalid_flags_info.get("closed_port_responded")

    # Archetype 1: Windows Non-RFC Compliant RST on Open Port
    if open_resp and (open_flags is not None) and (open_flags & TCP_RST):
        return {
            "status": "WINDOWS_RST_ON_INVALID",
            "probe": probe,
            "scores": {"Windows": 2.5},
            "reason": f"Ambiguous/invalid TCP flags ({probe}) on open port elicited RST response (Flags=0x{open_flags:02x}) -- characteristic of Windows stack (RFC 793 rule-breaker)",
            "description": f"RST on Open Port (Flags=0x{open_flags:02x}, Windows Rule-Breaker)",
        }

    # Archetype 2: Unix / Linux / Darwin Silent Drop on Open Port
    if not open_resp:
        if closed_resp is False:
            # Darwin BSD behavior: drops SYN+FIN on both open and closed ports!
            return {
                "status": "DARWIN_TOTAL_DROP",
                "probe": probe,
                "scores": {"macOS / BSD": 2.5, "Linux": 0.5},
                "reason": f"Ambiguous/invalid TCP flags ({probe}) silently dropped on both open and closed ports -- characteristic of Apple Darwin / BSD packet filtering",
                "description": f"Silently Dropped (Open & Closed, Apple Darwin / BSD)",
            }
        elif closed_resp is True:
            # Linux behavior: drops on open, responds with RST on closed
            return {
                "status": "LINUX_STANDARD_DROP",
                "probe": probe,
                "scores": {"Linux": 2.0, "macOS / BSD": 1.0},
                "reason": f"Ambiguous/invalid TCP flags ({probe}) silently dropped on open port but RST on closed port -- RFC 793 compliant Linux/Unix behavior",
                "description": f"Silently Dropped on Open Port (RFC 793 Linux/Unix)",
            }
        else:
            return {
                "status": "UNIX_SILENT_DROP",
                "probe": probe,
                "scores": {"Linux": 1.5, "macOS / BSD": 1.5},
                "reason": f"Ambiguous/invalid TCP flags ({probe}) on open port silently dropped without response -- RFC 793 compliant Unix behavior (Linux / BSD / macOS)",
                "description": f"Silently Dropped on Open Port (RFC 793 Unix Standard)",
            }

    return {
        "status": "INVALID_OTHER",
        "probe": probe,
        "scores": {},
        "reason": f"Ambiguous/invalid TCP flags ({probe}) returned unexpected response (Flags=0x{open_flags:02x})",
        "description": f"Unexpected Response (Flags=0x{open_flags:02x})",
    }


# ---------------------------------------------------------------------------
# ICMP & UDP Probing Battery Analysis (Idea 6)
# ---------------------------------------------------------------------------

def evaluate_icmp_udp(icmp_udp_info):
    """
    Evaluate server response to ICMP Echo and UDP Port Unreachable probes (Idea 6: ICMP/UDP Battery).

    Signatures evaluated:
      - ICMP Echo Code reflection: Windows resets non-zero request code (e.g. Code 9) to 0.
        Linux and Apple Darwin reflect Code 9 verbatim.
      - ICMP Echo DF bit: Apple Darwin / iOS sets DF=1 on Echo replies (RFC 6864).
        Windows and Linux leave DF=0 on Echo replies.
      - ICMP Echo TTL: Windows=128, Linux=64, Darwin=64.
      - UDP U1 Quoted Length: Windows quotes extensive payload (>28B, typically 328B).
        Apple Darwin quotes RFC 792 minimum 28 bytes (IP hdr + 8B UDP).
        Linux/Android filters/drops unsolicited UDP probes on mobile devices.

    Parameters:
        icmp_udp_info (dict or None)

    Returns:
        dict with:
            'status': str ('WINDOWS_ICMP_UDP', 'DARWIN_ICMP_UDP', 'LINUX_ICMP_UDP', 'NOT_TESTED')
            'scores': dict of {os_class: float}
            'reason': str or None
            'description': str
    """
    if not icmp_udp_info or not icmp_udp_info.get("tested"):
        return {
            "status": "NOT_TESTED",
            "scores": {},
            "reason": None,
            "description": "ICMP/UDP battery not performed",
            "echo_responded": False,
            "echo_code": None,
            "echo_ttl": None,
            "echo_df": None,
            "udp_responded": False,
            "udp_quoted_len": None,
        }

    echo_resp = icmp_udp_info.get("echo_responded", False)
    echo_code = icmp_udp_info.get("echo_code")
    echo_ttl = icmp_udp_info.get("echo_ttl")
    echo_df = icmp_udp_info.get("echo_df")
    udp_resp = icmp_udp_info.get("udp_responded", False)
    udp_quoted_len = icmp_udp_info.get("udp_quoted_len")
    udp_ttl = icmp_udp_info.get("udp_ttl")

    scores = {}

    # 1. Check Windows Signature:
    # Code 9 was sent; if reply has Code=0 with TTL=128 -> Windows
    # And/or UDP port unreachable with large quoted length (>28 bytes)
    is_windows = False
    if echo_resp and (echo_code == 0) and (echo_ttl is not None and echo_ttl >= 100):
        is_windows = True
    elif udp_resp and (udp_quoted_len is not None and udp_quoted_len > 28) and (udp_ttl is not None and udp_ttl >= 100):
        is_windows = True

    if is_windows:
        quote_text = f", U1 quotes {udp_quoted_len}B" if udp_resp and udp_quoted_len else ""
        scores["Windows"] = 3.0
        return {
            "status": "WINDOWS_ICMP_UDP",
            "scores": scores,
            "reason": f"ICMP Echo Reply normalized Code=0 (Code 9 probe) with TTL={echo_ttl or udp_ttl}{quote_text} -- characteristic of Windows stack",
            "description": f"Windows Stack (Code=0 normalized, TTL={echo_ttl or udp_ttl}{quote_text})",
            "echo_responded": echo_resp,
            "echo_code": echo_code,
            "echo_ttl": echo_ttl,
            "echo_df": echo_df,
            "udp_responded": udp_resp,
            "udp_quoted_len": udp_quoted_len,
        }

    # 2. Check Darwin BSD Signature:
    # DF=1 on ICMP Echo Reply with Code=9 reflection, or UDP U1 exactly 28 bytes quoted
    is_darwin = False
    if echo_resp and echo_df and (echo_ttl is not None and echo_ttl <= 64):
        is_darwin = True
    elif udp_resp and (udp_quoted_len == 28) and (udp_ttl is not None and udp_ttl <= 64):
        is_darwin = True

    if is_darwin:
        quote_text = f", U1 quotes {udp_quoted_len}B (RFC 792 min)" if udp_resp and udp_quoted_len else ""
        scores["macOS / BSD"] = 3.0
        return {
            "status": "DARWIN_ICMP_UDP",
            "scores": scores,
            "reason": f"ICMP Echo Reply has DF=1 and reflected Code={echo_code} (TTL={echo_ttl or udp_ttl}){quote_text} -- characteristic of Apple Darwin / BSD",
            "description": f"Apple Darwin / BSD (DF=1 on ICMP, Code={echo_code} reflected{quote_text})",
            "echo_responded": echo_resp,
            "echo_code": echo_code,
            "echo_ttl": echo_ttl,
            "echo_df": echo_df,
            "udp_responded": udp_resp,
            "udp_quoted_len": udp_quoted_len,
        }

    # 3. Check Linux Signature:
    # Code=9 reflected, DF=False, TTL=64, UDP dropped/filtered
    if echo_resp and (echo_code == 9) and (echo_df is False) and (echo_ttl is not None and echo_ttl <= 64):
        scores["Linux"] = 2.5
        return {
            "status": "LINUX_ICMP_UDP",
            "scores": scores,
            "reason": f"ICMP Echo Reply reflected Code=9 with DF=0 and TTL={echo_ttl}; UDP probe silently filtered -- characteristic of Linux kernel (Android stack)",
            "description": f"Linux / Android (Code=9 reflected, DF=0, UDP filtered)",
            "echo_responded": echo_resp,
            "echo_code": echo_code,
            "echo_ttl": echo_ttl,
            "echo_df": echo_df,
            "udp_responded": udp_resp,
            "udp_quoted_len": udp_quoted_len,
        }

    # Fallback if partial echo response
    if echo_resp:
        if echo_ttl is not None and echo_ttl >= 100:
            scores["Windows"] = 2.0
            desc = f"ICMP Echo TTL={echo_ttl} (Windows)"
            reason = f"ICMP Echo Reply TTL={echo_ttl} indicates Windows initial TTL 128"
        elif echo_df:
            scores["macOS / BSD"] = 2.0
            desc = f"ICMP Echo TTL={echo_ttl}, DF=1 (Darwin)"
            reason = f"ICMP Echo Reply DF=1 indicates Apple Darwin"
        else:
            scores["Linux"] = 1.5
            scores["macOS / BSD"] = 0.5
            desc = f"ICMP Echo TTL={echo_ttl}, DF=0 (Unix)"
            reason = f"ICMP Echo Reply TTL={echo_ttl} with DF=0 indicates Unix/Linux"

        return {
            "status": "ICMP_GENERIC",
            "scores": scores,
            "reason": reason,
            "description": desc,
            "echo_responded": echo_resp,
            "echo_code": echo_code,
            "echo_ttl": echo_ttl,
            "echo_df": echo_df,
            "udp_responded": udp_resp,
            "udp_quoted_len": udp_quoted_len,
        }

    return {
        "status": "ICMP_UDP_FILTERED",
        "scores": {"Network device": 1.5},
        "reason": "ICMP and UDP probes were completely filtered by host or network firewall",
        "description": "ICMP/UDP Filtered",
        "echo_responded": False,
        "echo_code": None,
        "echo_ttl": None,
        "echo_df": None,
        "udp_responded": False,
        "udp_quoted_len": None,
    }


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

def fingerprint(info, banners=None, ip_ids=None, ts_samples=None, ecn_info=None, invalid_flags_info=None, icmp_udp_info=None):
    """Return a probabilistic OS fingerprint for one parsed SYN/ACK (or RST)
    with optional cross-layer application banner correlation (Idea 7.1),
    multi-probe IP ID sequence tracking (Idea 2), TCP timestamp clock/uptime
    analysis (Idea 3), active RFC 3168 ECN probe evaluation (Idea 4),
    ambiguous/invalid TCP flag response analysis (Idea 5),
    and ICMP/UDP battery probe evaluation (Idea 6).

    The returned dict keeps the keys the previous engine exposed
    (os, confidence, version, ttl, window, options, reasons) so existing
    callers keep working, and adds:
        distribution : list of (os_class, percent) sorted high -> low
        initial_ttl  : normalised initial TTL
        hops         : estimated router hops to the target
        df           : Don't-Fragment bit observed
        ip_id        : IPv4 identification field of primary candidate
        ip_id_sequence : list of IP IDs observed across scan probes
        ip_id_class  : sequence generation classification (ALL_ZERO, STRICT_INCREMENTAL, etc.)
        ip_id_deltas : consecutive modular deltas
        ts_rate      : estimated TCP timestamp clock rate in Hz
        ts_class     : clock rate archetype (HZ_1000, HZ_250, RANDOM_OFFSET, etc.)
        uptime       : estimated human-readable system uptime
        uptime_seconds : raw estimated uptime in seconds
        ecn_status   : RFC 3168 ECN support classification (ECN_SUPPORTED, ECN_IGNORED, etc.)
        ecn_flags    : response flags on ECN probe
        ecn_reflected: whether ECE bit was reflected
        ecn_description: summary description of ECN probe result
        invalid_flags_status : invalid flags classification (WINDOWS_RST_ON_INVALID, etc.)
        invalid_flags_probe  : probe type used (e.g. 'SYN+FIN')
        invalid_flags_description : summary description of invalid flags response
        icmp_udp_status : ICMP/UDP classification (WINDOWS_ICMP_UDP, DARWIN_ICMP_UDP, etc.)
        icmp_udp_description : summary description of ICMP/UDP battery response
        probe_type   : 'SYN/ACK', 'RST', or 'ICMP'
        banners      : input application banners
        banner_evidence : list of correlated banner signatures
    """
    if banners is None:
        banners = info.get("banners", [])
    if isinstance(banners, dict):
        banners = [banners]

    if ip_ids is None:
        ip_ids = info.get("ip_ids")

    if ts_samples is None:
        ts_samples = info.get("ts_samples")

    if ecn_info is None:
        ecn_info = info.get("ecn_info", info.get("ecn"))

    if invalid_flags_info is None:
        invalid_flags_info = info.get("invalid_flags_info", info.get("invalid_flags"))

    if icmp_udp_info is None:
        icmp_udp_info = info.get("icmp_udp_info", info.get("icmp_udp"))

    options = parse_tcp_options(info.get("options", b""))
    names = [x[0] for x in options]
    mss = next((x[1] for x in options if x[0] == "MSS"), None)
    wscale = next((x[1] for x in options if x[0] == "WSCALE"), None)
    has_sack = "SACK_PERMITTED" in names
    has_ts = "TIMESTAMP" in names

    ttl = info.get("ttl", 0)
    window = info.get("window", 0)
    df = bool(info.get("df", False))
    ip_id = info.get("ip_id", info.get("identification", None))
    flags = info.get("flags", 0)
    is_rst = bool(flags & TCP_RST)

    initial_ttl, hops = normalise_ttl(ttl)
    option_order = _option_kind_sequence(options)

    scores = {cls: 0.0 for cls in OS_CLASSES}
    reasons = []

    if is_rst:
        reasons.append("Probe response: TCP RST (Closed-Port Fingerprinting)")
        if window == 0:
            reasons.append("TCP window is 0 (standard closed-port RST response)")
        else:
            reasons.append(f"TCP window is {window}")

        if initial_ttl == 128:
            scores["Windows"] += 4.5
            reasons.append(f"RST with initial TTL {initial_ttl} and window {window} "
                           f"strongly indicates Windows stack")
        elif initial_ttl == 64:
            scores["Linux"] += 2.5
            scores["macOS / BSD"] += 2.0
            reasons.append(f"RST with initial TTL {initial_ttl} indicates "
                           f"Linux/macOS/BSD stack")
        elif initial_ttl == 255:
            scores["Network device"] += 4.0
            reasons.append(f"RST with initial TTL {initial_ttl} indicates "
                           f"network device or firewall")
    else:
        # --- Feature 1: initial TTL (strong, but shared 64<->many, 128<->Windows).
        if ttl <= 0:
            reasons.append("no TTL reading (no SYN/ACK captured)")
        elif initial_ttl == 128:
            scores["Windows"] += 4.0
            reasons.append(f"initial TTL {initial_ttl} (~{ttl} observed, "
                           f"{hops} hop(s)) is characteristic of Windows")
        elif initial_ttl == 64:
            scores["Linux"] += 2.0
            scores["macOS / BSD"] += 2.0
            reasons.append(f"initial TTL {initial_ttl} (~{ttl} observed, "
                           f"{hops} hop(s)) is typical of Linux/macOS/BSD")
        elif initial_ttl == 255:
            scores["Network device"] += 3.0
            scores["macOS / BSD"] += 0.5
            reasons.append(f"initial TTL {initial_ttl} often indicates a network "
                           f"device / Unix-style stack")
        elif initial_ttl == 32:
            scores["Windows"] += 1.0
            reasons.append(f"initial TTL {initial_ttl} suggests a legacy Windows "
                           f"9x-era stack")

        # --- Feature 2: advertised TCP window.
        for cls, windows in WINDOW_SIGNATURES.items():
            if window in windows:
                scores[cls] += 1.5
        matched_windows = [c for c, w in WINDOW_SIGNATURES.items() if window in w]
        if matched_windows:
            reasons.append(f"TCP window {window} matches "
                           f"{', '.join(matched_windows)}")
        else:
            reasons.append(f"TCP window {window} (no strong family match)")

        # --- Feature 3: Don't-Fragment bit. Modern Windows and Linux set DF on
        # SYN/ACK; its absence leans (weakly) toward older/embedded stacks.
        if df:
            scores["Windows"] += 0.5
            scores["Linux"] += 0.5
            scores["macOS / BSD"] += 0.5
            reasons.append("Don't-Fragment (DF) bit set - modern TCP stack")
        else:
            scores["Network device"] += 0.5
            reasons.append("Don't-Fragment (DF) bit clear")

        # --- Feature 4: TCP option ORDER (strong discriminator).
        order_matched = False
        for cls, orders in OPTION_ORDER_SIGNATURES.items():
            if any(_orders_match(option_order, ref) for ref in orders):
                scores[cls] += 3.0
                reasons.append(f"TCP option order {option_order} matches "
                               f"a known {cls} layout")
                order_matched = True
        if option_order and not order_matched:
            reasons.append(f"TCP option order {option_order} "
                           f"(no exact family layout match)")

        # --- Feature 5: presence of specific options (weak corroboration).
        if has_ts:
            # Windows historically omits the TCP timestamp on SYN/ACK by default;
            # Linux/macOS/BSD include it.
            scores["Linux"] += 1.0
            scores["macOS / BSD"] += 1.0
            reasons.append("TCP timestamp present (leans Unix-like)")
        else:
            scores["Windows"] += 0.5
            reasons.append("TCP timestamp absent (leans Windows)")

        if has_sack:
            reasons.append("SACK permitted")
        if mss is not None:
            reasons.append(f"MSS={mss}")
        if wscale is not None:
            reasons.append(f"window scale={wscale}")

    # --- Feature: IPv4 Identification (RFC 6864 & Multi-probe Tracking - Idea 2)
    # Linux kernels zero out the IP ID field when DF is set on atomic datagrams.
    # Windows and BSD stacks traditionally generate non-zero or incremental IDs.
    ip_ids_list = list(ip_ids) if ip_ids is not None else ([ip_id] if ip_id is not None else [])
    ipid_res = classify_ipid_sequence(ip_ids_list, df=df)
    for cls, s in ipid_res["scores"].items():
        scores[cls] += s
    if ipid_res["reason"]:
        reasons.append(ipid_res["reason"])

    # --- Feature: Cross-layer Application Banner Correlation (Idea 7.1)
    banner_scores, banner_reasons, banner_evidence, banner_tier_hint = _evaluate_banners(banners)
    for cls, s in banner_scores.items():
        scores[cls] += s
    reasons.extend(banner_reasons)

    # --- Feature: TCP Timestamp Clock Frequency & Uptime Analysis (Idea 3)
    ts_analysis = analyze_tcp_timestamps(ts_samples)
    for cls, s in ts_analysis["scores"].items():
        scores[cls] += s
    if ts_analysis["reason"]:
        reasons.append(ts_analysis["reason"])

    # --- Feature: Explicit Congestion Notification (RFC 3168 - Idea 4)
    ecn_res = evaluate_ecn(ecn_info)
    for cls, s in ecn_res["scores"].items():
        scores[cls] += s
    if ecn_res["reason"]:
        reasons.append(ecn_res["reason"])

    # --- Feature: Ambiguous / Invalid TCP Flags Probe (Idea 5)
    inv_res = evaluate_invalid_flags(invalid_flags_info)
    for cls, s in inv_res["scores"].items():
        scores[cls] += s
    if inv_res["reason"]:
        reasons.append(inv_res["reason"])

    # --- Feature: ICMP & UDP Probing Battery (Idea 6)
    icmp_res = evaluate_icmp_udp(icmp_udp_info)
    for cls, s in icmp_res["scores"].items():
        scores[cls] += s
    if icmp_res["reason"]:
        reasons.append(icmp_res["reason"])

    # --- Turn raw scores into a probability distribution. -------------------
    total = sum(scores.values())
    if total <= 0:
        distribution = [(cls, 0) for cls in OS_CLASSES]
        best_os = "Unknown"
        confidence = 20
        version = "Unknown (insufficient distinguishing features)"
        version_tiers = []
    else:
        distribution = sorted(
            ((cls, round(100 * s / total)) for cls, s in scores.items()),
            key=lambda kv: kv[1],
            reverse=True,
        )
        best_os, confidence = distribution[0]

        # A high percentage off a tiny evidence base is not real confidence.
        # Damp the reported confidence toward "uncertain" when few distinctive
        # features were actually observed (total weight is small).
        LOW_EVIDENCE = 4.0
        if total < LOW_EVIDENCE:
            confidence = round(confidence * total / LOW_EVIDENCE)
            reasons.append(
                f"limited distinguishing evidence "
                f"(weight {total:.1f}) - confidence reduced"
            )

        # If the top two families are effectively tied, be honest about it.
        if len(distribution) > 1 and distribution[0][1] - distribution[1][1] < 8:
            reasons.append(
                f"top candidates are close "
                f"({distribution[0][0]} {distribution[0][1]}% vs "
                f"{distribution[1][0]} {distribution[1][1]}%) - low certainty"
            )
        # Refine the winning family into a coarse-but-honest version tier.
        tier_hint = (
            banner_tier_hint[1]
            if (banner_tier_hint and banner_tier_hint[0] == best_os)
            else None
        )
        if is_rst:
            if tier_hint:
                version = f"{best_os} ({tier_hint} via cross-layer banner)"
            else:
                version = f"{best_os} family (closed-port RST; open port required for build-tiering)"
            version_tiers = []
        else:
            feats = {
                "initial_ttl": initial_ttl,
                "window": window,
                "wscale": wscale,
                "mss": mss,
                "has_ts": has_ts,
                "has_sack": has_sack,
                "df": df,
            }
            version, version_tiers = refine_version(best_os, feats, tier_hint=tier_hint)

        if confidence < 40:
            best_os = f"{best_os} (uncertain)"

    return {
        "os": best_os,
        "confidence": confidence,
        "version": version,
        "version_tiers": version_tiers,
        "distribution": distribution,
        "ttl": ttl,
        "initial_ttl": initial_ttl,
        "hops": hops,
        "window": window,
        "df": df,
        "ip_id": ip_id,
        "ip_id_sequence": ip_ids_list,
        "ip_id_class": ipid_res["class"],
        "ip_id_deltas": ipid_res["deltas"],
        "ts_rate": ts_analysis["rate"],
        "ts_class": ts_analysis["class"],
        "uptime": ts_analysis["uptime_str"],
        "uptime_seconds": ts_analysis["uptime_seconds"],
        "ecn_status": ecn_res["status"],
        "ecn_flags": ecn_res["flags"],
        "ecn_reflected": ecn_res["ece_reflected"],
        "ecn_description": ecn_res["description"],
        "invalid_flags_status": inv_res["status"],
        "invalid_flags_probe": inv_res["probe"],
        "invalid_flags_description": inv_res["description"],
        "icmp_udp_status": icmp_res["status"],
        "icmp_udp_description": icmp_res["description"],
        "icmp_udp_info": icmp_res,
        "probe_type": info.get("probe_type", "RST" if is_rst else "SYN/ACK"),
        "options": options,
        "banners": banners,
        "banner_evidence": banner_evidence,
        "reasons": reasons,
    }
