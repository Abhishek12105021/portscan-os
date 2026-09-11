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

from common.packet import parse_tcp_options, TCP_RST, TCP_SYN, TCP_ACK


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


def refine_version(family, feats):
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
# Main engine
# ---------------------------------------------------------------------------

def fingerprint(info):
    """Return a probabilistic OS fingerprint for one parsed SYN/ACK (or RST).

    The returned dict keeps the keys the previous engine exposed
    (os, confidence, version, ttl, window, options, reasons) so existing
    callers keep working, and adds:
        distribution : list of (os_class, percent) sorted high -> low
        initial_ttl  : normalised initial TTL
        hops         : estimated router hops to the target
        df           : Don't-Fragment bit observed
        ip_id        : IPv4 identification field
        probe_type   : 'SYN/ACK' or 'RST'
    """
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

    # --- Feature: IPv4 Identification (RFC 6864 heuristic).
    # Linux kernels zero out the IP ID field when DF is set on atomic datagrams.
    # Windows and BSD stacks traditionally generate non-zero or incremental IDs.
    if ip_id is not None:
        if df and ip_id == 0:
            scores["Linux"] += 1.5
            reasons.append("IP ID is 0 with DF set (RFC 6864, characteristic of Linux)")
        elif df and ip_id > 0:
            scores["Windows"] += 0.8
            scores["macOS / BSD"] += 0.4
            reasons.append(f"IP ID is non-zero ({ip_id}) with DF set (characteristic of Windows/BSD)")

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
        if is_rst:
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
            version, version_tiers = refine_version(best_os, feats)

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
        "probe_type": "RST" if is_rst else "SYN/ACK",
        "options": options,
        "reasons": reasons,
    }
