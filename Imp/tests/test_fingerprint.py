"""Tests for the probabilistic OS fingerprint engine."""

import sys
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))                 # for `common` package
sys.path.insert(0, str(ROOT / "attacker"))    # for `fingerprint` module

from fingerprint import (
    fingerprint, normalise_ttl, classify_ipid_sequence, analyze_tcp_timestamps, evaluate_ecn, evaluate_invalid_flags, evaluate_icmp_udp
)
from common.packet import TCP_RST, TCP_SYN, TCP_ACK, TCP_ECE, TCP_CWR, TCP_FIN


def _synack(ttl, window, options, df=True):
    """Build a minimal parsed-SYN/ACK dict as the scanner would hand it in."""
    info = {"ttl": ttl, "window": window, "options": options, "df": df}
    return info


# Realistic option blobs (kind/length/value), padded to a multiple of 4 bytes.
WINDOWS_OPTS = (
    b"\x02\x04\x05\xb4"   # MSS 1460
    b"\x01\x03\x03\x08"   # NOP, WSCALE 8
    b"\x01\x01\x04\x02"   # NOP, NOP, SACK permitted
)
LINUX_OPTS = (
    b"\x02\x04\x05\xb4"   # MSS 1460
    b"\x04\x02"           # SACK permitted
    b"\x08\x0a\x00\x00\x00\x01\x00\x00\x00\x00"  # timestamp
    b"\x01\x03\x03\x07"   # NOP, WSCALE 7
)


class NormaliseTtlTests(unittest.TestCase):
    def test_windows_ttl_with_hops(self):
        self.assertEqual(normalise_ttl(122), (128, 6))

    def test_linux_ttl_direct(self):
        self.assertEqual(normalise_ttl(64), (64, 0))

    def test_network_device_ttl(self):
        self.assertEqual(normalise_ttl(250), (255, 5))


class FingerprintTests(unittest.TestCase):
    def test_windows_synack_scores_windows_top(self):
        fp = fingerprint(_synack(122, 64240, WINDOWS_OPTS))
        self.assertTrue(fp["os"].startswith("Windows"))
        self.assertEqual(fp["initial_ttl"], 128)
        self.assertEqual(fp["distribution"][0][0], "Windows")

    def test_linux_synack_scores_linux_top(self):
        fp = fingerprint(_synack(58, 29200, LINUX_OPTS))
        self.assertIn("Linux", fp["os"])
        self.assertEqual(fp["initial_ttl"], 64)
        self.assertEqual(fp["distribution"][0][0], "Linux")

    def test_distribution_sums_to_about_100(self):
        fp = fingerprint(_synack(122, 64240, WINDOWS_OPTS))
        self.assertAlmostEqual(sum(p for _, p in fp["distribution"]), 100, delta=2)

    def test_empty_features_low_confidence(self):
        fp = fingerprint(_synack(0, 0, b"", df=False))
        self.assertLessEqual(fp["confidence"], 60)

    def test_backward_compatible_keys(self):
        fp = fingerprint(_synack(122, 64240, WINDOWS_OPTS))
        for key in ("os", "confidence", "version", "ttl", "window",
                    "options", "reasons"):
            self.assertIn(key, fp)


class VersionTierTests(unittest.TestCase):
    def test_modern_windows_tier(self):
        # TTL128 + window 64240 + wscale 8 -> modern Win10/11 tier on top.
        fp = fingerprint(_synack(122, 64240, WINDOWS_OPTS))
        self.assertTrue(fp["version_tiers"])
        top_tier = fp["version_tiers"][0][0]
        self.assertIn("10 / 11", top_tier)

    def test_legacy_windows_tier(self):
        # TTL 32 (initial) -> legacy 9x tier should win.
        legacy_opts = b"\x02\x04\x05\xb4"  # just MSS
        fp = fingerprint(_synack(30, 8192, legacy_opts))
        self.assertTrue(fp["os"].startswith("Windows"))
        self.assertIn("legacy", fp["version_tiers"][0][0].lower())

    def test_tier_percentages_present(self):
        fp = fingerprint(_synack(58, 29200, LINUX_OPTS))
        self.assertTrue(all(isinstance(p, int) for _, p in fp["version_tiers"]))

    def test_modern_linux_tier(self):
        fp = fingerprint(_synack(58, 29200, LINUX_OPTS))
        self.assertIn("modern", fp["version_tiers"][0][0].lower())


class ClosedPortRstTests(unittest.TestCase):
    def test_windows_closed_port_rst(self):
        rst_info = {
            "ttl": 128,
            "window": 0,
            "options": b"",
            "df": False,
            "flags": TCP_RST,
        }
        fp = fingerprint(rst_info)
        self.assertTrue(fp["os"].startswith("Windows"))
        self.assertEqual(fp["initial_ttl"], 128)
        self.assertEqual(fp["window"], 0)
        self.assertEqual(fp["probe_type"], "RST")
        self.assertGreaterEqual(fp["confidence"], 70)
        self.assertTrue(any("Closed-Port" in r for r in fp["reasons"]))

    def test_linux_closed_port_rst(self):
        rst_info = {
            "ttl": 64,
            "window": 0,
            "options": b"",
            "df": True,
            "ip_id": 0,
            "flags": TCP_RST,
        }
        fp = fingerprint(rst_info)
        self.assertTrue(fp["os"].startswith("Linux"))
        self.assertEqual(fp["initial_ttl"], 64)
        self.assertEqual(fp["probe_type"], "RST")
        self.assertEqual(fp["distribution"][0][0], "Linux")


class IpIdHeuristicTests(unittest.TestCase):
    def test_linux_ip_id_zero_rfc6864(self):
        synack = _synack(64, 29200, LINUX_OPTS, df=True)
        synack["ip_id"] = 0
        synack["flags"] = TCP_SYN | TCP_ACK
        fp = fingerprint(synack)
        self.assertIn("Linux", fp["os"])
        self.assertTrue(any("RFC 6864" in r for r in fp["reasons"]))

    def test_windows_ip_id_nonzero(self):
        synack = _synack(128, 64240, WINDOWS_OPTS, df=True)
        synack["ip_id"] = 34521
        synack["flags"] = TCP_SYN | TCP_ACK
        fp = fingerprint(synack)
        self.assertTrue(fp["os"].startswith("Windows"))
        self.assertTrue(any("non-zero" in r for r in fp["reasons"]))


class BannerCrossLayerTests(unittest.TestCase):
    def test_iis_banner_boosts_windows(self):
        synack = _synack(128, 64240, WINDOWS_OPTS, df=True)
        banners = [
            {
                "port": 80,
                "service": "HTTP",
                "version": "Microsoft-IIS/10.0",
                "raw_banner": b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nDate: Sat, 12 Sep 2026 12:00:00 GMT\r\n\r\n",
                "success": True,
            }
        ]
        fp_no_banner = fingerprint(synack)
        fp_with_banner = fingerprint(synack, banners=banners)

        self.assertTrue(fp_with_banner["os"].startswith("Windows"))
        self.assertGreater(fp_with_banner["confidence"], fp_no_banner["confidence"])
        self.assertTrue(len(fp_with_banner["banner_evidence"]) > 0)
        self.assertTrue(any("Microsoft-IIS" in r for r in fp_with_banner["reasons"]))
        self.assertIn("10 / 11", fp_with_banner["version"])

    def test_ubuntu_ssh_banner_boosts_linux(self):
        synack = _synack(64, 29200, LINUX_OPTS, df=True)
        banners = [
            {
                "port": 22,
                "service": "SSH",
                "version": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
                "raw_banner": b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
                "success": True,
            }
        ]
        fp_no_banner = fingerprint(synack)
        fp_with_banner = fingerprint(synack, banners=banners)

        self.assertIn("Linux", fp_with_banner["os"])
        self.assertGreater(fp_with_banner["confidence"], fp_no_banner["confidence"])
        self.assertTrue(any("Ubuntu" in r for r in fp_with_banner["reasons"]))

    def test_vlc_ios_banner_boosts_macos_bsd(self):
        synack = _synack(64, 65535, b"", df=True)
        banners = [
            {
                "port": 80,
                "service": "HTTP",
                "version": "VLC Web Sharing",
                "raw_banner": b"HTTP/1.1 200 OK (VLC Web Sharing)\r\n\r\n",
                "success": True,
            }
        ]
        fp = fingerprint(synack, banners=banners)
        self.assertEqual(fp["distribution"][0][0], "macOS / BSD")
        self.assertTrue(any("VLC" in r for r in fp["reasons"]))

    def test_cisco_banner_boosts_network_device(self):
        synack = _synack(255, 4128, b"", df=False)
        banners = [
            {
                "port": 23,
                "service": "Telnet",
                "version": "User Access Verification Cisco IOS Software",
                "raw_banner": b"User Access Verification Cisco IOS Software\r\n",
                "success": True,
            }
        ]
        fp = fingerprint(synack, banners=banners)
        self.assertEqual(fp["distribution"][0][0], "Network device")
        self.assertTrue(any("Cisco" in r for r in fp["reasons"]))

    def test_http_header_ordering_quirk(self):
        synack = _synack(128, 64240, WINDOWS_OPTS, df=True)
        # Server before Date -> IIS/embedded layout
        banners = [
            {
                "port": 80,
                "service": "HTTP",
                "version": "CustomServer/1.0",
                "raw_banner": b"HTTP/1.0 200 OK\r\nServer: CustomServer/1.0\r\nDate: Sat, 12 Sep 2026\r\n\r\n",
                "success": True,
            }
        ]
        fp = fingerprint(synack, banners=banners)
        self.assertTrue(any("precedes 'Date'" in r for r in fp["reasons"]))


class IpIdSequenceTrackingTests(unittest.TestCase):
    def test_all_zero_sequence_boosts_linux(self):
        synack = _synack(64, 29200, LINUX_OPTS, df=True)
        synack["ip_ids"] = [0, 0, 0, 0]
        fp = fingerprint(synack)
        self.assertEqual(fp["ip_id_class"], "ALL_ZERO")
        self.assertEqual(fp["ip_id_sequence"], [0, 0, 0, 0])
        self.assertEqual(fp["distribution"][0][0], "Linux")
        self.assertTrue(any("constant zero" in r for r in fp["reasons"]))

    def test_strict_incremental_sequence_boosts_windows(self):
        synack = _synack(128, 64240, WINDOWS_OPTS, df=True)
        synack["ip_ids"] = [25714, 25715, 25716, 25718]
        fp = fingerprint(synack)
        self.assertEqual(fp["ip_id_class"], "STRICT_INCREMENTAL")
        self.assertEqual(fp["ip_id_deltas"], [1, 1, 2])
        self.assertEqual(fp["distribution"][0][0], "Windows")
        self.assertTrue(any("strictly incremental" in r for r in fp["reasons"]))

    def test_broken_incremental_sequence(self):
        res = classify_ipid_sequence([1000, 1050, 1200], df=True)
        self.assertEqual(res["class"], "BROKEN_INCREMENTAL")
        self.assertEqual(res["deltas"], [50, 150])
        self.assertGreater(res["scores"].get("Windows", 0), 0)

    def test_random_sequence_darwin_bsd(self):
        synack = _synack(64, 65535, b"", df=True)
        synack["ip_ids"] = [0, 54248]
        fp = fingerprint(synack)
        self.assertEqual(fp["ip_id_class"], "RANDOM_POSITIVE")
        self.assertEqual(fp["ip_id_deltas"], [54248])
        self.assertTrue(any("randomized" in r for r in fp["reasons"]))

    def test_constant_nonzero_sequence(self):
        res = classify_ipid_sequence([0x1234, 0x1234, 0x1234], df=False)
        self.assertEqual(res["class"], "CONSTANT_NONZERO")
        self.assertEqual(res["deltas"], [0, 0])
        self.assertGreater(res["scores"].get("Network device", 0), 0)


class TcpTimestampClockTests(unittest.TestCase):
    def test_1000hz_clock_rate_boosts_windows(self):
        # 1000 ticks in 1.0 second -> 1000 Hz
        ts_samples = [(100.0, 1000000), (101.0, 1001000)]
        res = analyze_tcp_timestamps(ts_samples)
        self.assertEqual(res["class"], "HZ_1000")
        self.assertAlmostEqual(res["rate"], 1000.0, delta=1.0)
        self.assertGreater(res["scores"].get("Windows", 0), 0)
        self.assertTrue(any("1000 Hz" in res["reason"] for _ in [1]))

        synack = _synack(128, 64240, WINDOWS_OPTS, df=True)
        synack["ts_samples"] = ts_samples
        fp = fingerprint(synack)
        self.assertEqual(fp["ts_class"], "HZ_1000")
        self.assertIsNotNone(fp["uptime"])

    def test_250hz_clock_rate_boosts_linux(self):
        # 250 ticks in 1.0 second -> 250 Hz
        ts_samples = [(200.0, 500000), (201.0, 500250)]
        res = analyze_tcp_timestamps(ts_samples)
        self.assertEqual(res["class"], "HZ_250")
        self.assertAlmostEqual(res["rate"], 250.0, delta=1.0)
        self.assertGreater(res["scores"].get("Linux", 0), 0)
        self.assertTrue(any("CONFIG_HZ=250" in res["reason"] for _ in [1]))

    def test_randomized_offsets_boosts_darwin(self):
        # Large jump (> 10,000,000) characteristic of iOS / Darwin RFC 7323
        ts_samples = [(300.0, 1287455648), (300.8, 781575066)]
        res = analyze_tcp_timestamps(ts_samples)
        self.assertEqual(res["class"], "RANDOM_OFFSET")
        self.assertGreater(res["scores"].get("macOS / BSD", 0), 0)
        self.assertTrue(any("randomized" in res["reason"] for _ in [1]))

        synack = _synack(64, 65535, b"", df=True)
        synack["ts_samples"] = ts_samples
        fp = fingerprint(synack)
        self.assertEqual(fp["ts_class"], "RANDOM_OFFSET")
        self.assertEqual(fp["distribution"][0][0], "macOS / BSD")

    def test_uptime_calculation_formatting(self):
        # Rate = 1000 Hz, TSval = 2667146 -> 2667.1s -> 44 min
        ts_samples = [(10.0, 2666146), (11.0, 2667146)]
        res = analyze_tcp_timestamps(ts_samples)
        self.assertEqual(res["class"], "HZ_1000")
        self.assertIn("44 min(s)", res["uptime_str"])

    def test_single_or_missing_timestamp_graceful_fallback(self):
        res_empty = analyze_tcp_timestamps([])
        self.assertEqual(res_empty["class"], "NONE")
        self.assertIsNone(res_empty["rate"])

        res_single = analyze_tcp_timestamps([(10.0, 50000)])
        self.assertEqual(res_single["class"], "SINGLE_SAMPLE")
        self.assertIsNone(res_single["rate"])


class EcnProbeFingerprintTests(unittest.TestCase):
    def test_ecn_supported_boosts_linux_darwin(self):
        # SYN/ACK with ECE=1, CWR=0 (flags=0x52)
        ecn_res = evaluate_ecn({"tested": True, "flags": TCP_SYN | TCP_ACK | TCP_ECE})
        self.assertEqual(ecn_res["status"], "ECN_SUPPORTED")
        self.assertTrue(ecn_res["ece_reflected"])
        self.assertFalse(ecn_res["cwr_reflected"])
        self.assertGreater(ecn_res["scores"].get("Linux", 0), 0)
        self.assertGreater(ecn_res["scores"].get("macOS / BSD", 0), 0)

        synack = _synack(64, 65535, LINUX_OPTS, df=True)
        synack["ecn_info"] = {"tested": True, "flags": 0x52}
        fp = fingerprint(synack)
        self.assertEqual(fp["ecn_status"], "ECN_SUPPORTED")
        self.assertTrue(fp["ecn_reflected"])
        self.assertTrue(any("RFC 3168 ECN negotiation supported" in r for r in fp["reasons"]))

    def test_ecn_ignored_boosts_windows(self):
        # Standard SYN/ACK with ECE=0, CWR=0 (flags=0x12)
        ecn_res = evaluate_ecn({"tested": True, "flags": TCP_SYN | TCP_ACK})
        self.assertEqual(ecn_res["status"], "ECN_IGNORED")
        self.assertFalse(ecn_res["ece_reflected"])
        self.assertGreater(ecn_res["scores"].get("Windows", 0), 0)

        synack = _synack(128, 64240, WINDOWS_OPTS, df=True)
        synack["ecn_info"] = {"tested": True, "flags": 0x12}
        fp = fingerprint(synack)
        self.assertEqual(fp["ecn_status"], "ECN_IGNORED")
        self.assertFalse(fp["ecn_reflected"])
        self.assertTrue(any("RFC 3168 ECN flags ignored" in r for r in fp["reasons"]))

    def test_ecn_dropped_boosts_network_device(self):
        ecn_res = evaluate_ecn({"tested": True, "dropped": True})
        self.assertEqual(ecn_res["status"], "ECN_DROPPED")
        self.assertGreater(ecn_res["scores"].get("Network device", 0), 0)

        synack = _synack(255, 4128, b"", df=False)
        synack["ecn_info"] = {"tested": True, "dropped": True}
        fp = fingerprint(synack)
        self.assertEqual(fp["ecn_status"], "ECN_DROPPED")
        self.assertTrue(any("ECN probe dropped" in r for r in fp["reasons"]))

    def test_ecn_rejected_rst(self):
        ecn_res = evaluate_ecn({"tested": True, "flags": TCP_RST | TCP_ACK})
        self.assertEqual(ecn_res["status"], "ECN_REJECTED_RST")
        self.assertGreater(ecn_res["scores"].get("Network device", 0), 0)

    def test_ecn_not_tested_graceful(self):
        ecn_res = evaluate_ecn(None)
        self.assertEqual(ecn_res["status"], "NOT_TESTED")
        self.assertEqual(ecn_res["scores"], {})

        synack = _synack(64, 5840, LINUX_OPTS, df=True)
        fp = fingerprint(synack)
        self.assertEqual(fp["ecn_status"], "NOT_TESTED")


class InvalidFlagsFingerprintTests(unittest.TestCase):
    def test_windows_rst_on_open_port(self):
        info = {
            "tested": True,
            "probe": "SYN+FIN",
            "open_port_responded": True,
            "open_port_flags": TCP_RST | TCP_ACK,
        }
        res = evaluate_invalid_flags(info)
        self.assertEqual(res["status"], "WINDOWS_RST_ON_INVALID")
        self.assertGreater(res["scores"].get("Windows", 0), 0)

        synack = _synack(128, 64240, WINDOWS_OPTS, df=True)
        synack["invalid_flags_info"] = info
        fp = fingerprint(synack)
        self.assertEqual(fp["invalid_flags_status"], "WINDOWS_RST_ON_INVALID")
        self.assertTrue(any("RFC 793 rule-breaker" in r for r in fp["reasons"]))

    def test_darwin_total_drop(self):
        info = {
            "tested": True,
            "probe": "SYN+FIN",
            "open_port_responded": False,
            "closed_port_responded": False,
        }
        res = evaluate_invalid_flags(info)
        self.assertEqual(res["status"], "DARWIN_TOTAL_DROP")
        self.assertGreater(res["scores"].get("macOS / BSD", 0), 0)

        synack = _synack(64, 65535, LINUX_OPTS, df=True)
        synack["invalid_flags_info"] = info
        fp = fingerprint(synack)
        self.assertEqual(fp["invalid_flags_status"], "DARWIN_TOTAL_DROP")
        self.assertTrue(any("Apple Darwin / BSD packet filtering" in r for r in fp["reasons"]))

    def test_linux_standard_drop(self):
        info = {
            "tested": True,
            "probe": "SYN+FIN",
            "open_port_responded": False,
            "closed_port_responded": True,
        }
        res = evaluate_invalid_flags(info)
        self.assertEqual(res["status"], "LINUX_STANDARD_DROP")
        self.assertGreater(res["scores"].get("Linux", 0), 0)

        synack = _synack(64, 29200, LINUX_OPTS, df=True)
        synack["invalid_flags_info"] = info
        fp = fingerprint(synack)
        self.assertEqual(fp["invalid_flags_status"], "LINUX_STANDARD_DROP")
        self.assertTrue(any("RFC 793 compliant Linux/Unix" in r for r in fp["reasons"]))

    def test_unix_silent_drop_fallback(self):
        info = {
            "tested": True,
            "probe": "SYN+FIN",
            "open_port_responded": False,
            "closed_port_responded": None,
        }
        res = evaluate_invalid_flags(info)
        self.assertEqual(res["status"], "UNIX_SILENT_DROP")
        self.assertGreater(res["scores"].get("Linux", 0), 0)
        self.assertGreater(res["scores"].get("macOS / BSD", 0), 0)

    def test_invalid_flags_not_tested_graceful(self):
        res = evaluate_invalid_flags(None)
        self.assertEqual(res["status"], "NOT_TESTED")
        self.assertEqual(res["scores"], {})

        synack = _synack(64, 5840, LINUX_OPTS, df=True)
        fp = fingerprint(synack)
        self.assertEqual(fp["invalid_flags_status"], "NOT_TESTED")


class IcmpUdpFingerprintTests(unittest.TestCase):
    def test_windows_icmp_code_zero_and_long_quote(self):
        info = {
            "tested": True,
            "echo_responded": True,
            "echo_code": 0,
            "echo_ttl": 128,
            "echo_df": False,
            "echo_ip_id": 25995,
            "udp_responded": True,
            "udp_icmp_type": 3,
            "udp_icmp_code": 3,
            "udp_ttl": 128,
            "udp_quoted_len": 328,
        }
        res = evaluate_icmp_udp(info)
        self.assertEqual(res["status"], "WINDOWS_ICMP_UDP")
        self.assertGreater(res["scores"].get("Windows", 0), 0)

        synack = _synack(128, 64240, WINDOWS_OPTS, df=True)
        synack["icmp_udp_info"] = info
        fp = fingerprint(synack)
        self.assertEqual(fp["icmp_udp_status"], "WINDOWS_ICMP_UDP")
        self.assertTrue(any("normalized Code=0" in r for r in fp["reasons"]))

    def test_darwin_icmp_df_and_minimal_quote(self):
        info = {
            "tested": True,
            "echo_responded": True,
            "echo_code": 9,
            "echo_ttl": 64,
            "echo_df": True,
            "echo_ip_id": 0,
            "udp_responded": True,
            "udp_icmp_type": 3,
            "udp_icmp_code": 3,
            "udp_ttl": 64,
            "udp_quoted_len": 28,
        }
        res = evaluate_icmp_udp(info)
        self.assertEqual(res["status"], "DARWIN_ICMP_UDP")
        self.assertGreater(res["scores"].get("macOS / BSD", 0), 0)

        synack = _synack(64, 65535, LINUX_OPTS, df=True)
        synack["icmp_udp_info"] = info
        fp = fingerprint(synack)
        self.assertEqual(fp["icmp_udp_status"], "DARWIN_ICMP_UDP")
        self.assertTrue(any("DF=1 and reflected Code=9" in r for r in fp["reasons"]))

    def test_linux_icmp_code_reflection_and_udp_filtered(self):
        info = {
            "tested": True,
            "echo_responded": True,
            "echo_code": 9,
            "echo_ttl": 64,
            "echo_df": False,
            "echo_ip_id": 36249,
            "udp_responded": False,
            "udp_quoted_len": None,
        }
        res = evaluate_icmp_udp(info)
        self.assertEqual(res["status"], "LINUX_ICMP_UDP")
        self.assertGreater(res["scores"].get("Linux", 0), 0)

        synack = _synack(64, 29200, LINUX_OPTS, df=True)
        synack["icmp_udp_info"] = info
        fp = fingerprint(synack)
        self.assertEqual(fp["icmp_udp_status"], "LINUX_ICMP_UDP")
        self.assertTrue(any("reflected Code=9 with DF=0" in r for r in fp["reasons"]))

    def test_icmp_fallback_candidate_fingerprint(self):
        # When all TCP ports are filtered, fingerprinting an ICMP candidate
        icmp_cand = {
            "ttl": 128,
            "window": 0,
            "options": b"",
            "df": False,
            "ip_id": 25995,
            "flags": 0,
            "probe_type": "ICMP Echo Reply",
            "icmp_udp_info": {
                "tested": True,
                "echo_responded": True,
                "echo_code": 0,
                "echo_ttl": 128,
                "echo_df": False,
                "echo_ip_id": 25995,
                "udp_responded": True,
                "udp_quoted_len": 328,
                "udp_ttl": 128,
            }
        }
        fp = fingerprint(icmp_cand)
        self.assertEqual(fp["os"], "Windows")
        self.assertEqual(fp["probe_type"], "ICMP Echo Reply")
        self.assertGreaterEqual(fp["confidence"], 60)

    def test_icmp_udp_not_tested_graceful(self):
        res = evaluate_icmp_udp(None)
        self.assertEqual(res["status"], "NOT_TESTED")
        self.assertEqual(res["scores"], {})

        synack = _synack(64, 5840, LINUX_OPTS, df=True)
        fp = fingerprint(synack)
        self.assertEqual(fp["icmp_udp_status"], "NOT_TESTED")


if __name__ == "__main__":
    unittest.main()
