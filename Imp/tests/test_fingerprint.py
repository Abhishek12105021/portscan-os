"""Tests for the probabilistic OS fingerprint engine."""

import sys
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))                 # for `common` package
sys.path.insert(0, str(ROOT / "attacker"))    # for `fingerprint` module

from fingerprint import fingerprint, normalise_ttl
from common.packet import TCP_RST, TCP_SYN, TCP_ACK


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


if __name__ == "__main__":
    unittest.main()
