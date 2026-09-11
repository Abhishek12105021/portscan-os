"""Tests for the probabilistic OS fingerprint engine."""

import sys
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))                 # for `common` package
sys.path.insert(0, str(ROOT / "attacker"))    # for `fingerprint` module

from fingerprint import fingerprint, normalise_ttl


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


if __name__ == "__main__":
    unittest.main()
