import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "defense"))

from detector import ScanDetector


def test_detector_fast_scan_alert():
    det = ScanDetector(threshold=3, distinct_ports=2, window=10.0, canary_ports=[])
    # Port 1
    cnt, uniq, alert, reason = det.observe_syn("192.168.1.50", 80)
    assert not alert
    # Port 2
    cnt, uniq, alert, reason = det.observe_syn("192.168.1.50", 443)
    assert not alert
    # Port 3 (hits threshold 3 and distinct 2)
    cnt, uniq, alert, reason = det.observe_syn("192.168.1.50", 8080)
    assert alert
    assert "fast port scan" in reason


def test_detector_canary_honeyport():
    det = ScanDetector(canary_ports=[81, 1337])
    cnt, uniq, alert, reason = det.observe_syn("10.0.0.99", 81)
    assert alert
    assert "canary honeyport" in reason


def test_detector_invalid_flags():
    det = ScanDetector()
    # 0x03 = SYN + FIN
    bad, reason = det.observe_invalid_flags("10.0.0.99", 80, 0x03)
    assert bad
    assert "SYN+FIN" in reason


def test_detector_whitelist():
    det = ScanDetector(threshold=2, distinct_ports=1, whitelist=["192.168.1.1"])
    cnt, uniq, alert, reason = det.observe_syn("192.168.1.1", 80)
    assert not alert
    cnt, uniq, alert, reason = det.observe_syn("192.168.1.1", 443)
    assert not alert


@patch("subprocess.run")
def test_detector_auto_release_ttl(mock_subproc):
    mock_subproc.return_value = MagicMock(returncode=0)
    det = ScanDetector(block=True, block_ttl=2.0)
    det.mitigate("192.168.1.200", reason="test block")

    assert "192.168.1.200" in det.blocked

    # Immediately check release -> should still be blocked
    det.release_expired()
    assert "192.168.1.200" in det.blocked

    # Fast forward time
    det.blocked["192.168.1.200"]["added_at"] = time.monotonic() - 5.0
    det.release_expired()

    # Should now be released
    assert "192.168.1.200" not in det.blocked
