import sys
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.packet import (
    build_syn_frame,
    internet_checksum,
    parse_ipv4_tcp_frame,
    parse_tcp_options,
    TCP_SYN,
)


class PacketTests(unittest.TestCase):
    def test_checksum_zero_word(self):
        self.assertEqual(internet_checksum(b"\x00\x00"), 0xFFFF)

    def test_syn_frame_structure(self):
        frame = build_syn_frame(
            "02:00:00:00:00:01",
            "02:00:00:00:00:02",
            "192.168.56.10",
            "192.168.56.20",
            40000,
            80,
            0x11223344,
        )

        self.assertEqual(frame[12:14], b"\x08\x00")
        self.assertEqual(len(frame), 54)

        info = parse_ipv4_tcp_frame(frame)
        self.assertIsNotNone(info)
        self.assertEqual(info["src_ip"], "192.168.56.10")
        self.assertEqual(info["dst_ip"], "192.168.56.20")
        self.assertEqual(info["src_port"], 40000)
        self.assertEqual(info["dst_port"], 80)
        self.assertEqual(info["seq"], 0x11223344)
        self.assertEqual(info["flags"], TCP_SYN)

    def test_option_parser(self):
        options = (
            b"\x02\x04\x05\xb4"   # MSS 1460
            b"\x01"               # NOP
            b"\x03\x03\x08"       # window scale 8
            b"\x04\x02"           # SACK permitted
            b"\x00"               # EOL
        )
        parsed = parse_tcp_options(options)
        self.assertIn(("MSS", 1460), parsed)
        self.assertIn(("WSCALE", 8), parsed)
        self.assertIn(("SACK_PERMITTED",), parsed)

    def test_icmp_echo_frame(self):
        from common.packet import build_icmp_echo_frame, parse_ipv4_icmp_frame
        frame = build_icmp_echo_frame(
            "02:00:00:00:00:01",
            "02:00:00:00:00:02",
            "192.168.1.10",
            "192.168.1.20",
            icmp_id=0x1234,
            icmp_seq=1,
            icmp_code=9,
            payload=b"PINGDATA",
        )
        parsed = parse_ipv4_icmp_frame(frame)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["icmp_type"], 8)
        self.assertEqual(parsed["icmp_code"], 9)
        self.assertEqual(parsed["icmp_id"], 0x1234)
        self.assertEqual(parsed["icmp_seq"], 1)
        self.assertEqual(parsed["icmp_payload"], b"PINGDATA")

    def test_udp_frame_structure(self):
        from common.packet import build_udp_frame
        frame = build_udp_frame(
            "02:00:00:00:00:01",
            "02:00:00:00:00:02",
            "192.168.1.10",
            "192.168.1.20",
            src_port=45000,
            dst_port=33434,
            payload=b"C" * 100,
        )
        self.assertEqual(frame[12:14], b"\x08\x00")
        # 14 (eth) + 20 (ip) + 8 (udp) + 100 = 142
        self.assertEqual(len(frame), 142)


if __name__ == "__main__":
    unittest.main()
