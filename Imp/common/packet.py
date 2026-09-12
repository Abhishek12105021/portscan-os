"""
Manual Ethernet / IPv4 / TCP packet construction and parsing.

No Scapy/Nmap.
"""

import ipaddress
import socket
import struct


ETHERTYPE_IPV4 = 0x0800
IPPROTO_TCP = 6

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80


def internet_checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def mac_bytes(text: str) -> bytes:
    parts = text.replace("-", ":").split(":")
    if len(parts) != 6:
        raise ValueError("MAC must contain six octets")
    return bytes(int(x, 16) for x in parts)


def mac_text(data: bytes) -> str:
    return ":".join(f"{x:02x}" for x in data)


def ipv4_bytes(text: str) -> bytes:
    return socket.inet_aton(str(ipaddress.IPv4Address(text)))


def build_ethernet(dst_mac: str, src_mac: str, payload: bytes) -> bytes:
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack(
        "!H", ETHERTYPE_IPV4
    ) + payload


def build_ipv4(src_ip: str, dst_ip: str, tcp_segment: bytes,
               identification: int = 0x4000, ttl: int = 64) -> bytes:
    version_ihl = (4 << 4) | 5
    total_length = 20 + len(tcp_segment)
    flags_fragment = 0
    checksum = 0

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_length, identification & 0xFFFF,
        flags_fragment, ttl, IPPROTO_TCP, checksum,
        ipv4_bytes(src_ip), ipv4_bytes(dst_ip)
    )

    checksum = internet_checksum(header)

    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_length, identification & 0xFFFF,
        flags_fragment, ttl, IPPROTO_TCP, checksum,
        ipv4_bytes(src_ip), ipv4_bytes(dst_ip)
    ) + tcp_segment


def build_tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
              sequence: int, window: int = 64240,
              options: bytes = b"", flags: int = TCP_SYN) -> bytes:
    if len(options) % 4:
        raise ValueError("TCP options must be a multiple of 4 bytes")

    data_offset = 5 + len(options) // 4
    ack = 0
    checksum = 0
    urgent = 0

    offset_flags = (data_offset << 12) | (flags & 0x01FF)

    header = struct.pack(
        "!HHLLHHHH",
        src_port, dst_port, sequence & 0xFFFFFFFF, ack,
        offset_flags, window, checksum, urgent
    ) + options

    pseudo = struct.pack(
        "!4s4sBBH",
        ipv4_bytes(src_ip), ipv4_bytes(dst_ip), 0, IPPROTO_TCP, len(header)
    )

    checksum = internet_checksum(pseudo + header)

    return struct.pack(
        "!HHLLHHHH",
        src_port, dst_port, sequence & 0xFFFFFFFF, ack,
        offset_flags, window, checksum, urgent
    ) + options


# Standard SYN options offering MSS, SACK Permitted, Timestamp, and Window Scale.
# This triggers rich TCP option negotiation on Apple Darwin, Linux, and Windows.
STANDARD_SYN_OPTIONS = (
    b"\x02\x04\x05\xb4"                            # MSS 1460
    b"\x04\x02"                                    # SACK permitted
    b"\x08\x0a\x00\x00\x00\x01\x00\x00\x00\x00"    # Timestamp
    b"\x01"                                        # NOP
    b"\x03\x03\x08"                                # Window scale 8
)


def build_syn_frame(src_mac: str, dst_mac: str,
                    src_ip: str, dst_ip: str,
                    src_port: int, dst_port: int,
                    sequence: int, ttl: int = 64,
                    options: bytes = b"",
                    flags: int = TCP_SYN) -> bytes:
    tcp = build_tcp(
        src_ip, dst_ip, src_port, dst_port, sequence, options=options, flags=flags
    )
    ip = build_ipv4(
        src_ip, dst_ip, tcp, identification=sequence & 0xFFFF, ttl=ttl
    )
    return build_ethernet(dst_mac, src_mac, ip)


def build_ecn_syn_frame(src_mac: str, dst_mac: str,
                        src_ip: str, dst_ip: str,
                        src_port: int, dst_port: int,
                        sequence: int, ttl: int = 64,
                        options: bytes = STANDARD_SYN_OPTIONS) -> bytes:
    """Builds an RFC 3168 ECN probe frame (TCP SYN with ECE and CWR flags set)."""
    return build_syn_frame(
        src_mac=src_mac, dst_mac=dst_mac,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        sequence=sequence, ttl=ttl,
        options=options,
        flags=TCP_SYN | TCP_ECE | TCP_CWR,
    )


def build_synfin_frame(src_mac: str, dst_mac: str,
                       src_ip: str, dst_ip: str,
                       src_port: int, dst_port: int,
                       sequence: int, ttl: int = 64,
                       options: bytes = b"") -> bytes:
    """Builds an ambiguous SYN+FIN probe frame (The 'Rule-Breaker' Test - Idea 5)."""
    return build_syn_frame(
        src_mac=src_mac, dst_mac=dst_mac,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        sequence=sequence, ttl=ttl,
        options=options,
        flags=TCP_SYN | TCP_FIN,
    )


def build_null_frame(src_mac: str, dst_mac: str,
                     src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int,
                     sequence: int, ttl: int = 64,
                     options: bytes = b"") -> bytes:
    """Builds a NULL scan frame with no flags set (flags = 0)."""
    return build_syn_frame(
        src_mac=src_mac, dst_mac=dst_mac,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        sequence=sequence, ttl=ttl,
        options=options,
        flags=0,
    )


def build_xmas_frame(src_mac: str, dst_mac: str,
                     src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int,
                     sequence: int, ttl: int = 64,
                     options: bytes = b"") -> bytes:
    """Builds an Xmas scan frame with FIN, PSH, and URG flags set."""
    return build_syn_frame(
        src_mac=src_mac, dst_mac=dst_mac,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        sequence=sequence, ttl=ttl,
        options=options,
        flags=TCP_FIN | TCP_PSH | TCP_URG,
    )


def parse_ethernet(frame: bytes):
    if len(frame) < 14:
        return None
    dst = mac_text(frame[0:6])
    src = mac_text(frame[6:12])
    ethertype = struct.unpack("!H", frame[12:14])[0]
    return {
        "dst_mac": dst,
        "src_mac": src,
        "ethertype": ethertype,
        "payload_offset": 14,
    }


def parse_ipv4(frame: bytes, offset: int):
    if len(frame) < offset + 20:
        return None

    first = frame[offset]
    version = first >> 4
    ihl = (first & 0x0F) * 4

    if version != 4 or ihl < 20 or len(frame) < offset + ihl:
        return None

    (
        _vihl, tos, total_length, identification,
        flags_fragment, ttl, protocol, ip_checksum,
        src, dst
    ) = struct.unpack(
        "!BBHHHBBH4s4s", frame[offset:offset + 20]
    )

    # The 3-bit flags live in the top of the 16-bit flags/fragment word:
    #   bit 15 = reserved, bit 14 = DF (Don't Fragment), bit 13 = MF.
    df_flag = bool(flags_fragment & 0x4000)
    mf_flag = bool(flags_fragment & 0x2000)

    return {
        "src_ip": socket.inet_ntoa(src),
        "dst_ip": socket.inet_ntoa(dst),
        "ihl": ihl,
        "tos": tos,
        "total_length": total_length,
        "identification": identification,
        "ip_id": identification,
        "flags_fragment": flags_fragment,
        "df": df_flag,
        "mf": mf_flag,
        "ttl": ttl,
        "protocol": protocol,
        "checksum": ip_checksum,
        "tcp_offset": offset + ihl,
    }


def parse_tcp(frame: bytes, offset: int):
    if len(frame) < offset + 20:
        return None

    (
        src_port, dst_port, seq, ack,
        offset_flags, window, checksum, urgent
    ) = struct.unpack(
        "!HHLLHHHH", frame[offset:offset + 20]
    )

    data_offset = ((offset_flags >> 12) & 0xF) * 4
    flags = offset_flags & 0x01FF

    if data_offset < 20 or len(frame) < offset + data_offset:
        return None

    options = frame[offset + 20: offset + data_offset]

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq": seq,
        "ack": ack,
        "data_offset": data_offset,
        "flags": flags,
        "window": window,
        "checksum": checksum,
        "urgent": urgent,
        "options": options,
    }


def parse_ipv4_tcp_frame(frame: bytes):
    eth = parse_ethernet(frame)
    if not eth or eth["ethertype"] != ETHERTYPE_IPV4:
        return None

    ip = parse_ipv4(frame, eth["payload_offset"])
    if not ip or ip["protocol"] != IPPROTO_TCP:
        return None

    tcp = parse_tcp(frame, ip["tcp_offset"])
    if not tcp:
        return None

    result = {}
    result.update(eth)
    result.update(ip)
    result.update(tcp)
    return result


def parse_tcp_options(options: bytes):
    result = []
    i = 0

    while i < len(options):
        kind = options[i]

        if kind == 0:  # EOL
            result.append(("EOL",))
            break

        if kind == 1:  # NOP
            result.append(("NOP",))
            i += 1
            continue

        if i + 1 >= len(options):
            break

        length = options[i + 1]
        if length < 2 or i + length > len(options):
            break

        value = options[i + 2:i + length]

        if kind == 2 and length == 4:
            result.append(("MSS", struct.unpack("!H", value)[0]))
        elif kind == 3 and length == 3:
            result.append(("WSCALE", value[0]))
        elif kind == 4 and length == 2:
            result.append(("SACK_PERMITTED",))
        elif kind == 5:
            result.append(("SACK", value.hex()))
        elif kind == 8 and length == 10:
            tsval, tsecr = struct.unpack("!LL", value)
            result.append(("TIMESTAMP", tsval, tsecr))
        else:
            result.append((f"KIND_{kind}", value.hex()))

        i += length

    return result
