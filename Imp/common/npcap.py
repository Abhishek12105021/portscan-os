"""
Minimal ctypes bindings to the Npcap WinPcap-compatible API.

This module is deliberately small: it only provides packet I/O. It does not
construct, scan, fingerprint, or classify packets.
"""

import ctypes
from ctypes import (
    POINTER, Structure, byref, c_char, c_char_p, c_int, c_ubyte,
    c_uint, c_void_p, c_ulong, c_ushort
)
import socket
import struct
import time


class PcapAddr(Structure):
    pass


class PcapIf(Structure):
    pass


PcapAddr._fields_ = [
    ("next", POINTER(PcapAddr)),
    ("addr", c_void_p),
    ("netmask", c_void_p),
    ("broadaddr", c_void_p),
    ("dstaddr", c_void_p),
]

PcapIf._fields_ = [
    ("next", POINTER(PcapIf)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", POINTER(PcapAddr)),
    ("flags", c_uint),
]

PCAP_ERRBUF_SIZE = 256


class PcapPkthdr(Structure):
    _fields_ = [
        ("ts_sec", ctypes.c_long),
        ("ts_usec", ctypes.c_long),
        ("caplen", c_uint),
        ("len", c_uint),
    ]


def load_npcap():
    errors = []
    for name in ("wpcap.dll", "Npcap/wpcap.dll"):
        try:
            lib = ctypes.WinDLL(name)
            return lib
        except OSError as exc:
            errors.append(str(exc))
    raise RuntimeError(
        "Could not load wpcap.dll. Install Npcap with WinPcap-compatible "
        "API support. Details: " + " | ".join(errors)
    )


class Pcap:
    def __init__(self, device: str, snaplen=65535, promisc=True, timeout_ms=100):
        self.lib = load_npcap()

        self.lib.pcap_open_live.argtypes = [
            c_char_p, c_int, c_int, c_int, POINTER(c_char)
        ]
        self.lib.pcap_open_live.restype = c_void_p

        self.lib.pcap_sendpacket.argtypes = [c_void_p, c_char_p, c_int]
        self.lib.pcap_sendpacket.restype = c_int

        self.lib.pcap_next_ex.argtypes = [
            c_void_p, POINTER(POINTER(PcapPkthdr)), POINTER(POINTER(c_ubyte))
        ]
        self.lib.pcap_next_ex.restype = c_int

        self.lib.pcap_close.argtypes = [c_void_p]
        self.lib.pcap_close.restype = None

        self.handle = None
        self._device = device.encode("utf-8")
        errbuf = (c_char * PCAP_ERRBUF_SIZE)()

        self.handle = self.lib.pcap_open_live(
            self._device,
            snaplen,
            1 if promisc else 0,
            timeout_ms,
            errbuf,
        )

        if not self.handle:
            msg = bytes(errbuf).split(b"\0", 1)[0].decode(
                errors="replace"
            )
            raise RuntimeError(f"pcap_open_live failed: {msg}")

    def send(self, frame: bytes):
        buf = ctypes.create_string_buffer(frame)
        rc = self.lib.pcap_sendpacket(
            self.handle, ctypes.cast(buf, c_char_p), len(frame)
        )
        if rc != 0:
            raise RuntimeError(f"pcap_sendpacket failed: {rc}")

    def recv(self):
        header = POINTER(PcapPkthdr)()
        data = POINTER(c_ubyte)()

        rc = self.lib.pcap_next_ex(
            self.handle, byref(header), byref(data)
        )

        if rc == 0:
            return None
        if rc < 0:
            raise RuntimeError(f"pcap_next_ex failed: {rc}")

        return bytes(data[:header.contents.caplen])

    def close(self):
        if self.handle:
            self.lib.pcap_close(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def list_adapters():
    lib = load_npcap()

    lib.pcap_findalldevs.argtypes = [
        POINTER(POINTER(PcapIf)), POINTER(c_char)
    ]
    lib.pcap_findalldevs.restype = c_int

    lib.pcap_freealldevs.argtypes = [POINTER(PcapIf)]
    lib.pcap_freealldevs.restype = None

    alldevs = POINTER(PcapIf)()
    errbuf = (c_char * PCAP_ERRBUF_SIZE)()

    rc = lib.pcap_findalldevs(byref(alldevs), errbuf)
    if rc != 0:
        msg = bytes(errbuf).split(b"\0", 1)[0].decode(
            errors="replace"
        )
        raise RuntimeError(f"pcap_findalldevs failed: {msg}")

    result = []
    try:
        current = alldevs
        while current:
            item = current.contents
            name = item.name.decode("utf-8", errors="replace") if item.name else ""
            desc = (
                item.description.decode("utf-8", errors="replace")
                if item.description else ""
            )
            result.append((name, desc))
            current = item.next
    finally:
        lib.pcap_freealldevs(alldevs)

    return result


def choose_adapter(name: str):
    adapters = list_adapters()
    for n, d in adapters:
        if n == name:
            return n
    raise ValueError(
        "Adapter not found. Run tools\\list_npcap_adapters.py first."
    )


def local_ipv4_for_target(target: str) -> str:
    """
    Ask Windows routing/socket code which local IPv4 would be used to reach
    the target. No application payload is transmitted.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    finally:
        s.close()


# ---- Windows IP Helper API: local MAC + ARP resolution ---------------------

class IPAddrString(Structure):
    pass


IPAddrString._fields_ = [
    ("Next", POINTER(IPAddrString)),
    ("IpAddress", c_char * 16),
    ("IpMask", c_char * 16),
    ("Context", c_ulong),
]


class IPAdapterInfo(Structure):
    pass


IPAdapterInfo._fields_ = [
    ("Next", POINTER(IPAdapterInfo)),
    ("ComboIndex", c_ulong),
    ("AdapterName", c_char * 260),
    ("Description", c_char * 132),
    ("AddressLength", c_uint),
    ("Address", c_ubyte * 8),
    ("Index", c_ulong),
    ("Type", c_uint),
    ("DhcpEnabled", c_uint),
    ("CurrentIpAddress", c_void_p),
    ("IpAddressList", IPAddrString),
    ("GatewayList", IPAddrString),
    ("DhcpServer", IPAddrString),
    ("HaveWins", c_uint),
    ("PrimaryWinsServer", IPAddrString),
    ("SecondaryWinsServer", IPAddrString),
    ("LeaseObtained", c_ulong),
    ("LeaseExpires", c_ulong),
]


def local_mac_for_ip(ip: str) -> str:
    iphlpapi = ctypes.WinDLL("iphlpapi.dll")
    GetAdaptersInfo = iphlpapi.GetAdaptersInfo
    GetAdaptersInfo.argtypes = [POINTER(IPAdapterInfo), POINTER(c_ulong)]
    GetAdaptersInfo.restype = c_ulong

    size = c_ulong(0)
    rc = GetAdaptersInfo(None, byref(size))

    # ERROR_BUFFER_OVERFLOW = 111
    if rc not in (0, 111):
        raise RuntimeError(f"GetAdaptersInfo sizing failed: {rc}")

    buf = ctypes.create_string_buffer(size.value)
    ptr = ctypes.cast(buf, POINTER(IPAdapterInfo))

    rc = GetAdaptersInfo(ptr, byref(size))
    if rc != 0:
        raise RuntimeError(f"GetAdaptersInfo failed: {rc}")

    current = ptr
    while current:
        info = current.contents
        p = info.IpAddressList

        while True:
            addr = p.IpAddress.split(b"\0", 1)[0].decode(
                errors="replace"
            )
            if addr == ip:
                mac = bytes(info.Address[:info.AddressLength])
                if len(mac) >= 6:
                    return ":".join(f"{x:02x}" for x in mac[:6])
                raise RuntimeError("Adapter has no usable MAC address.")

            if not p.Next:
                break
            p = p.Next

        current = info.Next

    raise RuntimeError(
        f"Could not find the local adapter corresponding to {ip}."
    )


def _lookup_arp_cache(target_ip: str):
    """Fallback to Windows ARP table if SendARP packet was missed during power-save."""
    import subprocess
    import re
    try:
        out = subprocess.check_output(
            ["arp", "-a", target_ip], stderr=subprocess.DEVNULL, timeout=2.0
        ).decode("utf-8", errors="replace")
        m = re.search(
            r"([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})",
            out,
        )
        if m:
            return m.group(1).replace("-", ":").lower()
    except Exception:
        pass
    return None


def arp_resolve(target_ip: str, source_ip: str, retries: int = 6) -> str:
    iphlpapi = ctypes.WinDLL("iphlpapi.dll")
    SendARP = iphlpapi.SendARP
    SendARP.argtypes = [
        c_ulong, c_ulong, c_void_p, POINTER(c_ulong)
    ]
    SendARP.restype = c_ulong

    dst = struct_ipv4_to_ulong(target_ip)
    src = struct_ipv4_to_ulong(source_ip)

    mac = (c_ubyte * 8)()
    length = c_ulong(8)

    last_rc = 0
    for attempt in range(retries):
        length = c_ulong(8)
        last_rc = SendARP(dst, src, mac, byref(length))
        if last_rc == 0 and length.value >= 6:
            return ":".join(f"{x:02x}" for x in mac[:6])
        time.sleep(0.35)

    # Fallback to existing Windows ARP table cache before raising
    cached_mac = _lookup_arp_cache(target_ip)
    if cached_mac:
        return cached_mac

    if last_rc != 0:
        raise RuntimeError(
            f"SendARP failed with Windows error {last_rc}. "
            "The target may be unreachable or not on the local LAN."
        )

    if length.value < 6:
        raise RuntimeError("ARP returned an invalid hardware address.")

    return ":".join(f"{x:02x}" for x in mac[:6])


def struct_ipv4_to_ulong(ip: str) -> int:
    # inet_aton is network-order; Windows IP Helper expects the IPv4 value
    # represented as an unsigned integer.
    packed = socket.inet_aton(ip)
    return int.from_bytes(packed, byteorder="little")
