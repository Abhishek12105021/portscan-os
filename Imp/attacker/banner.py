"""
Service banner grabbing module.

Connects to open ports using standard TCP sockets and reads the service
identification banner. This complements the SYN scanner by identifying
*what* is running on each open port.

Design decision: uses standard socket.connect() rather than raw packets
because banner grabbing requires a complete TCP handshake — there is no
stealth advantage to using raw frames here.
"""

import re
import socket


# Port-to-protocol hint table.  Used to decide which probe to send.
PROTOCOL_HINTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    587: "smtp",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    8080: "http",
    8443: "https",
}

# Services that send a banner immediately on connect (passive).
PASSIVE_SERVICES = {"ftp", "ssh", "telnet", "smtp", "pop3", "imap", "mysql"}

# Services that require us to send something first (active).
ACTIVE_SERVICES = {"http"}


def _recv_banner(sock, timeout=3.0, bufsize=1024):
    """Read whatever the remote end sends within *timeout* seconds."""
    sock.settimeout(timeout)
    try:
        data = sock.recv(bufsize)
        return data
    except (socket.timeout, ConnectionError, OSError):
        return b""


def _grab_passive(sock):
    """Read the initial banner from a passive service."""
    return _recv_banner(sock, timeout=3.0)


def _grab_http(sock):
    """Send an HTTP HEAD request and capture the response."""
    request = b"HEAD / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n"
    # Defined before the try so the except handler can reference it even if
    # sock.sendall() fails before any data is read.
    chunks = []
    try:
        sock.sendall(request)
        # HTTP responses can be larger; read in a loop.
        sock.settimeout(3.0)
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            if len(b"".join(chunks)) > 8192:
                break
        return b"".join(chunks)
    except (socket.timeout, ConnectionError, OSError):
        return b"".join(chunks) if chunks else b""


def _parse_http_server(raw_banner):
    """Extract the Server header from an HTTP response."""
    text = raw_banner.decode("utf-8", errors="replace")
    match = re.search(r"Server:\s*(.+)", text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def _parse_service_version(protocol, raw_banner):
    """
    Parse the raw banner into (service_name, version_string).

    Returns best-effort strings. If we can't parse, we return the raw text.
    """
    text = raw_banner.decode("utf-8", errors="replace").strip()

    if protocol == "ftp":
        # e.g. "220 vsftpd 3.0.3" or "220 (vsFTPd 3.0.5)"
        match = re.search(r"220[- ](.+)", text)
        if match:
            return "FTP", match.group(1).strip()
        return "FTP", text

    if protocol == "ssh":
        # e.g. "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        if text.startswith("SSH-"):
            return "SSH", text
        return "SSH", text

    if protocol == "smtp":
        match = re.search(r"220\s+(.+)", text)
        if match:
            return "SMTP", match.group(1).strip()
        return "SMTP", text

    if protocol == "http":
        server = _parse_http_server(raw_banner)
        if server:
            return "HTTP", server
        return "HTTP", text[:120] if text else "(no banner)"

    if protocol == "telnet":
        return "Telnet", text[:120] if text else "(no banner)"

    if protocol == "pop3":
        return "POP3", text[:120] if text else "(no banner)"

    if protocol == "imap":
        return "IMAP", text[:120] if text else "(no banner)"

    if protocol == "mysql":
        return "MySQL", text[:120] if text else "(no banner)"

    # Unknown protocol — just return raw text.
    return "Unknown", text[:120] if text else "(no banner)"


def grab_banner(target_ip, port, timeout=5.0):
    """
    Attempt to grab the service banner on *target_ip*:*port*.

    Returns a dict:
        {
            "port": int,
            "protocol": str,       # e.g. "ftp", "http", "ssh"
            "service": str,        # e.g. "FTP", "HTTP", "SSH"
            "version": str,        # e.g. "vsftpd 3.0.3"
            "raw_banner": bytes,
            "success": bool,
        }

    Never raises; returns success=False on failure.
    """
    protocol = PROTOCOL_HINTS.get(port, "unknown")
    result = {
        "port": port,
        "protocol": protocol,
        "service": "Unknown",
        "version": "(no banner)",
        "raw_banner": b"",
        "success": False,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        result["version"] = f"(connect failed: {exc})"
        return result

    try:
        if protocol in ACTIVE_SERVICES:
            raw = _grab_http(sock)
        elif protocol in PASSIVE_SERVICES:
            raw = _grab_passive(sock)
        else:
            # Unknown service — try passive read first.
            raw = _recv_banner(sock, timeout=2.0)
            if not raw:
                # No passive banner; skip active probe for unknown services.
                pass

        if raw:
            result["raw_banner"] = raw
            service, version = _parse_service_version(protocol, raw)
            result["service"] = service
            result["version"] = version
            result["success"] = True
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass

    return result


def grab_banners(target_ip, open_ports, timeout=5.0):
    """
    Grab banners for a list of open ports.

    Returns a list of result dicts (same format as grab_banner).
    """
    results = []
    for port in open_ports:
        info = grab_banner(target_ip, port, timeout=timeout)
        results.append(info)
    return results
