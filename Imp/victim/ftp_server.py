"""
Simulated vulnerable FTP server for lab demonstration.

INTENTIONAL VULNERABILITIES (for lab use only):
    - Anonymous login accepted with any password
    - Anonymous WRITE access via STOR (enables web-shell upload chain)
    - PORT command accepts arbitrary IP:port (enables bounce attack)
    - No TLS, no rate limiting, no logging beyond the console

DO NOT run this outside an isolated lab environment.

Usage:
    python victim\\ftp_server.py --port 21 --root ./lab_root
"""

import argparse
import os
import socket
import sys
import threading
import time


# Force UTF-8 output; the default Windows console codepage cannot encode
# the arrow glyphs used in log lines.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


class FTPSession(threading.Thread):
    """Handle a single FTP client session."""

    def __init__(self, client_sock, client_addr, root_dir, server_ip):
        super().__init__(daemon=True)
        self.sock = client_sock
        self.addr = client_addr
        self.root = os.path.abspath(root_dir)
        self.cwd = "/"
        self.server_ip = server_ip
        if not self.server_ip or self.server_ip == "127.0.0.1":
            try:
                if client_sock:
                    sock_name = client_sock.getsockname()[0]
                    if sock_name and not sock_name.startswith("127."):
                        self.server_ip = sock_name
            except Exception:
                pass
        self.logged_in = False

        # Data channel state — one of: "pasv" (listen) or "port" (dial out)
        self.data_mode = None
        self.data_sock = None       # PASV listener
        self.active_target = None   # PORT target (host, port)

    # ------------------------------------------------------------------ I/O

    def send(self, message):
        try:
            self.sock.sendall((message + "\r\n").encode("utf-8"))
        except OSError:
            pass

    def recv_line(self, timeout=30.0):
        self.sock.settimeout(timeout)
        buf = b""
        try:
            while b"\n" not in buf:
                chunk = self.sock.recv(1024)
                if not chunk:
                    return None
                buf += chunk
                if len(buf) > 4096:
                    break
        except (socket.timeout, OSError):
            return None
        return buf.decode("utf-8", errors="replace").strip()

    # ---------------------------------------------------------- Path helpers

    def _real_path(self, path):
        """Resolve an FTP path to a real filesystem path within root."""
        if path.startswith("/"):
            rel = path.lstrip("/")
        else:
            rel = os.path.join(self.cwd.lstrip("/"), path)
        real = os.path.normpath(os.path.join(self.root, rel))
        if not real.startswith(self.root):
            return None
        return real

    # --------------------------------------------------------- Data channels

    def _setup_pasv(self):
        """Create a PASV listener."""
        if self.data_sock:
            try:
                self.data_sock.close()
            except OSError:
                pass
        self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.data_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.data_sock.bind(("0.0.0.0", 0))
        self.data_sock.listen(1)
        self.data_sock.settimeout(10.0)
        self.data_mode = "pasv"
        self.active_target = None
        return self.data_sock.getsockname()[1]

    def _open_data_connection(self):
        """
        Open the data connection.

        In PASV mode: accept the client's incoming connection.
        In PORT mode: dial OUT to the client-specified host:port
                      (this is the FTP bounce primitive).
        Returns a connected socket or None on failure.
        """
        if self.data_mode == "port" and self.active_target:
            target = self.active_target
            self.active_target = None
            self.data_mode = None
            try:
                conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn.settimeout(5.0)
                conn.connect(target)
                print(f"[FTP] {self.addr} bounce dial-out to "
                      f"{target[0]}:{target[1]} SUCCEEDED")
                return conn
            except (socket.timeout, ConnectionRefusedError, OSError) as exc:
                print(f"[FTP] {self.addr} bounce dial-out to "
                      f"{target[0]}:{target[1]} FAILED: {exc}")
                return None

        if self.data_sock:
            try:
                conn, _ = self.data_sock.accept()
                return conn
            except (socket.timeout, OSError):
                return None
            finally:
                try:
                    self.data_sock.close()
                except OSError:
                    pass
                self.data_sock = None
                self.data_mode = None

        return None

    # ------------------------------------------------------------ Main loop

    def run(self):
        print(f"[FTP] Connection from {self.addr}")
        self.send("220 LabFTP Server (Vulnerable Demo) Ready")

        while True:
            line = self.recv_line()
            if line is None:
                break

            parts = line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            print(f"[FTP] {self.addr} → {cmd} {arg}")

            # ---------------------------------------------------------- AUTH
            if cmd == "USER":
                if arg.lower() in ("anonymous", "ftp"):
                    self.send("331 Anonymous login OK, send email as password.")
                else:
                    self.send(f"331 Password required for {arg}")

            elif cmd == "PASS":
                self.logged_in = True
                self.send("230 Login successful. (anonymous access enabled)")
                print(f"[FTP] {self.addr} logged in as anonymous")

            elif cmd == "SYST":
                self.send("215 UNIX Type: L8")

            elif cmd == "FEAT":
                self.send("211-Features:")
                self.send(" PASV")
                self.send(" UTF8")
                self.send("211 End")

            # -------------------------------------------------------- NAVIGATION
            elif cmd in ("PWD", "XPWD"):
                if not self.logged_in:
                    self.send("530 Not logged in.")
                    continue
                self.send(f'257 "{self.cwd}" is the current directory.')

            elif cmd == "CWD":
                if not self.logged_in:
                    self.send("530 Not logged in.")
                    continue
                new_path = self._real_path(arg)
                if new_path and os.path.isdir(new_path):
                    self.cwd = "/" + os.path.relpath(
                        new_path, self.root
                    ).replace("\\", "/")
                    if self.cwd == "/.":
                        self.cwd = "/"
                    self.send(f"250 Directory changed to {self.cwd}")
                else:
                    self.send("550 Directory not found.")

            elif cmd == "MKD":
                if not self.logged_in:
                    self.send("530 Not logged in.")
                    continue
                real = self._real_path(arg)
                if real:
                    try:
                        os.makedirs(real, exist_ok=True)
                        self.send(f'257 "{arg}" created.')
                    except OSError as exc:
                        self.send(f"550 MKD failed: {exc}")
                else:
                    self.send("550 Invalid path.")

            elif cmd == "TYPE":
                self.send("200 Type set to I.")

            # ------------------------------------------------------- DATA MODE
            elif cmd == "PASV":
                if not self.logged_in:
                    self.send("530 Not logged in.")
                    continue
                port = self._setup_pasv()
                p1 = port // 256
                p2 = port % 256
                ip_parts = self.server_ip.replace(".", ",")
                self.send(f"227 Entering Passive Mode ({ip_parts},{p1},{p2}).")

            elif cmd == "PORT":
                # INTENTIONALLY VULNERABLE: accepts any host:port. A secure
                # server would restrict this to the peer's own address.
                if not self.logged_in:
                    self.send("530 Not logged in.")
                    continue
                try:
                    pieces = arg.split(",")
                    if len(pieces) != 6:
                        self.send("501 Syntax error in PORT arguments.")
                        continue
                    host = ".".join(pieces[:4])
                    port = int(pieces[4]) * 256 + int(pieces[5])
                    if not (1 <= port <= 65535):
                        raise ValueError("bad port")
                    if self.data_sock:
                        try:
                            self.data_sock.close()
                        except OSError:
                            pass
                        self.data_sock = None
                    self.active_target = (host, port)
                    self.data_mode = "port"
                    self.send("200 PORT command successful.")
                    print(f"[FTP] {self.addr} PORT {host}:{port} stored as "
                          f"bounce target (vulnerable)")
                except (ValueError, IndexError):
                    self.send("501 Syntax error in PORT arguments.")

            # -------------------------------------------------------- LISTING
            elif cmd == "LIST":
                if not self.logged_in:
                    self.send("530 Not logged in.")
                    continue
                if not self.data_sock and not self.active_target:
                    self.send("425 Use PASV or PORT first.")
                    continue

                data_conn = self._open_data_connection()
                if not data_conn:
                    self.send("425 Can't open data connection.")
                    continue

                self.send("150 Opening data connection for directory listing.")
                real = self._real_path(self.cwd)
                if real and os.path.isdir(real):
                    listing = ""
                    for name in sorted(os.listdir(real)):
                        full = os.path.join(real, name)
                        if os.path.isdir(full):
                            listing += (f"drwxr-xr-x 1 ftp ftp 0 "
                                        f"Jan 01 00:00 {name}\r\n")
                        else:
                            size = os.path.getsize(full)
                            listing += (f"-rw-r--r-- 1 ftp ftp {size} "
                                        f"Jan 01 00:00 {name}\r\n")
                    try:
                        data_conn.sendall(listing.encode("utf-8"))
                    except OSError:
                        pass
                try:
                    data_conn.close()
                except OSError:
                    pass
                self.send("226 Transfer complete.")

            # ---------------------------------------------------- DOWNLOAD
            elif cmd == "RETR":
                if not self.logged_in:
                    self.send("530 Not logged in.")
                    continue
                if not self.data_sock and not self.active_target:
                    self.send("425 Use PASV or PORT first.")
                    continue

                real = self._real_path(arg)
                if not (real and os.path.isfile(real)):
                    self.send("550 File not found.")
                    continue

                data_conn = self._open_data_connection()
                if not data_conn:
                    self.send("425 Can't open data connection.")
                    continue

                self.send("150 Opening data connection.")
                try:
                    with open(real, "rb") as f:
                        while True:
                            chunk = f.read(8192)
                            if not chunk:
                                break
                            data_conn.sendall(chunk)
                except OSError:
                    pass
                finally:
                    try:
                        data_conn.close()
                    except OSError:
                        pass
                self.send("226 Transfer complete.")

            # ------------------------------------------------------ UPLOAD
            elif cmd == "STOR":
                if not self.logged_in:
                    self.send("530 Not logged in.")
                    continue
                if not self.data_sock and not self.active_target:
                    self.send("425 Use PASV or PORT first.")
                    continue

                real = self._real_path(arg)
                if not real:
                    self.send("550 Invalid path.")
                    continue

                parent = os.path.dirname(real)
                try:
                    os.makedirs(parent, exist_ok=True)
                except OSError:
                    self.send("550 Cannot create parent directory.")
                    continue

                data_conn = self._open_data_connection()
                if not data_conn:
                    self.send("425 Can't open data connection.")
                    continue

                self.send("150 Opening data connection for upload.")
                try:
                    with open(real, "wb") as f:
                        while True:
                            chunk = data_conn.recv(8192)
                            if not chunk:
                                break
                            f.write(chunk)
                    self.send("226 Transfer complete.")
                    print(f"[FTP] {self.addr} STOR {arg} "
                          f"({os.path.getsize(real)} bytes)")
                except OSError as exc:
                    self.send(f"550 Upload failed: {exc}")
                finally:
                    try:
                        data_conn.close()
                    except OSError:
                        pass

            elif cmd == "DELE":
                if not self.logged_in:
                    self.send("530 Not logged in.")
                    continue
                real = self._real_path(arg)
                if real and os.path.isfile(real):
                    try:
                        os.remove(real)
                        self.send("250 File deleted.")
                        print(f"[FTP] {self.addr} DELE {arg}")
                    except OSError as exc:
                        self.send(f"550 Delete failed: {exc}")
                else:
                    self.send("550 File not found.")

            elif cmd == "QUIT":
                self.send("221 Goodbye.")
                break

            elif cmd == "NOOP":
                self.send("200 OK")

            else:
                self.send(f"502 Command not implemented: {cmd}")

        print(f"[FTP] {self.addr} disconnected")
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Simulated vulnerable FTP server for lab demos"
    )
    parser.add_argument("--port", type=int, default=21)
    parser.add_argument("--root", type=str, default="./lab_root")
    parser.add_argument("--bind", type=str, default="0.0.0.0")
    parser.add_argument("--server-ip", type=str, default=None,
                        help="Explicit IP to advertise in PASV (auto-detected if omitted)")
    args = parser.parse_args()

    # Ensure root + uploads directory exist with sample files.
    root = os.path.abspath(args.root)
    os.makedirs(root, exist_ok=True)
    os.makedirs(os.path.join(root, "uploads"), exist_ok=True)
    os.makedirs(os.path.join(root, "pub"), exist_ok=True)
    os.makedirs(os.path.join(root, "pub", "data"), exist_ok=True)

    readme = os.path.join(root, "pub", "readme.txt")
    if not os.path.exists(readme):
        with open(readme, "w") as f:
            f.write("This is a simulated vulnerable FTP server.\n")
            f.write("If you can read this, the FTP anonymous exploit worked!\n")

    secret = os.path.join(root, "pub", "data", "credentials.txt")
    if not os.path.exists(secret):
        with open(secret, "w") as f:
            f.write("admin:SuperSecretPassword123\n")
            f.write("backup:BackupPass456\n")

    # Discover server IP for PASV responses.
    if args.server_ip:
        server_ip = args.server_ip
    else:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            server_ip = s.getsockname()[0]
            s.close()
        except OSError:
            server_ip = "127.0.0.1"

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(5)

    print(f"[FTP] Vulnerable FTP server listening on {args.bind}:{args.port}")
    print(f"[FTP] Root: {root}")
    print(f"[FTP] Uploads dir: {os.path.join(root, 'uploads')}")
    print(f"[FTP] Server IP (for PASV): {server_ip}")
    print(f"[FTP] Anonymous login: ENABLED")
    print(f"[FTP] Anonymous WRITE (STOR/DELE/MKD): ENABLED")
    print(f"[FTP] PORT command (bounce): ENABLED (arbitrary target)")
    print(f"[FTP] Press Ctrl+C to stop.\n")

    try:
        while True:
            client_sock, client_addr = listener.accept()
            session = FTPSession(client_sock, client_addr, root, server_ip)
            session.start()
    except KeyboardInterrupt:
        print("\n[FTP] Server stopped.")
    finally:
        listener.close()


if __name__ == "__main__":
    main()