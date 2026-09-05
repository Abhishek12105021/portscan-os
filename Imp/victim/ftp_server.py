"""
Simulated vulnerable FTP server for lab demonstration.

This server intentionally allows anonymous login and serves files from a
configurable directory. It is designed to be exploited by the FTP
anonymous login exploit module.

DO NOT run this outside of an isolated lab environment.

Usage:
    python victim\\ftp_server.py --port 21 --root ./ftp_root

The server:
    - Accepts USER anonymous / PASS (anything)
    - Supports PWD, LIST, PASV, RETR, QUIT
    - Serves files from the --root directory
"""

import argparse
import os
import socket
import sys
import threading
import time


# Log lines contain a "→" glyph that the default Windows console code page
# (cp1252) cannot encode; without this the session threads crash on the
# first logged command. Force UTF-8 output with graceful fallback.
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
        self.logged_in = False
        self.data_sock = None
        self.data_port = None

    def send(self, message):
        """Send an FTP response line."""
        try:
            self.sock.sendall((message + "\r\n").encode("utf-8"))
        except OSError:
            pass

    def recv_line(self, timeout=30.0):
        """Receive one line from the client."""
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

    def _real_path(self, path):
        """Resolve an FTP path to a real filesystem path within the root."""
        if path.startswith("/"):
            rel = path.lstrip("/")
        else:
            rel = os.path.join(self.cwd.lstrip("/"), path)
        real = os.path.normpath(os.path.join(self.root, rel))
        # Ensure we stay within root.
        if not real.startswith(self.root):
            return None
        return real

    def _setup_pasv(self):
        """Create a PASV data listener and return the port."""
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
        self.data_port = self.data_sock.getsockname()[1]
        return self.data_port

    def _accept_data(self):
        """Accept a data connection from the client."""
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

    def run(self):
        """Main FTP session loop."""
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

            if cmd == "USER":
                if arg.lower() in ("anonymous", "ftp"):
                    self.send("331 Anonymous login OK, send email as password.")
                else:
                    self.send("331 Password required for " + arg)

            elif cmd == "PASS":
                # Accept any password for anonymous.
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

            elif cmd == "PWD" or cmd == "XPWD":
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
                    self.cwd = "/" + os.path.relpath(new_path, self.root).replace("\\", "/")
                    if self.cwd == "/.":
                        self.cwd = "/"
                    self.send(f"250 Directory changed to {self.cwd}")
                else:
                    self.send("550 Directory not found.")

            elif cmd == "TYPE":
                self.send("200 Type set to I.")

            elif cmd == "PASV":
                if not self.logged_in:
                    self.send("530 Not logged in.")
                    continue
                port = self._setup_pasv()
                p1 = port // 256
                p2 = port % 256
                ip_parts = self.server_ip.replace(".", ",")
                self.send(f"227 Entering Passive Mode ({ip_parts},{p1},{p2}).")

            elif cmd == "LIST":
                if not self.logged_in:
                    self.send("530 Not logged in.")
                    continue
                if not self.data_sock:
                    self.send("425 Use PASV first.")
                    continue

                self.send("150 Opening data connection for directory listing.")
                data_conn = self._accept_data()
                if data_conn:
                    real = self._real_path(self.cwd)
                    if real and os.path.isdir(real):
                        listing = ""
                        for name in sorted(os.listdir(real)):
                            full = os.path.join(real, name)
                            if os.path.isdir(full):
                                listing += f"drwxr-xr-x 1 ftp ftp 0 Jan 01 00:00 {name}\r\n"
                            else:
                                size = os.path.getsize(full)
                                listing += f"-rw-r--r-- 1 ftp ftp {size} Jan 01 00:00 {name}\r\n"
                        try:
                            data_conn.sendall(listing.encode("utf-8"))
                        except OSError:
                            pass
                    try:
                        data_conn.close()
                    except OSError:
                        pass
                self.send("226 Transfer complete.")

            elif cmd == "RETR":
                if not self.logged_in:
                    self.send("530 Not logged in.")
                    continue
                if not self.data_sock:
                    self.send("425 Use PASV first.")
                    continue

                real = self._real_path(arg)
                if real and os.path.isfile(real):
                    self.send("150 Opening data connection.")
                    data_conn = self._accept_data()
                    if data_conn:
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
                else:
                    self.send("550 File not found.")
                    self._accept_data()  # consume pending connection

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
    parser.add_argument("--port", type=int, default=21,
                        help="FTP control port (default: 21)")
    parser.add_argument("--root", type=str, default="./ftp_root",
                        help="Root directory to serve (default: ./ftp_root)")
    parser.add_argument("--bind", type=str, default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")
    args = parser.parse_args()

    # Ensure root directory exists with sample files.
    root = os.path.abspath(args.root)
    os.makedirs(root, exist_ok=True)
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

    # Determine server IP for PASV responses.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        server_ip = s.getsockname()[0]
        s.close()
    except OSError:
        server_ip = "127.0.0.1"

    # Start FTP listener.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(5)

    print(f"[FTP] Vulnerable FTP server listening on {args.bind}:{args.port}")
    print(f"[FTP] Serving files from: {root}")
    print(f"[FTP] Server IP (for PASV): {server_ip}")
    print(f"[FTP] Anonymous login: ENABLED (intentionally vulnerable)")
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
