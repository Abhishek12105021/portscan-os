"""
Simulated vulnerable HTTP server for lab demonstration.

This server intentionally has a path traversal vulnerability: it does NOT
sanitise ".." sequences in request paths, allowing an attacker to read
files outside the web root.

DO NOT run this outside of an isolated lab environment.

Usage:
    python victim\\http_server.py --port 80 --root ./web_root

Real-world parallel:
    CVE-2021-41773 — Apache 2.4.49 path traversal
    CVE-2021-42013 — Apache 2.4.50 path traversal bypass
"""

import argparse
import datetime
import mimetypes
import os
import socket
import sys
import threading


# Request log lines contain a "→" glyph that the default Windows console
# code page (cp1252) cannot encode; without this the handler thread raises
# UnicodeEncodeError and the client receives an empty response. Force UTF-8
# output with graceful fallback.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


SERVER_NAME = "VulnHTTP/1.0 (Lab Demo)"


class HTTPSession(threading.Thread):
    """Handle a single HTTP request."""

    def __init__(self, client_sock, client_addr, root_dir):
        super().__init__(daemon=True)
        self.sock = client_sock
        self.addr = client_addr
        self.root = os.path.abspath(root_dir)

    def run(self):
        try:
            self.sock.settimeout(10.0)
            request = b""
            while b"\r\n\r\n" not in request and b"\n\n" not in request:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return
                request += chunk
                if len(request) > 16384:
                    break

            text = request.decode("utf-8", errors="replace")
            lines = text.split("\n")
            if not lines:
                return

            # Parse request line.
            parts = lines[0].strip().split(" ")
            if len(parts) < 2:
                self._send_error(400, "Bad Request")
                return

            method = parts[0].upper()
            raw_path = parts[1]

            print(f"[HTTP] {self.addr} → {method} {raw_path}")

            if method not in ("GET", "HEAD"):
                self._send_error(405, "Method Not Allowed")
                return

            # ─── INTENTIONAL VULNERABILITY ───
            # We do NOT sanitise ".." in the path. This allows traversal
            # outside the web root.
            #
            # A safe server would do:
            #     path = os.path.normpath(path)
            #     if not path.startswith(self.root):
            #         return 403
            #
            # We intentionally skip this check.

            # URL-decode common sequences.
            decoded_path = raw_path
            decoded_path = decoded_path.replace("%2f", "/")
            decoded_path = decoded_path.replace("%2F", "/")
            decoded_path = decoded_path.replace("%5c", "\\")
            decoded_path = decoded_path.replace("%5C", "\\")
            decoded_path = decoded_path.replace("%2e", ".")
            decoded_path = decoded_path.replace("%2E", ".")

            # Strip leading slash and join with root.
            rel = decoded_path.lstrip("/")

            # VULNERABLE: os.path.join with ".." sequences!
            file_path = os.path.join(self.root, rel)

            # Try to serve the file.
            if os.path.isfile(file_path):
                self._serve_file(file_path, method)
            elif os.path.isdir(file_path):
                # Serve directory listing.
                index = os.path.join(file_path, "index.html")
                if os.path.isfile(index):
                    self._serve_file(index, method)
                else:
                    self._serve_directory(file_path, raw_path, method)
            else:
                self._send_error(404, "Not Found")

        except (socket.timeout, OSError, Exception) as exc:
            print(f"[HTTP] Error handling {self.addr}: {exc}")
        finally:
            try:
                self.sock.close()
            except OSError:
                pass

    def _send_response(self, status_code, status_text, headers, body=b""):
        """Send an HTTP response."""
        response = f"HTTP/1.0 {status_code} {status_text}\r\n"
        headers["Server"] = SERVER_NAME
        headers["Date"] = datetime.datetime.utcnow().strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        headers["Connection"] = "close"
        for key, value in headers.items():
            response += f"{key}: {value}\r\n"
        response += "\r\n"

        try:
            self.sock.sendall(response.encode("utf-8"))
            if body:
                self.sock.sendall(body)
        except OSError:
            pass

    def _send_error(self, code, text):
        body = f"<html><body><h1>{code} {text}</h1></body></html>".encode()
        self._send_response(code, text, {
            "Content-Type": "text/html",
            "Content-Length": str(len(body)),
        }, body)

    def _serve_file(self, path, method):
        """Serve a file."""
        try:
            with open(path, "rb") as f:
                content = f.read()
        except (OSError, PermissionError):
            self._send_error(403, "Forbidden")
            return

        content_type = mimetypes.guess_type(path)[0] or "application/octet-stream"

        # For text-like files, use text/plain so content is visible.
        if path.endswith((".ini", ".cfg", ".conf", ".txt", ".log", ".passwd")):
            content_type = "text/plain"
        if "passwd" in path or "shadow" in path:
            content_type = "text/plain"

        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(content)),
        }

        if method == "HEAD":
            self._send_response(200, "OK", headers)
        else:
            self._send_response(200, "OK", headers, content)

    def _serve_directory(self, dir_path, url_path, method):
        """Serve a directory listing."""
        entries = sorted(os.listdir(dir_path))
        body = f"<html><head><title>Index of {url_path}</title></head><body>\n"
        body += f"<h1>Index of {url_path}</h1><hr><pre>\n"
        body += '<a href="../">../</a>\n'
        for entry in entries:
            full = os.path.join(dir_path, entry)
            if os.path.isdir(full):
                body += f'<a href="{entry}/">{entry}/</a>\n'
            else:
                size = os.path.getsize(full)
                body += f'<a href="{entry}">{entry}</a>  ({size} bytes)\n'
        body += "</pre><hr></body></html>"
        content = body.encode("utf-8")

        headers = {
            "Content-Type": "text/html",
            "Content-Length": str(len(content)),
        }

        if method == "HEAD":
            self._send_response(200, "OK", headers)
        else:
            self._send_response(200, "OK", headers, content)


def main():
    parser = argparse.ArgumentParser(
        description="Simulated vulnerable HTTP server for lab demos"
    )
    parser.add_argument("--port", type=int, default=80,
                        help="HTTP port (default: 80)")
    parser.add_argument("--root", type=str, default="./web_root",
                        help="Web root directory (default: ./web_root)")
    parser.add_argument("--bind", type=str, default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")
    args = parser.parse_args()

    # Ensure web root exists with sample content.
    root = os.path.abspath(args.root)
    os.makedirs(root, exist_ok=True)

    index = os.path.join(root, "index.html")
    if not os.path.exists(index):
        with open(index, "w") as f:
            f.write("<!DOCTYPE html>\n")
            f.write("<html><head><title>Lab Web Server</title></head>\n")
            f.write("<body>\n")
            f.write("<h1>Welcome to the Lab Web Server</h1>\n")
            f.write("<p>This is a deliberately vulnerable HTTP server.</p>\n")
            f.write("<p>If you can read system files via path traversal, ")
            f.write("the exploit worked!</p>\n")
            f.write("</body></html>\n")

    # Start HTTP listener.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(5)

    print(f"[HTTP] Vulnerable HTTP server listening on {args.bind}:{args.port}")
    print(f"[HTTP] Serving files from: {root}")
    print(f"[HTTP] Server name: {SERVER_NAME}")
    print(f"[HTTP] Path traversal protection: DISABLED (intentionally vulnerable)")
    print(f"[HTTP] Press Ctrl+C to stop.\n")

    try:
        while True:
            client_sock, client_addr = listener.accept()
            session = HTTPSession(client_sock, client_addr, root)
            session.start()
    except KeyboardInterrupt:
        print("\n[HTTP] Server stopped.")
    finally:
        listener.close()


if __name__ == "__main__":
    main()
