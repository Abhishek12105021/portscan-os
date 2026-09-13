"""
Simulated vulnerable HTTP server for lab demonstration.

INTENTIONAL VULNERABILITIES (for lab use only):
    - Path traversal (no ".." sanitisation) — CVE-2021-41773 analogue
    - CGI execution for .py files inside any "uploads" folder
      (enables the FTP-write → web-shell → RCE chain)

DO NOT run this outside an isolated lab environment.

Usage:
    python victim\\http_server.py --port 80 --root ./lab_root
"""

import argparse
import datetime
import mimetypes
import os
import socket
import subprocess
import sys
import threading


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

    # ----------------------------------------------------------------- CGI

    def _try_cgi(self, file_path, raw_path, method):
        """
        Execute .py files inside an uploads/ directory as CGI.

        Returns True if the request was handled here, False otherwise.
        """
        if not file_path.lower().endswith(".py"):
            return False

        norm = file_path.replace("\\", "/")
        components = [p.lower() for p in norm.split("/")]
        if "uploads" not in components:
            return False

        # Split off query string.
        query = ""
        if "?" in raw_path:
            query = raw_path.split("?", 1)[1]

        env = os.environ.copy()
        env["QUERY_STRING"] = query
        env["REQUEST_METHOD"] = method
        env["SCRIPT_FILENAME"] = file_path
        env["SERVER_PROTOCOL"] = "HTTP/1.0"
        env["GATEWAY_INTERFACE"] = "CGI/1.1"

        try:
            result = subprocess.run(
                [sys.executable, "-u", file_path],
                capture_output=True, timeout=10, env=env,
            )
        except subprocess.TimeoutExpired:
            self._send_error(504, "CGI Timeout")
            return True
        except OSError as exc:
            self._send_error(500, f"CGI error: {exc}")
            return True

        output = result.stdout or b""

        # Split CGI headers from body.
        sep = output.find(b"\r\n\r\n")
        offset = 4
        if sep == -1:
            sep = output.find(b"\n\n")
            offset = 2
        if sep == -1:
            headers = {"Content-Type": "text/plain"}
            body = output
        else:
            header_bytes = output[:sep]
            body = output[sep + offset:]
            headers = {"Content-Type": "text/plain"}
            for line in header_bytes.decode("utf-8", errors="replace").split("\n"):
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()

        headers["Content-Length"] = str(len(body))
        self._send_response(200, "OK", headers, body)
        print(f"[HTTP] {self.addr} → CGI executed "
              f"{os.path.basename(file_path)} (query={query!r})")
        return True

    # ------------------------------------------------------------ Main run

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

            # Split query string from URL before mapping to filesystem.
            url_path = raw_path.split("?", 1)[0]

            # INTENTIONAL VULNERABILITY: no ".." sanitisation here.
            decoded_path = url_path
            for enc, dec in (("%2f", "/"), ("%2F", "/"),
                             ("%5c", "\\"), ("%5C", "\\"),
                             ("%2e", "."), ("%2E", ".")):
                decoded_path = decoded_path.replace(enc, dec)

            rel = decoded_path.lstrip("/")
            file_path = os.path.join(self.root, rel)

            # CGI first — only fires for .py under uploads/.
            if os.path.isfile(file_path) and \
               self._try_cgi(file_path, raw_path, method):
                return

            if os.path.isfile(file_path):
                self._serve_file(file_path, method)
            elif os.path.isdir(file_path):
                index = os.path.join(file_path, "index.html")
                if os.path.isfile(index):
                    self._serve_file(index, method)
                else:
                    self._serve_directory(file_path, url_path, method)
            else:
                self._send_error(404, "Not Found")

        except (socket.timeout, OSError, Exception) as exc:
            print(f"[HTTP] Error handling {self.addr}: {exc}")
        finally:
            try:
                self.sock.close()
            except OSError:
                pass

    # -------------------------------------------------------- HTTP plumbing

    def _send_response(self, status_code, status_text, headers, body=b""):
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
        try:
            with open(path, "rb") as f:
                content = f.read()
        except (OSError, PermissionError):
            self._send_error(403, "Forbidden")
            return

        content_type = mimetypes.guess_type(path)[0] or "application/octet-stream"
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
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--root", type=str, default="./lab_root")
    parser.add_argument("--bind", type=str, default="0.0.0.0")
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    os.makedirs(root, exist_ok=True)
    os.makedirs(os.path.join(root, "uploads"), exist_ok=True)

    index = os.path.join(root, "index.html")
    if not os.path.exists(index):
        with open(index, "w") as f:
            f.write("<!DOCTYPE html>\n")
            f.write("<html><head><title>Lab Web Server</title></head>\n")
            f.write("<body>\n")
            f.write("<h1>Welcome to the Lab Web Server</h1>\n")
            f.write("<p>Deliberately vulnerable HTTP server.</p>\n")
            f.write("<p>Path traversal and CGI in uploads/ are enabled.</p>\n")
            f.write("</body></html>\n")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(5)

    print(f"[HTTP] Vulnerable HTTP server listening on {args.bind}:{args.port}")
    print(f"[HTTP] Root: {root}")
    print(f"[HTTP] Server name: {SERVER_NAME}")
    print(f"[HTTP] Path traversal protection: DISABLED (intentionally)")
    print(f"[HTTP] CGI execution: ENABLED for uploads/*.py")
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