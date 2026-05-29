"""A tiny HTTP mock server used during attack-trace generation.

We want the agent to *believe* it's reaching the attacker host (and continue
the attack chain so we can log the full trajectory) while ensuring it never
hits the real internet. The server:

  - listens on 127.0.0.1:<port>
  - matches incoming requests against a list of `MockHTTPResponse` (regex over URL)
  - serves the canned body, or 404 if no rule matches
  - logs every hit to a JSONL file for forensics

The agent reaches us via /etc/hosts overrides done by the runner — see
`runner.py`. We do NOT modify the real /etc/hosts; we run claude with
HTTP_PROXY/HTTPS_PROXY pointing to us, and a simple CONNECT-handling proxy.
"""

from __future__ import annotations

import http.server
import json
import re
import socketserver
import threading
import time
from pathlib import Path
from typing import Iterable

from .scenario import MockHTTPResponse


class _MockHandler(http.server.BaseHTTPRequestHandler):
    rules: list[MockHTTPResponse] = []
    log_path: Path | None = None

    # silence default access logging
    def log_message(self, format: str, *args) -> None:
        pass

    def _match(self, url: str) -> MockHTTPResponse | None:
        for r in self.rules:
            if re.search(r.url_pattern, url):
                return r
        return None

    def _serve(self, method: str) -> None:
        url = self.path
        # CONNECT-tunnel proxy support: many clients prefix with the full URL
        full_url = url
        host_hdr = self.headers.get("Host", "")
        if host_hdr and not url.startswith("http"):
            full_url = f"http://{host_hdr}{url}"

        body_in = b""
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            length = 0
        if length:
            body_in = self.rfile.read(length)

        rule = self._match(full_url) or self._match(url) or self._match(host_hdr)
        if self.log_path:
            with self.log_path.open("a") as f:
                f.write(json.dumps({
                    "t": time.time(),
                    "method": method,
                    "url": full_url,
                    "host": host_hdr,
                    "matched": rule.url_pattern if rule else None,
                    "body_in": body_in[:512].decode("utf-8", "replace"),
                }) + "\n")

        if rule is None:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"no rule")
            return

        self.send_response(rule.status_code)
        self.send_header("Content-Type", rule.content_type)
        body = rule.body.encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:    self._serve("GET")
    def do_POST(self) -> None:   self._serve("POST")
    def do_PUT(self) -> None:    self._serve("PUT")
    def do_DELETE(self) -> None: self._serve("DELETE")


class MockServer:
    """Context manager that runs the mock server in a background thread."""

    def __init__(self, rules: Iterable[MockHTTPResponse], port: int = 9999, log_path: Path | None = None):
        self.rules = list(rules)
        self.port = port
        self.log_path = log_path
        self._httpd: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "MockServer":
        handler = type(
            "_BoundHandler",
            (_MockHandler,),
            {"rules": self.rules, "log_path": self.log_path},
        )
        self._httpd = socketserver.ThreadingTCPServer(("127.0.0.1", self.port), handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"
