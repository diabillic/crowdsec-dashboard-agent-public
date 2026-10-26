"""The web dashboard: a static page (web/) plus a small read-only JSON API.

  GET /                       the dashboard
  GET /api/overview?hours=24  status, alert summary for the range, active decisions, metrics
  GET /api/alerts?hours=24&q= alerts in the range, newest first, optionally filtered
  GET /health                 200 while the server runs (container health; never needs auth)

Basic auth guards everything but /health when DASHBOARD_PASSWORD is set (any user name).
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .collector import Snapshot
from .store import Store

log = logging.getLogger(__name__)

WEB = os.path.join(os.path.dirname(__file__), "web")
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8"),
          "/favicon.svg": ("favicon.svg", "image/svg+xml")}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def overview(store: Store, snapshot: Snapshot, hours: int, info: dict) -> dict:
    view = snapshot.view()
    metrics = view["metrics"]
    return {
        "generatedAt": time.time(),
        "agent": info,
        "lapi": view["lapi"],
        "metrics": {k: metrics[k] for k in ("ok", "error", "at")},
        "crowdsec": metrics["data"],
        "decisions": view["decisions"][:500],
        "decisionsTotal": len(view["decisions"]),
        "summary": store.summary(hours),
    }


def make_handler(store: Store, snapshot: Snapshot, password: str, max_hours: int, info: dict):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "crowdsec-dashboard"
        sys_version = ""

        def log_message(self, fmt, *args):
            log.debug("web %s - " + fmt, self.address_string(), *args)

        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, data) -> None:
            self._send(status, json.dumps(data, default=str).encode(), "application/json")

        def _authorized(self) -> bool:
            if not password:
                return True
            header = self.headers.get("Authorization", "")
            if not header.startswith("Basic "):
                return False
            try:
                supplied = base64.b64decode(header[6:]).decode().partition(":")[2]
            except ValueError:
                return False
            return hmac.compare_digest(supplied.encode(), password.encode())

        def _hours(self, params: dict) -> int:
            try:
                hours = int((params.get("hours") or ["24"])[0])
            except ValueError:
                hours = 24
            return min(max(hours, 1), max_hours)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/health":
                return self._json(200, {"ok": True})
            if not self._authorized():
                return self._send(401, b"authentication required", "text/plain",
                                  {"WWW-Authenticate": 'Basic realm="CrowdSec dashboard", charset="UTF-8"'})
            params = parse_qs(url.query)
            try:
                if url.path in STATIC:
                    name, ctype = STATIC[url.path]
                    with open(os.path.join(WEB, name), "rb") as fh:
                        return self._send(200, fh.read(), ctype)
                if url.path == "/api/overview":
                    return self._json(200, overview(store, snapshot, self._hours(params), info))
                if url.path == "/api/alerts":
                    query = (params.get("q") or [""])[0][:200]
                    try:
                        limit = min(max(int((params.get("limit") or ["500"])[0]), 1), 2000)
                    except ValueError:
                        limit = 500
                    return self._json(200, {"alerts": store.alerts(self._hours(params), query, limit)})
            except Exception:  # keep serving; the page shows the error
                log.exception("web %s failed", url.path)
                return self._json(500, {"error": "internal error, see the agent's log"})
            return self._json(404, {"error": "not found"})

    return Handler


def serve(port: int, store: Store, snapshot: Snapshot, password: str, max_hours: int, info: dict,
          host: str = "0.0.0.0") -> ThreadingHTTPServer:
    """Start the dashboard on a daemon thread; returns the server (call .shutdown() to stop)."""
    server = ThreadingHTTPServer((host, port), make_handler(store, snapshot, password, max_hours, info))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="dashboard", daemon=True).start()
    log.info("Dashboard on %s:%s (auth %s)", host, server.server_address[1], "on" if password else "off")
    return server
