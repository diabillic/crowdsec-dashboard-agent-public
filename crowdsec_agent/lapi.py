"""CrowdSec Local API client, logged in as a machine (watcher). Read-only: GETs alerts only.

A machine logs in with its id and password (POST /v1/watchers/login) and gets a JWT that expires
after a while; a 401 means log in again. Alerts carry their decisions, so active decisions come
from /v1/alerts?has_active_decision=true. Community blocklist (CAPI) and list alerts are left out:
they hold tens of thousands of decisions and are counted from the metrics instead.
"""

from __future__ import annotations

import re

import requests


class LapiError(Exception):
    pass


class Lapi:
    def __init__(self, url: str, machine_id: str, password: str, timeout: float = 30,
                 session: requests.Session | None = None):
        self.url = url.rstrip("/")
        self.machine_id, self.password, self.timeout = machine_id, password, timeout
        self.http = session or requests.Session()
        self.http.headers["User-Agent"] = "crowdsec-dashboard-agent"
        self.token = ""

    def login(self) -> None:
        resp = self.http.post(f"{self.url}/v1/watchers/login", timeout=self.timeout,
                              json={"machine_id": self.machine_id, "password": self.password, "scenarios": []})
        if resp.status_code in (401, 403):
            raise LapiError(f"login as machine {self.machine_id!r} was refused (HTTP {resp.status_code}): "
                            "check CROWDSEC_MACHINE_ID / CROWDSEC_PASSWORD and `cscli machines list`")
        resp.raise_for_status()
        self.token = (resp.json() or {}).get("token") or ""
        if not self.token:
            raise LapiError("login answered without a token")

    def _get(self, path: str, params: dict) -> object:
        for attempt in (1, 2):
            if not self.token:
                self.login()
            resp = self.http.get(f"{self.url}{path}", params=params, timeout=self.timeout,
                                 headers={"Authorization": f"Bearer {self.token}"})
            if resp.status_code == 401 and attempt == 1:  # token expired
                self.token = ""
                continue
            resp.raise_for_status()
            return resp.json()
        raise LapiError("unauthorized after logging in again")

    def alerts(self, since_seconds: int | None = None, active: bool = False) -> list[dict]:
        """Alerts started in the last `since_seconds` (all when None); only those with an active
        decision when `active`. Simulated alerts are included (they're flagged)."""
        params = {"include_capi": "false", "simulated": "true", "limit": "0"}
        if since_seconds is not None:
            params["since"] = f"{max(1, int(since_seconds))}s"
        if active:
            params["has_active_decision"] = "true"
        return self._get("/v1/alerts", params) or []

    def healthy(self) -> bool:
        try:
            return self.http.get(f"{self.url}/health", timeout=10).ok
        except requests.RequestException:
            return False


_UNITS = {"h": 3600, "m": 60, "s": 1, "ms": 0.001, "us": 1e-6, "µs": 1e-6, "ns": 1e-9}


def go_duration(text: str) -> float:
    """Seconds in a Go duration string such as '3h48m36.5s' or '-1h2m' (0 when unparseable)."""
    text = (text or "").strip()
    sign = -1 if text.startswith("-") else 1
    parts = re.findall(r"([\d.]+)(ns|us|µs|ms|h|m|s)", text)
    return sign * sum(float(n) * _UNITS[u] for n, u in parts)
