"""One sync cycle: read CrowdSec's metrics and alerts, keep the history, report CrowdSec down/up.

The first sync reads HISTORY_DAYS of alerts; later ones read what started since the last sync plus
an overlap (an alert's start can precede its creation by a bucket's lifetime). Active decisions are
re-read every cycle, so expired or deleted ones drop off the dashboard straight away.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

import requests

from . import metrics as prom
from .config import Config
from .findings import Finding
from .lapi import Lapi, LapiError
from .state import State
from .store import Store, decision_rows

log = logging.getLogger(__name__)

OVERLAP = 3600
PRUNE_EVERY = 86400


class Snapshot:
    """The latest view of CrowdSec, shared by the sync loop (writer) and the web/bus threads (readers)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict = {"lapi": {"ok": None, "error": "", "syncedAt": None},
                            "metrics": {"ok": None, "error": "", "at": None, "data": None},
                            "decisions": [], "decisionsAt": None}

    def update(self, **parts) -> None:
        with self._lock:
            self._data.update(parts)

    def view(self) -> dict:
        with self._lock:
            return dict(self._data)


class Collector:
    def __init__(self, cfg: Config, lapi: Lapi, store: Store, state: State, snapshot: Snapshot,
                 fetch_metrics: Callable[[str], list] = prom.fetch):
        self.cfg, self.lapi, self.store, self.state, self.snapshot = cfg, lapi, store, state, snapshot
        self.fetch_metrics = fetch_metrics

    def run(self, now: float | None = None) -> tuple[list[Finding], list[str]]:
        """(open problems, recoveries) for this cycle."""
        now = now or time.time()
        findings, cleared = [], []

        if self.cfg.metrics_url:
            try:
                data = prom.summarize(self.fetch_metrics(self.cfg.metrics_url))
                self.snapshot.update(metrics={"ok": True, "error": "", "at": now, "data": data})
                self._outage("crowdsec:metrics", "CrowdSec's metrics endpoint", None, now, findings, cleared)
            except (requests.RequestException, ValueError) as exc:
                old = self.snapshot.view()["metrics"]
                self.snapshot.update(metrics={**old, "ok": False, "error": str(exc)})
                self._outage("crowdsec:metrics", "CrowdSec's metrics endpoint", exc, now, findings, cleared)

        try:
            self._sync_alerts(now)
            self.snapshot.update(lapi={"ok": True, "error": "", "syncedAt": now})
            self._outage("crowdsec:lapi", f"CrowdSec's Local API ({self.cfg.lapi_url})", None, now, findings, cleared)
        except (requests.RequestException, LapiError, ValueError) as exc:
            log.warning("Alert sync failed: %s", exc)
            old = self.snapshot.view()["lapi"]
            self.snapshot.update(lapi={**old, "ok": False, "error": str(exc)})
            self._outage("crowdsec:lapi", f"CrowdSec's Local API ({self.cfg.lapi_url})", exc, now, findings, cleared)

        if now - self.state["progress"].get("pruned_at", 0) >= PRUNE_EVERY:
            removed = self.store.prune(self.cfg.retention_days, now)
            self.state.mark("progress", "pruned_at", now)
            if removed:
                log.info("Pruned %d alert(s) older than %d days", removed, self.cfg.retention_days)
        return findings, cleared

    def _sync_alerts(self, now: float) -> None:
        last = self.state["progress"].get("synced_at")
        if last and self.store.count():
            since = now - last + OVERLAP
        else:
            since = self.cfg.history_days * 86400
        alerts = self.lapi.alerts(since_seconds=int(since))
        stored = self.store.upsert(alerts, now)
        active = self.lapi.alerts(active=True)
        self.snapshot.update(decisions=decision_rows(active, now), decisionsAt=now)
        self.state.mark("progress", "synced_at", now)
        log.debug("Synced %d alert(s) from the last %ds; %d with active decisions", stored, since, len(active))

    def _outage(self, key: str, what: str, error: Exception | None, now: float,
                findings: list[Finding], cleared: list[str]) -> None:
        """Report `what` once it has been failing for DOWN_MINUTES, and its recovery if that was reported."""
        if error is None:
            self.state["first_seen"].pop(key, None)
            if self.state["notified"].pop(key, None) is not None:
                cleared.append(f"{what} is reachable again")
            return
        down_for = now - self.state.first_seen(key, now)
        if down_for >= self.cfg.down_minutes * 60:
            findings.append(Finding(key, f"{what} has failed for {down_for / 60:.0f} min: {error}", "error"))
