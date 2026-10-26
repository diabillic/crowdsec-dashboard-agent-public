"""Alert history in SQLite, so the dashboard keeps RETENTION_DAYS even though CrowdSec flushes its own
database sooner (db_config.flush.max_age). One row per alert, keyed by the alert's uuid.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from collections import Counter
from datetime import datetime, timezone

from .lapi import go_duration

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    uuid TEXT PRIMARY KEY,
    id INTEGER,
    created_at REAL NOT NULL,
    scenario TEXT, kind TEXT, message TEXT, machine TEXT,
    scope TEXT, value TEXT, ip TEXT, cn TEXT, as_name TEXT, as_number TEXT, ip_range TEXT,
    target TEXT, uri TEXT, events INTEGER, simulated INTEGER,
    decision TEXT, decision_until REAL
);
CREATE INDEX IF NOT EXISTS alerts_created ON alerts (created_at);
"""

COLUMNS = ("uuid", "id", "created_at", "scenario", "kind", "message", "machine", "scope", "value", "ip", "cn",
           "as_name", "as_number", "ip_range", "target", "uri", "events", "simulated", "decision", "decision_until")

# Bucket width for the timeline by range: hourly up to 2 days, 6-hourly up to 10, then daily.
def bucket_seconds(hours: int) -> int:
    return 3600 if hours <= 48 else 6 * 3600 if hours <= 240 else 86400


def _ts(text: str | None) -> float | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _meta(items: list | None, key: str) -> str:
    for m in items or []:
        if m.get("key") == key and m.get("value"):
            value = m["value"]
            if value.startswith("["):  # alert-level meta holds JSON lists
                try:
                    values = json.loads(value)
                    return ", ".join(str(v) for v in values[:3]) if isinstance(values, list) else value
                except ValueError:
                    pass
            return value
    return ""


def row(alert: dict, now: float) -> dict:
    """The stored shape of one LAPI alert."""
    src = alert.get("source") or {}
    events = alert.get("events") or []
    target = _meta(alert.get("meta"), "target_fqdn") or next(
        (v for v in (_meta(e.get("meta"), "target_fqdn") for e in events) if v), "")
    target = re.sub(r":(443|80)$", "", target)  # the same site, whether or not the Host header had a port
    uri = _meta(alert.get("meta"), "target_uri") or next(
        (v for v in (_meta(e.get("meta"), "uri") or _meta(e.get("meta"), "http_path") for e in events) if v), "")
    decisions = [d for d in alert.get("decisions") or [] if not d.get("simulated")]
    first = decisions[0] if decisions else {}
    created = _ts(alert.get("created_at")) or _ts(alert.get("start_at")) or now
    return {
        "uuid": alert.get("uuid") or f"id-{alert.get('id')}-{created}",
        "id": alert.get("id"),
        "created_at": created,
        "scenario": alert.get("scenario") or "",
        "kind": alert.get("kind") or ("crowdsec" if decisions else ""),
        "message": alert.get("message") or "",
        "machine": alert.get("machine_id") or "",
        "scope": src.get("scope") or "",
        "value": src.get("value") or "",
        "ip": src.get("ip") or "",
        "cn": src.get("cn") or "",
        "as_name": src.get("as_name") or "",
        "as_number": str(src.get("as_number") or ""),
        "ip_range": src.get("range") or "",
        "target": target,
        "uri": uri[:300],
        "events": alert.get("events_count") or len(events),
        "simulated": 1 if alert.get("simulated") else 0,
        "decision": first.get("type") or "",
        "decision_until": now + go_duration(first.get("duration", "")) if first else None,
    }


def decision_rows(alerts: list[dict], now: float) -> list[dict]:
    """Active decisions, one per decision, with the source details of the alert that made it."""
    out = []
    for alert in alerts:
        src = alert.get("source") or {}
        for d in alert.get("decisions") or []:
            remaining = go_duration(d.get("duration", ""))
            if remaining <= 0:
                continue
            out.append({
                "id": d.get("id"), "type": d.get("type", ""), "scope": d.get("scope", ""), "value": d.get("value", ""),
                "origin": d.get("origin", ""), "scenario": d.get("scenario") or alert.get("scenario", ""),
                "simulated": bool(d.get("simulated")), "until": now + remaining,
                "cn": src.get("cn") or "", "asName": src.get("as_name") or "", "alertId": alert.get("id"),
                "createdAt": _ts(alert.get("created_at")),
            })
    out.sort(key=lambda d: -(d["createdAt"] or 0))
    return out


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript(SCHEMA)

    def count(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def upsert(self, alerts: list[dict], now: float | None = None) -> int:
        now = now or time.time()
        rows = [row(a, now) for a in alerts]
        sql = (f"INSERT INTO alerts ({', '.join(COLUMNS)}) VALUES ({', '.join('?' * len(COLUMNS))}) "
               f"ON CONFLICT(uuid) DO UPDATE SET {', '.join(f'{c}=excluded.{c}' for c in COLUMNS[1:])}")
        with self.lock, self.db:
            self.db.executemany(sql, [tuple(r[c] for c in COLUMNS) for r in rows])
        return len(rows)

    def prune(self, retention_days: int, now: float | None = None) -> int:
        cutoff = (now or time.time()) - retention_days * 86400
        with self.lock, self.db:
            return self.db.execute("DELETE FROM alerts WHERE created_at < ?", (cutoff,)).rowcount

    def _since(self, hours: int, now: float) -> list[sqlite3.Row]:
        with self.lock:
            return self.db.execute("SELECT * FROM alerts WHERE created_at >= ? ORDER BY created_at DESC",
                                   (now - hours * 3600,)).fetchall()

    def summary(self, hours: int, now: float | None = None) -> dict:
        now = now or time.time()
        rows = self._since(hours, now)
        width = bucket_seconds(hours)
        # Buckets aligned to local time, so daily bars start at midnight where the agent runs.
        offset = datetime.fromtimestamp(now).astimezone().utcoffset().total_seconds()
        last = int((now + offset) // width * width - offset)
        starts = list(range(last - (int(hours * 3600) // width - 1) * width, last + width, width))
        kinds = ("waf", "scenario")
        series = {k: [0] * len(starts) for k in kinds}
        for r in rows:
            i = int((r["created_at"] - starts[0]) // width)
            if 0 <= i < len(starts):
                series["waf" if r["kind"] == "waf" else "scenario"][i] += 1

        def top(key, n=10) -> list[dict]:
            counts = Counter(r[key] for r in rows if r[key])
            return [{"name": k, "count": v} for k, v in counts.most_common(n)]

        countries = Counter(r["cn"] for r in rows if r["cn"])
        as_names = Counter(f"{r['as_name']} (AS{r['as_number']})" if r["as_number"] else r["as_name"]
                           for r in rows if r["as_name"])
        return {
            "hours": hours,
            "total": len(rows),
            "uniqueSources": len({r["value"] or r["ip"] for r in rows}),
            "countries": len(countries),
            "withDecision": sum(1 for r in rows if r["decision"]),
            "waf": sum(1 for r in rows if r["kind"] == "waf"),
            "simulated": sum(1 for r in rows if r["simulated"]),
            "timeline": {"bucketSeconds": width, "starts": starts, "series": series},
            "topCountries": [{"name": k, "count": v} for k, v in countries.most_common(10)],
            "topScenarios": top("scenario"),
            "topAS": [{"name": k, "count": v} for k, v in as_names.most_common(10)],
            "topTargets": top("target"),
            "topSources": top("ip"),
        }

    def alerts(self, hours: int, query: str = "", limit: int = 500, now: float | None = None) -> list[dict]:
        now = now or time.time()
        q = query.strip().lower()
        out = []
        for r in self._since(hours, now):
            if q and not any(q in str(r[c] or "").lower() for c in
                             ("ip", "value", "scenario", "cn", "as_name", "as_number", "target", "uri", "message")):
                continue
            out.append({c: r[c] for c in COLUMNS if c not in ("machine",)})
            if len(out) >= limit:
                break
        return out
