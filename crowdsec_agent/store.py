"""Alert history in SQLite, so the dashboard keeps RETENTION_DAYS even though CrowdSec flushes its own
database sooner (db_config.flush.max_age). One row per alert, keyed by the alert's uuid.
"""

from __future__ import annotations

import functools
import json
import os
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
    decision TEXT, decision_until REAL,
    lat REAL, lon REAL, seen_at REAL, detail TEXT
);
CREATE INDEX IF NOT EXISTS alerts_created ON alerts (created_at);
"""
# Columns added after the first release; older databases get them on open.
ADDED = {"lat": "REAL", "lon": "REAL", "seen_at": "REAL", "detail": "TEXT"}

COLUMNS = ("uuid", "id", "created_at", "scenario", "kind", "message", "machine", "scope", "value", "ip", "cn",
           "as_name", "as_number", "ip_range", "target", "uri", "events", "simulated", "decision", "decision_until",
           "lat", "lon", "detail")
# Left out of alert lists: the detail is fetched per alert (/api/alert), and the machine is in it.
LIST_SKIP = ("machine", "detail")
# The detail keeps this many events per alert (an alert can carry hundreds) and trims long values.
DETAIL_EVENTS, DETAIL_VALUE = 20, 500
# How far back the live feed looks: a first sync stores weeks of alerts at once, and those aren't news.
LIVE_WINDOW = 2 * 3600

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


# Country names for the alert filter: ISO code -> lowercase English names and aliases (Natural Earth).
COUNTRIES = os.path.join(os.path.dirname(__file__), "countries.json")


@functools.cache
def _country_names() -> dict[str, list[str]]:
    try:
        with open(COUNTRIES, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def countries_named(query: str) -> set[str]:
    """Codes of the countries named exactly `query` ("uk", "china"), else those whose name, or a word of
    it, starts with it: "russ" finds Russia, "kingdom" the UK, "us" the USA but not Australia or Belarus."""
    q = query.strip().lower()
    if len(q) < 2:
        return set()
    countries = _country_names()
    exact = {code for code, names in countries.items() if q in names}
    return exact or {code for code, names in countries.items()
                     if any(n.startswith(q) or any(w.startswith(q) for w in re.split(r"[\W_]+", n)) for n in names)}


def category(kind: str, decision: str) -> str:
    """How the map shows an alert: banned (it got a decision), blocked (AppSec stopped the request)
    or flagged (detected, nothing enforced)."""
    return "banned" if decision else "blocked" if kind == "waf" else "flagged"


def _coord(value, limit: float) -> float | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return round(v, 3) if -limit <= v <= limit else None


def _pairs(items: list | None) -> list[list]:
    """A meta list as [key, value] pairs, values trimmed; alert-level values (JSON lists) become lists."""
    out = []
    for m in items or []:
        key, value = m.get("key"), m.get("value")
        if not key or value in (None, ""):
            continue
        if isinstance(value, str) and value.startswith("["):
            try:
                value = [str(v)[:DETAIL_VALUE] for v in json.loads(value)][:10]
            except ValueError:
                pass
        out.append([key, value if isinstance(value, list) else str(value)[:DETAIL_VALUE]])
    return out


def detail(alert: dict, now: float) -> dict:
    """What the table has no room for: timing, the bucket, every decision, the request context and
    the first DETAIL_EVENTS events with their metadata."""
    events = alert.get("events") or []
    return {
        "startedAt": _ts(alert.get("start_at")),
        "stoppedAt": _ts(alert.get("stop_at")),
        "capacity": alert.get("capacity"),
        "leakspeed": alert.get("leakspeed") or "",
        "scenarioVersion": alert.get("scenario_version") or "",
        "context": _pairs(alert.get("meta")),
        "decisions": [{"type": d.get("type", ""), "origin": d.get("origin", ""), "scope": d.get("scope", ""),
                       "value": d.get("value", ""), "duration": go_duration(d.get("duration", "")),
                       "until": now + go_duration(d.get("duration", "")), "simulated": bool(d.get("simulated"))}
                      for d in alert.get("decisions") or []],
        "events": [{"at": _ts(e.get("timestamp")), "meta": _pairs(e.get("meta"))} for e in events[:DETAIL_EVENTS]],
    }


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
    # GeoIP city coordinates; 0,0 means CrowdSec had none (the map then uses the country).
    located = bool(src.get("latitude") or src.get("longitude"))
    lat = _coord(src.get("latitude"), 90) if located else None
    lon = _coord(src.get("longitude"), 180) if located else None
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
        "lat": lat if lon is not None else None,
        "lon": lon if lat is not None else None,
        "detail": json.dumps(detail(alert, now), separators=(",", ":")),
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
        with self.lock, self.db:
            self.db.executescript(SCHEMA)
            have = {r[1] for r in self.db.execute("PRAGMA table_info(alerts)")}
            for col, kind in ADDED.items():
                if col not in have:
                    self.db.execute(f"ALTER TABLE alerts ADD COLUMN {col} {kind}")
            self.db.execute("UPDATE alerts SET seen_at = created_at WHERE seen_at IS NULL")
            self.db.execute("CREATE INDEX IF NOT EXISTS alerts_seen ON alerts (seen_at)")

    def count(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def upsert(self, alerts: list[dict], now: float | None = None) -> int:
        now = now or time.time()
        rows = [row(a, now) for a in alerts]
        # seen_at is when the agent first stored the alert (the live map's cursor); re-reads keep it.
        sql = (f"INSERT INTO alerts ({', '.join(COLUMNS)}, seen_at) VALUES ({', '.join('?' * (len(COLUMNS) + 1))}) "
               f"ON CONFLICT(uuid) DO UPDATE SET {', '.join(f'{c}=excluded.{c}' for c in COLUMNS[1:])}")
        with self.lock, self.db:
            self.db.executemany(sql, [(*(r[c] for c in COLUMNS), now) for r in rows])
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

    def map(self, hours: int, now: float | None = None) -> dict:
        """Alert counts per place for the heat map: per 0.1° cell when CrowdSec had coordinates, else per
        country (the page puts those on the country's centroid)."""
        now = now or time.time()
        with self.lock:
            rows = self.db.execute("SELECT lat, lon, cn, kind, decision FROM alerts WHERE created_at >= ?",
                                   (now - hours * 3600,)).fetchall()
        cells: dict[tuple, dict] = {}
        unlocated = 0
        for r in rows:
            if r["lat"] is not None and r["lon"] is not None:
                key = (round(r["lat"], 1), round(r["lon"], 1))
            elif r["cn"]:
                key = (None, None, r["cn"])
            else:
                unlocated += 1
                continue
            cell = cells.get(key)
            if cell is None:
                cell = cells[key] = {"lat": key[0], "lon": key[1], "cn": r["cn"], "banned": 0, "blocked": 0, "flagged": 0}
            cell[category(r["kind"], r["decision"])] += 1
        return {"hours": hours, "total": len(rows), "unlocated": unlocated, "points": list(cells.values())}

    def live(self, after: float | None, limit: int = 100, now: float | None = None) -> dict:
        """Alerts the agent stored after the cursor `after`, newest first, and the next cursor. Without a
        cursor: the cursor and the latest few alerts, so a page that just opened has a feed but no replay."""
        now = now or time.time()
        cols = "created_at, value, ip, cn, as_name, scenario, kind, decision, target, lat, lon"
        with self.lock:
            cursor = self.db.execute("SELECT MAX(seen_at) FROM alerts").fetchone()[0] or 0
            if after is None:
                rows = self.db.execute(f"SELECT {cols} FROM alerts ORDER BY created_at DESC LIMIT 12").fetchall()
            else:
                rows = self.db.execute(f"SELECT {cols} FROM alerts WHERE seen_at > ? AND created_at >= ? "
                                       "ORDER BY created_at DESC LIMIT ?", (after, now - LIVE_WINDOW, limit)).fetchall()
        events = [{"at": r["created_at"], "source": r["value"] or r["ip"], "cn": r["cn"], "asName": r["as_name"],
                   "scenario": r["scenario"], "target": r["target"], "lat": r["lat"], "lon": r["lon"],
                   "category": category(r["kind"], r["decision"])} for r in rows]
        return {"cursor": cursor, "events": events}

    def alert(self, uuid: str) -> dict | None:
        """One alert with everything stored about it; `detail` is None for alerts stored before it existed."""
        with self.lock:
            r = self.db.execute("SELECT * FROM alerts WHERE uuid = ?", (uuid,)).fetchone()
        if r is None:
            return None
        out = {c: r[c] for c in COLUMNS}
        out["detail"] = json.loads(r["detail"]) if r["detail"] else None
        return out

    def alerts(self, hours: int, query: str = "", limit: int = 500, now: float | None = None,
               detail: bool = False, offset: int = 0) -> list[dict]:
        """Alerts in the range, newest first; with `detail`, also the machine and the parsed detail."""
        return self.page(hours, query, limit, offset, now, detail)["alerts"]

    def page(self, hours: int, query: str = "", limit: int = 50, offset: int = 0, now: float | None = None,
             detail: bool = False) -> dict:
        """One page of the alerts matching `query`, newest first, and how many match in all."""
        now = now or time.time()
        q = query.strip().lower()
        named = countries_named(q)
        out, total = [], 0
        for r in self._since(hours, now):
            if q and (r["cn"] or "").upper() not in named and not any(q in str(r[c] or "").lower() for c in
                             ("ip", "value", "scenario", "cn", "as_name", "as_number", "target", "uri", "message")):
                continue
            if offset <= total < offset + limit:
                item = {c: r[c] for c in COLUMNS if c not in LIST_SKIP}
                if detail:
                    item["machine"] = r["machine"]
                    item["detail"] = json.loads(r["detail"]) if r["detail"] else None
                out.append(item)
            total += 1
        return {"alerts": out, "total": total, "offset": offset}
