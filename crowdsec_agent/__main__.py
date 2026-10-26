"""Entry point: python -m crowdsec_agent [--once]"""

from __future__ import annotations

import argparse
import logging
import os

from . import dashboard, health
from .bus import Approvals, BusTool, Runtime, schema, serve_mcp
from .collector import Collector, Snapshot
from .config import Config
from .lapi import Lapi
from .notify import Notifier
from .state import State
from .store import Store

log = logging.getLogger("crowdsec_agent")

SYNC_GRACE = 5 * 60  # longest a sync (a first backfill of HISTORY_DAYS included) should take

HOURS = {"type": "integer", "minimum": 1, "description": "How far back, in hours (default 24)."}


def bus_tools(cfg: Config, runtime: Runtime, store: Store, snapshot: Snapshot) -> list[BusTool]:
    """What the Discord bot may call: all read-only."""
    max_hours = cfg.retention_days * 24

    def clamp(hours: int) -> int:
        return min(max(int(hours), 1), max_hours)

    def summary(hours: int = 24) -> dict:
        view = snapshot.view()
        data = view["metrics"]["data"] or {}
        return {"lapi": view["lapi"], "summary": store.summary(clamp(hours)),
                "activeLocalDecisions": len(view["decisions"]),
                "allActiveDecisions": data.get("decisions"), "appsec": data.get("appsec"),
                "crowdsecVersion": data.get("version")}

    def alerts(hours: int = 24, query: str = "", limit: int = 50) -> dict:
        return {"alerts": store.alerts(clamp(hours), query, min(max(int(limit), 1), 200))}

    def decisions(limit: int = 100) -> dict:
        rows = snapshot.view()["decisions"]
        return {"total": len(rows), "decisions": rows[:min(max(int(limit), 1), 500)]}

    def sources() -> dict:
        data = snapshot.view()["metrics"]["data"] or {}
        return {k: data.get(k) for k in ("version", "startedAt", "sources", "bouncers", "machines", "whitelisted")}

    return runtime.common_tools(check_is_destructive=False) + [
        BusTool("crowdsec_summary", "CrowdSec: alert totals, timeline, top countries/scenarios/AS/targets/IPs for "
                "the last `hours`, plus active decisions by origin and AppSec counters.",
                schema({"hours": HOURS}), summary),
        BusTool("crowdsec_alerts", "CrowdSec: recent alerts, newest first. `query` filters by IP, scenario, "
                "country, AS, target host or URI.",
                schema({"hours": HOURS, "query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1}}),
                alerts),
        BusTool("crowdsec_decisions", "CrowdSec: active local decisions (bans) with country, AS, scenario and "
                "expiry. Community blocklist decisions are only counted, in crowdsec_summary.",
                schema({"limit": {"type": "integer", "minimum": 1}}), decisions),
        BusTool("crowdsec_sources", "CrowdSec: log sources with lines read/parsed/unparsed (notParsing flags a "
                "source none of whose lines parse), bouncer and machine API requests.", schema(), sources),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="CrowdSec dashboard agent")
    parser.add_argument("--once", action="store_true", help="run one sync and exit")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = Config.from_env()
    os.makedirs(os.path.dirname(cfg.db_path) or ".", exist_ok=True)
    state = State(cfg.state_path)
    store = Store(cfg.db_path)
    snapshot = Snapshot()
    lapi = Lapi(cfg.lapi_url, cfg.machine_id, cfg.password)
    collector = Collector(cfg, lapi, store, state, snapshot)
    notifier = Notifier(cfg.notify_urls, cfg.renotify_hours, state, cfg.bot_alert_url, cfg.bus_token)
    runtime = Runtime("crowdsec", revision=_revision())
    health.reset()
    if not args.once:
        info = {"revision": runtime.revision[:12], "pollSeconds": cfg.poll_seconds,
                "retentionDays": cfg.retention_days, "lapiUrl": cfg.lapi_url}
        dashboard.serve(cfg.dashboard_port, store, snapshot, cfg.dashboard_password, cfg.retention_days * 24, info)
        health.endpoint("dashboard", f"http://127.0.0.1:{cfg.dashboard_port}/health")
        if cfg.bus_token and cfg.bus_port:
            # No destructive tools, so no approval channel is needed.
            serve_mcp("0.0.0.0", cfg.bus_port, cfg.bus_token, bus_tools(cfg, runtime, store, snapshot),
                      "crowdsec-agent", Approvals("crowdsec", [], mode="client"))
            health.endpoint("agent bus", f"http://127.0.0.1:{cfg.bus_port}/health")
    log.info("Starting: lapi=%s machine=%s metrics=%s poll=%ss retention=%sd dashboard=:%s auth=%s bus=%s",
             cfg.lapi_url, cfg.machine_id, cfg.metrics_url or "-", cfg.poll_seconds, cfg.retention_days,
             cfg.dashboard_port, bool(cfg.dashboard_password), bool(cfg.bus_token))

    while True:
        health.beat("sync", cfg.poll_seconds + SYNC_GRACE)
        try:
            findings, cleared = collector.run()
            notifier.send(findings, cleared)
            state.save()
            runtime.record(findings, None)
        except Exception:  # keep the daemon alive; next cycle may succeed
            log.exception("Sync crashed")
        if args.once:
            return
        if runtime.wake.wait(cfg.poll_seconds):
            log.info("Sync requested via the agent bus")
        runtime.wake.clear()


def _revision() -> str:
    try:
        with open(os.path.join(os.path.dirname(__file__), "..", "REVISION"), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "dev"


if __name__ == "__main__":
    main()
