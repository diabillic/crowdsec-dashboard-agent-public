"""Environment-driven configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw and raw.strip() else default


def _list(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]


@dataclass
class Config:
    # CrowdSec Local API, read as a registered machine (watcher): `cscli machines add`
    lapi_url: str
    machine_id: str
    password: str
    # CrowdSec's Prometheus endpoint (prometheus.enabled, level full); empty: no runtime metrics
    metrics_url: str = ""

    poll_seconds: int = 60
    history_days: int = 30  # how far back the first sync reads
    retention_days: int = 90  # alerts are kept here this long, even after CrowdSec flushes them
    state_path: str = "/data/state.json"
    db_path: str = ""

    # The web dashboard (read-only). Basic auth when a password is set.
    dashboard_port: int = 8080
    dashboard_password: str = ""

    notify_urls: list[str] = field(default_factory=list)
    renotify_hours: int = 12
    down_minutes: int = 10  # CrowdSec must be unreachable this long before it's reported

    # Agent bus: MCP endpoint for the Discord bot, and where to hand it alerts
    bus_token: str = ""
    bus_port: int = 8765
    bot_alert_url: str = ""

    def __post_init__(self) -> None:
        if not self.db_path:
            self.db_path = os.path.join(os.path.dirname(self.state_path) or ".", "alerts.db")

    @classmethod
    def from_env(cls) -> "Config":
        url = os.environ.get("CROWDSEC_LAPI_URL", "").strip()
        password = os.environ.get("CROWDSEC_PASSWORD", "").strip()
        if not url or not password:
            raise SystemExit("CROWDSEC_LAPI_URL and CROWDSEC_PASSWORD are required")
        return cls(
            lapi_url=url.rstrip("/"),
            machine_id=os.environ.get("CROWDSEC_MACHINE_ID", "").strip() or "crowdsec-dashboard",
            password=password,
            metrics_url=os.environ.get("CROWDSEC_METRICS_URL", "").strip(),
            poll_seconds=max(15, _int("POLL_SECONDS", 60)),
            history_days=_int("HISTORY_DAYS", 30),
            retention_days=_int("RETENTION_DAYS", 90),
            state_path=os.environ.get("STATE_PATH", "/data/state.json"),
            db_path=os.environ.get("DB_PATH", "").strip(),
            dashboard_port=_int("DASHBOARD_PORT", 8080),
            dashboard_password=os.environ.get("DASHBOARD_PASSWORD", "").strip(),
            notify_urls=_list("NOTIFY_URLS"),
            renotify_hours=_int("RENOTIFY_HOURS", 12),
            down_minutes=_int("DOWN_MINUTES", 10),
            bus_token=os.environ.get("AGENT_BUS_TOKEN", "").strip(),
            bus_port=_int("AGENT_BUS_PORT", 8765),
            bot_alert_url=os.environ.get("BOT_ALERT_URL", "").strip(),
        )
