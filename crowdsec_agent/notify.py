"""Notifications: Discord embeds, or any Apprise URL as markdown (see notice.py)."""

from __future__ import annotations

import logging

from .bus import push_alert
from .findings import Finding
from .notice import Outbox, digest
from .state import State

log = logging.getLogger(__name__)

AUTHOR = "CrowdSec agent"


class Notifier:
    def __init__(self, urls: list[str], renotify_hours: int, state: State, bot_url: str = "", bot_token: str = ""):
        self.renotify_hours = renotify_hours
        self.state = state
        self.bot_url, self.bot_token = bot_url, bot_token  # Discord bot first, Apprise as fallback
        self.outbox = Outbox(urls)
        self.unsent_cleared: list[str] = []  # recoveries from a digest that wasn't delivered

    def send(self, findings: list[Finding], cleared: list[str] = ()) -> None:
        """One digest per cycle. Open problems repeat every renotify_hours; recoveries go out once.
        Nothing counts as sent until it's delivered."""
        cleared = self.unsent_cleared + [c for c in cleared if c not in self.unsent_cleared]
        fresh = [f for f in findings if not self.state.within("notified", f.key, self.renotify_hours)]
        if not fresh and not cleared:
            return
        msg = digest(AUTHOR, fresh, cleared=list(cleared))
        body = msg.markdown()
        log.info("%s\n%s", msg.title, body)
        delivered = bool(self.bot_url and push_alert(self.bot_url, self.bot_token, "crowdsec", msg.title, body, fresh,
                                                     None)) or self.outbox.send(msg)
        if not delivered:
            self.unsent_cleared = cleared  # open problems are found again next cycle; a recovery isn't
            return
        self.unsent_cleared = []
        for f in fresh:
            self.state.mark("notified", f.key)
