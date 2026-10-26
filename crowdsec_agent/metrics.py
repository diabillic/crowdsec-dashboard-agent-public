"""CrowdSec's Prometheus endpoint, boiled down to what the dashboard shows.

Counters are cumulative since CrowdSec last started (process_start_time_seconds says when).
"""

from __future__ import annotations

import os
import re
from collections import defaultdict

import requests

_LINE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)')
_LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')
# Datasource read counters: cs_filesource_hits_total, cs_dockersource_hits_total, cs_syslogsource_hits_total...
_SOURCE_HITS = re.compile(r"^cs_[a-z]+source_hits_total$")


def parse(text: str) -> list[tuple[str, dict, float]]:
    out = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = _LINE.match(line)
        if not m:
            continue
        try:
            value = float(m.group(3))
        except ValueError:
            continue
        labels = {k: v.replace('\\"', '"').replace("\\\\", "\\") for k, v in _LABEL.findall(m.group(2) or "")}
        out.append((m.group(1), labels, value))
    return out


def fetch(url: str, timeout: float = 20) -> list[tuple[str, dict, float]]:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return parse(resp.text)


def _top(counts: dict[str, float], n: int = 10) -> list[dict]:
    return [{"name": k, "count": int(v)} for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:n] if v]


def summarize(samples: list[tuple[str, dict, float]]) -> dict:
    version, started = "", None
    decisions_by_origin: dict[str, float] = defaultdict(float)
    decisions_by_reason: dict[str, float] = defaultdict(float)
    read: dict[str, float] = defaultdict(float)
    kind: dict[str, str] = {}
    parsed_ok: dict[str, float] = defaultdict(float)
    parsed_ko: dict[str, float] = defaultdict(float)
    parsed_total: dict[str, float] = defaultdict(float)
    bouncers: dict[str, float] = defaultdict(float)
    machines: dict[str, float] = defaultdict(float)
    rule_hits: dict[str, float] = defaultdict(float)
    appsec_reqs = appsec_blocked = whitelisted = overflowed = 0.0

    for name, labels, value in samples:
        src = labels.get("source", "")
        if name == "cs_info":
            version = labels.get("version", "")
        elif name == "process_start_time_seconds":
            started = value
        elif name == "cs_active_decisions":
            decisions_by_origin[labels.get("origin", "?")] += value
            decisions_by_reason[f"{labels.get('origin', '?')}: {labels.get('reason', '?')}"] += value
        elif _SOURCE_HITS.match(name):
            read[src] += value
            kind[src] = labels.get("acquis_type") or labels.get("datasource_type") or ""
        elif name == "cs_parser_hits_ok_total":
            parsed_ok[src] += value
            kind.setdefault(src, labels.get("acquis_type") or labels.get("type") or "")
        elif name == "cs_parser_hits_ko_total":
            parsed_ko[src] += value
        elif name == "cs_parser_hits_total":
            parsed_total[src] += value
        elif name == "cs_lapi_bouncer_requests_total":
            bouncers[labels.get("bouncer", "?")] += value
        elif name == "cs_lapi_machine_requests_total":
            machines[labels.get("machine", "?")] += value
        elif name == "cs_appsec_reqs_total":
            appsec_reqs += value
        elif name == "cs_appsec_block_total":
            appsec_blocked += value
        elif name == "cs_appsec_rule_hits":
            rule_hits[labels.get("rule_name", "?")] += value
        elif name == "cs_node_wl_hits_ok_total":
            whitelisted += value
        elif name == "cs_bucket_overflowed_total":
            overflowed += value

    sources = []
    for src in sorted(set(read) | set(parsed_total) | set(parsed_ok)):
        lines = read.get(src) or parsed_total.get(src, 0)
        ok, ko = parsed_ok.get(src, 0), parsed_ko.get(src, 0)
        # Web server error-log parsers keep only the lines scenarios use (failed logins, rate limits),
        # so an error log with nothing parsed is normal.
        error_log = "error" in os.path.basename(src).lower()
        sources.append({
            "source": src, "type": kind.get(src, ""), "read": int(lines), "parsed": int(ok), "unparsed": int(ko),
            "errorLog": error_log,
            # Lines arriving but none parsing means the parser for this log type isn't installed or
            # the acquisition `type`/labels don't match it: scenarios on that log never fire.
            "notParsing": lines >= 100 and ok == 0 and not error_log,
        })

    return {
        "version": version,
        "startedAt": started,
        "decisions": {
            "byOrigin": _top(decisions_by_origin, 20),
            "byReason": _top(decisions_by_reason, 15),
            "total": int(sum(decisions_by_origin.values())),
        },
        "sources": sources,
        "appsec": {"requests": int(appsec_reqs), "blocked": int(appsec_blocked), "topRules": _top(rule_hits)},
        "bouncers": _top(bouncers, 20),
        "machines": _top(machines, 20),
        "whitelisted": int(whitelisted),
        "overflows": int(overflowed),
    }
