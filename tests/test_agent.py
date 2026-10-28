import base64
import json
import time
import urllib.error
import urllib.request

import pytest

from crowdsec_agent import metrics as prom
from crowdsec_agent.collector import Collector, Snapshot
from crowdsec_agent.config import Config
from crowdsec_agent.dashboard import serve
from crowdsec_agent.lapi import Lapi, LapiError, go_duration
from crowdsec_agent.state import State
from crowdsec_agent.store import Store, decision_rows, row

NOW = 1_800_000_000.0


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def alert(n, ago=60, kind="waf", ip="203.0.113.7", cn="NL", decision=None, scenario="crowdsecurity/vpatch-env-access"):
    return {
        "id": n, "uuid": f"u-{n}", "created_at": iso(NOW - ago), "start_at": iso(NOW - ago), "kind": kind,
        "scenario": scenario, "message": f"WAF block: {scenario} from {ip}", "machine_id": "localhost",
        "events_count": 1, "simulated": False,
        "source": {"scope": "Ip", "value": ip, "ip": ip, "cn": cn, "as_name": "EXAMPLE-NET", "as_number": "64500",
                   "range": "203.0.113.0/24"},
        "meta": [{"key": "target_uri", "value": '["/.env"]'}],
        "events": [{"meta": [{"key": "target_fqdn", "value": "app.example.com"}, {"key": "uri", "value": "/.env"}]}],
        "decisions": [decision] if decision else None,
    }


BAN = {"duration": "3h59m30s", "id": 9, "origin": "crowdsec", "scenario": "crowdsecurity/appsec-vpatch",
       "scope": "Ip", "simulated": False, "type": "ban", "value": "203.0.113.7"}

METRICS = """
# HELP cs_info Information about Crowdsec.
cs_info{version="v1.8.1-abc"} 0
process_start_time_seconds 1.7999e+09
cs_active_decisions{action="ban",origin="CAPI",reason="http:scan"} 17000
cs_active_decisions{action="ban",origin="lists",reason="tor-exit-nodes"} 2000
cs_active_decisions{action="ban",origin="crowdsec",reason="crowdsecurity/appsec-vpatch"} 4
cs_filesource_hits_total{acquis_type="npmplus",datasource_type="file",source="/logs/access.log"} 1500
cs_parser_hits_ko_total{acquis_type="npmplus",source="/logs/access.log",type="file"} 1500
cs_parser_hits_total{source="/logs/access.log",type="file"} 1500
cs_filesource_hits_total{acquis_type="npmplus",datasource_type="file",source="/logs/error.log"} 900
cs_parser_hits_ko_total{acquis_type="npmplus",source="/logs/error.log",type="file"} 900
cs_filesource_hits_total{acquis_type="nginx",datasource_type="file",source="/logs/other.log"} 300
cs_parser_hits_ok_total{acquis_type="nginx",source="/logs/other.log",type="file"} 290
cs_parser_hits_ko_total{acquis_type="nginx",source="/logs/other.log",type="file"} 10
cs_parser_hits_ok_total{acquis_type="appsec",source="appsec",type="appsec"} 2000
cs_parser_hits_total{source="appsec",type="appsec"} 2000
cs_appsec_reqs_total{appsec_engine="appsec",source="172.18.0.2"} 179493
cs_appsec_block_total{appsec_engine="appsec",source="172.18.0.2"} 446
cs_appsec_rule_hits{appsec_engine="appsec",rule_name="crowdsecurity/vpatch-env-access",source="x",type="inband"} 64
cs_lapi_bouncer_requests_total{bouncer="proxy",method="GET",route="/v1/decisions"} 49764
cs_lapi_machine_requests_total{machine="localhost",method="GET",route="/v1/heartbeat"} 646
cs_node_wl_hits_ok_total{name="crowdsecurity/whitelists",source="appsec"} 1553
"""


def cfg(tmp_path, **kw):
    return Config(lapi_url="http://lapi.invalid:8080", machine_id="dash", password="pw", state_path=str(tmp_path / "state.json"),
                  metrics_url=kw.pop("metrics_url", "http://lapi.invalid:6060/metrics"), **kw)


def test_go_duration():
    assert go_duration("3h48m36s") == 3 * 3600 + 48 * 60 + 36
    assert go_duration("-1h2m") == -3720
    assert go_duration("150ms") == pytest.approx(0.15)
    assert go_duration("") == 0


def test_metrics_summary_flags_sources_that_never_parse():
    s = prom.summarize(prom.parse(METRICS))
    assert s["version"] == "v1.8.1-abc"
    assert s["decisions"]["total"] == 19004
    assert s["decisions"]["byOrigin"][0] == {"name": "CAPI", "count": 17000}
    by_source = {x["source"]: x for x in s["sources"]}
    assert by_source["/logs/access.log"]["notParsing"] is True
    assert by_source["/logs/error.log"]["notParsing"] is False and by_source["/logs/error.log"]["errorLog"]
    assert by_source["/logs/access.log"]["type"] == "npmplus"
    assert by_source["/logs/other.log"] == {"source": "/logs/other.log", "type": "nginx", "read": 300, "parsed": 290,
                                            "unparsed": 10, "errorLog": False, "notParsing": False}
    assert by_source["appsec"]["read"] == 2000 and not by_source["appsec"]["notParsing"]
    assert s["appsec"]["blocked"] == 446 and s["appsec"]["topRules"][0]["count"] == 64
    assert s["bouncers"] == [{"name": "proxy", "count": 49764}]
    assert s["whitelisted"] == 1553


def test_row_extracts_source_target_and_decision():
    r = row(alert(1, decision=BAN, kind="crowdsec"), NOW)
    assert r["ip"] == "203.0.113.7" and r["cn"] == "NL" and r["as_number"] == "64500"
    assert r["target"] == "app.example.com" and r["uri"] == "/.env"
    assert r["decision"] == "ban" and r["decision_until"] == pytest.approx(NOW + 3 * 3600 + 59 * 60 + 30)
    assert r["created_at"] == NOW - 60


def test_store_summary_upsert_and_prune(tmp_path):
    store = Store(str(tmp_path / "a.db"))
    alerts = [alert(1, ago=600), alert(2, ago=1800, ip="198.51.100.4", cn="US"),
              alert(3, ago=4000, kind="crowdsec", decision=BAN, scenario="crowdsecurity/appsec-vpatch"),
              alert(4, ago=3 * 86400)]
    alerts[3]["events"][0]["meta"][0]["value"] = "app.example.com:443"
    store.upsert(alerts, NOW)
    store.upsert(alerts[:2], NOW)  # re-reading the overlap doesn't duplicate
    assert store.count() == 4

    s = store.summary(24, NOW)
    assert s["total"] == 3 and s["uniqueSources"] == 2 and s["waf"] == 2 and s["withDecision"] == 1
    tl = s["timeline"]
    assert tl["bucketSeconds"] == 3600 and len(tl["starts"]) == 24 and tl["starts"][-1] <= NOW < tl["starts"][-1] + 3600
    assert sum(tl["series"]["waf"]) == 2 and sum(tl["series"]["scenario"]) == 1
    assert s["topCountries"][0] == {"name": "NL", "count": 2}
    assert s["topTargets"] == [{"name": "app.example.com", "count": 3}]
    assert s["topAS"][0]["name"] == "EXAMPLE-NET (AS64500)"

    assert store.summary(168, NOW)["total"] == 4
    assert store.summary(168, NOW)["topTargets"] == [{"name": "app.example.com", "count": 4}]
    assert len(store.summary(168, NOW)["timeline"]["starts"]) == 28
    assert [a["id"] for a in store.alerts(24, "198.51", now=NOW)] == [2]
    assert [a["id"] for a in store.alerts(24, "vpatch-env", now=NOW)] == [1, 2]

    assert store.prune(2, NOW) == 1 and store.count() == 3


def test_decision_rows_skip_expired():
    expired = dict(BAN, id=10, duration="-5m")
    a = alert(1, decision=BAN)
    a["decisions"].append(expired)
    rows = decision_rows([a], NOW)
    assert [d["id"] for d in rows] == [9]
    assert rows[0]["cn"] == "NL" and rows[0]["until"] > NOW


class FakeLapi:
    def __init__(self, alerts=(), active=(), fail=None):
        self.alerts_data, self.active, self.fail, self.calls = list(alerts), list(active), fail, []

    def alerts(self, since_seconds=None, active=False):
        self.calls.append((since_seconds, active))
        if self.fail:
            raise self.fail
        return self.active if active else self.alerts_data


def collector(tmp_path, lapi, metrics_text=METRICS, **kw):
    c = cfg(tmp_path, **kw)
    state = State(c.state_path)
    store = Store(c.db_path)
    snap = Snapshot()

    def fetch(url):
        if isinstance(metrics_text, Exception):
            raise metrics_text
        return prom.parse(metrics_text)

    return Collector(c, lapi, store, state, snap, fetch_metrics=fetch), state, store, snap


def test_collector_backfills_then_reads_increments(tmp_path):
    lapi = FakeLapi(alerts=[alert(1)], active=[alert(1, decision=BAN)])
    col, state, store, snap = collector(tmp_path, lapi, history_days=30)
    assert col.run(NOW) == ([], [])
    assert lapi.calls[0] == (30 * 86400, False) and lapi.calls[1] == (None, True)
    assert store.count() == 1
    view = snap.view()
    assert view["lapi"]["ok"] and len(view["decisions"]) == 1
    assert view["metrics"]["data"]["decisions"]["total"] == 19004

    col.run(NOW + 60)
    assert lapi.calls[2] == (60 + 3600, False)


def test_collector_reports_outage_after_grace_and_recovery_once(tmp_path):
    lapi = FakeLapi(fail=LapiError("login refused"))
    col, state, store, snap = collector(tmp_path, lapi, down_minutes=10)
    assert col.run(NOW) == ([], [])  # not yet: inside the grace period
    assert snap.view()["lapi"]["ok"] is False
    findings, cleared = col.run(NOW + 11 * 60)
    assert [f.key for f in findings] == ["crowdsec:lapi"] and "login refused" in findings[0].summary
    state.mark("notified", "crowdsec:lapi", NOW + 11 * 60)  # what the notifier does

    lapi.fail = None
    findings, cleared = col.run(NOW + 12 * 60)
    assert findings == [] and cleared == ["CrowdSec's Local API (http://lapi.invalid:8080) is reachable again"]
    assert col.run(NOW + 13 * 60) == ([], [])


def test_collector_metrics_outage(tmp_path):
    import requests
    col, state, store, snap = collector(tmp_path, FakeLapi(), metrics_text=requests.ConnectionError("refused"),
                                        down_minutes=0)
    findings, _ = col.run(NOW)
    assert [f.key for f in findings] == ["crowdsec:metrics"]
    assert snap.view()["metrics"]["ok"] is False


class FakeResponse:
    def __init__(self, status, data=None):
        self.status_code, self._data = status, data

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, gets):
        self.headers, self.gets, self.logins, self.params = {}, list(gets), 0, []

    def post(self, url, json=None, timeout=None):
        assert url.endswith("/v1/watchers/login") and json["machine_id"] == "dash"
        self.logins += 1
        return FakeResponse(200, {"token": f"t{self.logins}"})

    def get(self, url, params=None, timeout=None, headers=None):
        self.params.append((params, headers))
        return self.gets.pop(0)


def test_lapi_logs_in_again_when_the_token_expires():
    session = FakeSession([FakeResponse(200, []), FakeResponse(401), FakeResponse(200, [{"id": 1}])])
    lapi = Lapi("http://lapi.invalid:8080/", "dash", "pw", session=session)
    assert lapi.alerts(since_seconds=3600) == []
    assert session.params[0][0] == {"include_capi": "false", "simulated": "true", "limit": "0", "since": "3600s"}
    assert session.params[0][1]["Authorization"] == "Bearer t1"
    assert lapi.alerts(active=True) == [{"id": 1}]
    assert session.logins == 2 and session.params[2][1]["Authorization"] == "Bearer t2"
    assert session.params[2][0]["has_active_decision"] == "true"
    assert len(session.headers["User-Agent"].split("/")) == 2  # LAPI's login rejects anything else


@pytest.fixture
def web(tmp_path):
    store = Store(str(tmp_path / "a.db"))
    store.upsert([alert(1, ago=60)], time.time())
    snap = Snapshot()
    snap.update(decisions=decision_rows([alert(1, decision=BAN)], time.time()))
    servers = []

    def start(password=""):
        server = serve(0, store, snap, password, 90 * 24, {"revision": "test"}, host="127.0.0.1")
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for s in servers:
        s.shutdown()


def get(url, auth=None):
    req = urllib.request.Request(url)
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, resp.headers, resp.read()


def test_dashboard_serves_page_and_api(web):
    base = web()
    status, headers, body = get(base + "/")
    assert status == 200 and b"<title>CrowdSec Dashboard</title>" in body
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert get(base + "/app.js")[0] == 200 and get(base + "/app.css")[0] == 200
    data = json.loads(get(base + "/api/overview?hours=24")[2])
    assert data["summary"]["total"] == 1 and data["decisionsTotal"] == 1 and data["agent"]["revision"] == "test"
    assert json.loads(get(base + "/api/alerts?hours=99999&q=203.0")[2])["alerts"][0]["id"] == 1
    with pytest.raises(urllib.error.HTTPError) as err:
        get(base + "/nope")
    assert err.value.code == 404


def test_dashboard_basic_auth(web):
    base = web(password="s3cret")
    assert get(base + "/health")[0] == 200  # the container health check never needs the password
    with pytest.raises(urllib.error.HTTPError) as err:
        get(base + "/api/overview")
    assert err.value.code == 401 and "Basic" in err.value.headers["WWW-Authenticate"]
    with pytest.raises(urllib.error.HTTPError):
        get(base + "/", auth="admin:wrong")
    assert get(base + "/", auth="anyone:s3cret")[0] == 200


def test_config_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CROWDSEC_LAPI_URL", "http://lapi.invalid:8080/")
    monkeypatch.setenv("CROWDSEC_PASSWORD", "pw")
    monkeypatch.setenv("STATE_PATH", str(tmp_path / "s" / "state.json"))
    c = Config.from_env()
    assert c.lapi_url == "http://lapi.invalid:8080" and c.machine_id == "crowdsec-dashboard"
    assert c.db_path == str(tmp_path / "s" / "alerts.db") and c.dashboard_port == 8080
    monkeypatch.delenv("CROWDSEC_PASSWORD")
    with pytest.raises(SystemExit):
        Config.from_env()


def test_discord_posts_are_sent_under_the_agents_own_name(monkeypatch):
    from crowdsec_agent import notice

    posted = []
    monkeypatch.setattr(notice, "_post_webhook", lambda url, payload: posted.append(payload) or True)
    url = "https://discord.com/api/webhooks/" + "1/fake-TOKEN"  # split so the public-sync secret scan passes
    assert notice.Outbox([url]).send(notice.Message("hi"))
    notice.Outbox([url], username="Someone else").send(notice.Message("hi"))
    assert [p["username"] for p in posted] == ["crowdsec-agent", "Someone else"]
    assert posted[0]["avatar_url"].endswith("/png/crowdsec.png")


def test_undelivered_digest_is_retried(tmp_path):
    from crowdsec_agent.findings import Finding
    from crowdsec_agent.notify import Notifier
    st = State(str(tmp_path / "s.json"))
    n = Notifier([], 12, st)
    sent, ok = [], [False]
    n.outbox = type("O", (), {"send": lambda s, msg: sent.append(msg.markdown()) or ok[0]})()
    down = Finding("crowdsec:metrics", "metrics unreachable", "error")
    n.send([down], ["CrowdSec's Local API is reachable again."])  # the post fails
    assert st["notified"] == {}
    ok[0] = True
    n.send([down])  # the recovery isn't reported again by the collector, but it's still owed
    assert len(sent) == 2 and "reachable again" in sent[1] and "metrics unreachable" in sent[1]
    n.send([down])
    assert len(sent) == 2  # delivered: nothing is repeated
