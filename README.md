# crowdsec-dashboard-agent

A small service that runs a local web dashboard for a [CrowdSec](https://crowdsec.net) instance:
alerts over time, where attacks come from (countries, networks, IPs), which scenarios and AppSec
rules fire, what your sites are hit with, active bans, blocklist sizes, and whether every log source
is actually being parsed. It keeps its own alert history, so the dashboard can show 90 days even
though CrowdSec flushes its database sooner. It runs as a Docker container, deployed by GitHub
Actions from a self-hosted runner, like the other homelab agents.

Inspired by [crowdsec-web-ui](https://github.com/TheDuffman85/crowdsec-web-ui) (no code taken from
it). Unlike that project, this one is **read-only**. It never deletes alerts or adds decisions, and
it needs no admin account, database or build step: Python's standard library serves the page, and
the page is plain HTML, CSS and JavaScript with no CDN.

## What it shows

| Section | Source |
|---|---|
| Totals: alerts, source IPs, countries, active local bans, blocklisted IPs, AppSec blocks | alert history + metrics |
| Alerts over time, AppSec (WAF) blocks vs scenario alerts | alert history |
| Top countries, scenarios, targeted hosts, autonomous systems, source IPs | alert history |
| Active decisions with country, network, scenario, origin and time left | Local API |
| Every active decision by origin (your CrowdSec, community blocklist, list subscriptions) | metrics |
| AppSec rule hits, requests inspected and blocked | metrics |
| Log sources: lines read, parsed and unparsed, flagged when **none** of a source's lines parse | metrics |
| API clients: requests per bouncer and machine | metrics |
| Searchable alert list (IP, country, network, scenario, host or path) | alert history |

Pick 24 hours, 7, 30 or 90 days at the top; everything on the page follows. The page refreshes
every minute, and its light/dark theme follows the system unless you switch it.

A log source that reads lines but parses none means CrowdSec has no parser for that log type, or the
acquisition `labels.type` doesn't match the installed collection. Scenarios on that log then never
fire, and only AppSec protects you. The dashboard shows a banner when that happens.

## How it reads CrowdSec

- **Local API** (`CROWDSEC_LAPI_URL`): the agent logs in as a **machine** (watcher), the way
  `cscli` does, and only reads `GET /v1/alerts`. Every `POLL_SECONDS` it reads the alerts started
  since the last sync, plus an hour of overlap, and the alerts with active decisions. The first sync
  reads `HISTORY_DAYS`. Community blocklist (CAPI) and list alerts are left out: they hold tens of
  thousands of decisions, so they're counted from the metrics instead.
- **Prometheus metrics** (`CROWDSEC_METRICS_URL`, optional): blocklist sizes, AppSec counters,
  parser and acquisition counts, and API client requests. These counters start from zero when
  CrowdSec restarts.
- **History**: alerts are kept in SQLite (`alerts.db` next to the state file) for
  `RETENTION_DAYS`.

### CrowdSec setup (once)

1. **Register the agent as a machine** on the CrowdSec host:
   ```bash
   docker exec crowdsec cscli machines add crowdsec-dashboard --password '<long random string>' -f /dev/null
   ```
   Keep `-f /dev/null`: without it, `cscli` overwrites CrowdSec's own `local_api_credentials.yaml`.
   The password goes into the `CROWDSEC_PASSWORD` secret.
2. **Publish the Local API** so the agent can reach it: the container's **port 8080** (the
   `api.server.listen_uri` port) must be mapped to a host port. With Docker's bridge network,
   `-p 8080:8080`.
3. **Optional, metrics:** in CrowdSec's `config.yaml`, set `prometheus.enabled: true` and
   `level: full`, and publish port 6060.

The agent never needs `api.server.trusted_ips`: that only matters for deleting alerts.

## Notifications

When the Local API or the metrics endpoint has failed for `DOWN_MINUTES`, the agent sends one message
to `NOTIFY_URLS`, repeated every `RENOTIFY_HOURS` while it lasts, and a "reachable again" message
when it recovers. Discord webhooks get embeds, and the sender is shown as `crowdsec-agent`. The
dashboard keeps showing the stored history while CrowdSec is down.

## Deployment

Every push to `main` runs the tests. The deploy job then sends the build context (the generated
`Dockerfile` and `.dockerignore`, `requirements.txt` and the package) and a rendered `agent.env` to
a Docker host. There, the root-owned `agent-deploy` builds the image and replaces the container,
and rolls back if the new one doesn't stay up. Each build pulls the newest base image and runs
`apt-get full-upgrade`, so every deployed image is fully patched. State and alert history live in
the `crowdsec-agent-data` volume.

| Variable | Expected value |
|---|---|
| `AGENT_HOST` | Address of the Docker host. |
| `PRIORITY` | `high` (default) or `low`. Picks the deploying runner (`[self-hosted, proxmox]` or `[self-hosted, low-priority]`) and sets the container label `homelab.priority`. |
| `DASHBOARD_HOST_PORT` | Host port for the dashboard, e.g. `8780`. The container listens on `DASHBOARD_PORT` (8080). |
| `BUS_HOST_PORT` | Optional. Host port for the agent bus when several agents share a host. The container still listens on `AGENT_BUS_PORT`. |

To prepare a Docker host, run `deploy/docker-host.sh` from the dockerfile-agent repository. It
installs `agent-deploy`, creates the `deploy` user, allows only the given runners in, and turns
on unattended security upgrades. The LXC deployment (`deploy/provision.sh`, systemd unit in
`deploy/lxc/crowdsec-agent-install`) still works as an alternative and is what dockerfile-agent
generates the Dockerfile from.

### Self-hosted runners and public repositories

GitHub advises against attaching self-hosted runners to public repositories, because a pull
request from a fork could run code on your hardware. This workflow runs tests on GitHub-hosted
runners and never runs the deploy job for pull requests, but to be safe:

- Deploy from a **private** copy of this repository, or
- If you keep it public, set Settings → Actions → General → "Fork pull request workflows" to
  require approval for all outside collaborators, and never add the `self-hosted` label to a job
  that runs on `pull_request`.

## Secrets and variables (required before the first deploy)

This repository contains **no secrets**. Add them yourself under **GitHub → Settings → Secrets and
variables → Actions** before the first deploy. The deploy job stops with a clear error if a
required value is missing. Every setting is also documented in `.env.example`.

### Secrets

| Secret | Required | Expected value |
|---|---|---|
| `CROWDSEC_PASSWORD` | **yes** | The password of the machine registered with `cscli machines add` (see CrowdSec setup), e.g. a 40-character random string. |
| `DASHBOARD_PASSWORD` | optional | Turns on basic auth for the dashboard (any user name, this password). Unset: anyone who can reach the port can view it. |
| `NOTIFY_URLS` | recommended | One or more [Apprise](https://github.com/caronc/apprise/wiki) URLs, comma separated, e.g. `discord://<webhook_id>/<webhook_token>`, `ntfy://ntfy.sh/<topic>`. Without it, outages only go to the agent's log. |
| `AGENT_BUS_TOKEN` | optional | Enables the agent bus (below). A long random string. |

### Variables

| Variable | Required | Expected value |
|---|---|---|
| `AGENT_HOST` | **yes** | IP or hostname of the Docker host. The deploy job is skipped until it exists. |
| `CROWDSEC_LAPI_URL` | **yes** | CrowdSec's Local API as reachable **from the agent**, e.g. `http://192.168.1.10:8080`. |
| `CROWDSEC_METRICS_URL` | recommended | CrowdSec's Prometheus endpoint, e.g. `http://192.168.1.10:6060/metrics`. |
| `CROWDSEC_MACHINE_ID` | optional | The machine name, default `crowdsec-dashboard`. |
| `DASHBOARD_HOST_PORT` | recommended | Host port for the dashboard (see Deployment). Without it, the dashboard isn't published. |
| `POLL_SECONDS`, `HISTORY_DAYS`, `RETENTION_DAYS`, `DOWN_MINUTES`, `RENOTIFY_HOURS`, `DASHBOARD_PORT` | optional | Overrides; see `.env.example` for defaults (60 s, 30 days, 90 days, 10 min, 12 h, 8080). |

Changing a variable or secret takes effect on the next deploy: re-run the workflow
(Actions → test-and-deploy → Run workflow).

### Operating

```bash
docker logs -f crowdsec-agent                                     # live log, on the Docker host
docker exec crowdsec-agent cat /opt/crowdsec-agent/app/REVISION   # deployed commit
```

Uptime Kuma: nothing to set up here. The Proxmox janitor's monitor sync gives every agent container
a "Docker Container" monitor within one sync of its first deploy, with the same settings as the
other agents.

The container has a Docker health check (`python -m crowdsec_agent.health`): it turns `unhealthy`
when a sync is more than 5 minutes overdue, or when the dashboard or the agent bus stops answering
`/health`. CrowdSec being down doesn't make the container unhealthy, because the dashboard still
serves the stored history; that's what the notification is for.
`docker inspect --format '{{json .State.Health}}' crowdsec-agent` shows why.

## Agent bus (MCP for an assistant such as Hermes Agent)

Optional. When `AGENT_BUS_TOKEN` is set, the agent serves read-only tools at
`http://<agent>:8765/mcp` (Streamable HTTP MCP, bearer token), so an assistant you chat with can
answer questions like "what attacked us today?" with live data:

| Tool | Returns |
|---|---|
| `crowdsec_summary` | Totals, timeline and top lists for the last `hours`, plus decisions by origin and AppSec counters |
| `crowdsec_alerts` | Recent alerts, optionally filtered by IP, scenario, country, network, host or path |
| `crowdsec_decisions` | Active local bans |
| `crowdsec_sources` | Log sources with parse counts, bouncer and machine requests |
| `agent_status`, `agent_run_check` | The agent's own state; `agent_run_check` syncs now |

There are no destructive tools, so no approval channel is needed. Example Hermes
`~/.hermes/config.yaml` entry (token kept in `~/.hermes/.env`):

```yaml
mcp_servers:
  crowdsec:
    url: "http://192.168.1.21:8765/mcp"
    headers:
      Authorization: "Bearer ${AGENT_BUS_TOKEN}"
    timeout: 180
```

## Develop

```bash
pip install -r requirements.txt pytest
pytest -q
# with CROWDSEC_LAPI_URL / CROWDSEC_PASSWORD / STATE_PATH exported (and DASHBOARD_PORT if 8080 is taken):
python -m crowdsec_agent        # then open http://localhost:8080
```
