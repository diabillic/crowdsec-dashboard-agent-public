// CrowdSec dashboard. Everything from the API is inserted with textContent, never as HTML.
"use strict";

const REFRESH_MS = 60000;
const state = { hours: 24, query: "", overview: null, alerts: null, timer: null, searchTimer: null,
  open: new Set(), details: new Map() };
const $ = (id) => document.getElementById(id);
const regionNames = (() => { try { return new Intl.DisplayNames(["en"], { type: "region" }); } catch { return null; } })();

// ---------- small helpers ----------
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c !== null && c !== undefined) node.append(c);
  return node;
}
function svg(tag, attrs) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) node.setAttribute(k, v);
  return node;
}
const nf = new Intl.NumberFormat();
const cf = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });
const num = (n) => (n === null || n === undefined ? "–" : nf.format(n));
const compact = (n) => (n === null || n === undefined ? "–" : n >= 10000 ? cf.format(n) : nf.format(n));
function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}
function country(cc) {
  if (!cc) return "";
  let name = cc;
  try { name = (regionNames && regionNames.of(cc.toUpperCase())) || cc; } catch { /* unknown code */ }
  return name;
}
function ago(ts) {
  if (!ts) return "never";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 90) return `${Math.round(s)}s ago`;
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 172800) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}
function until(ts) {
  const s = ts - Date.now() / 1000;
  if (s <= 0) return "expired";
  if (s < 3600) return `${Math.ceil(s / 60)} min`;
  if (s < 172800) return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
  return `${Math.round(s / 86400)} days`;
}
const fmtTime = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
const fmtHour = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
const fmtDay = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });
const fmtDayHour = new Intl.DateTimeFormat(undefined, { weekday: "short", hour: "2-digit" });
const when = (ts) => (ts ? fmtTime.format(new Date(ts * 1000)) : "");
const short = (scenario) => (scenario || "").replace(/^crowdsecurity\//, "");

// ---------- tooltip ----------
const tip = $("tip");
function showTip(evt, title, rows) {
  tip.replaceChildren(el("div", { class: "t", text: title }),
    ...rows.map((r) => el("div", { class: "r" }, el("b", { text: r.value }), r.cls ? el("i", { class: r.cls }) : null, el("span", { text: r.label }))));
  tip.style.display = "block";
  const pad = 14, w = tip.offsetWidth, h = tip.offsetHeight;
  let x = evt.clientX + pad, y = evt.clientY + pad;
  if (x + w > window.innerWidth - 8) x = evt.clientX - w - pad;
  if (y + h > window.innerHeight - 8) y = evt.clientY - h - pad;
  tip.style.left = `${Math.max(8, x)}px`;
  tip.style.top = `${Math.max(8, y)}px`;
}
function hideTip() { tip.style.display = "none"; }

// ---------- status, banners, tiles ----------
function pill(cls, text, title) {
  return el("span", { class: `pill ${cls}`, title }, el("span", { class: "dot" }), text);
}
function renderStatus(o) {
  const lapiCls = o.lapi.ok ? "ok" : o.lapi.ok === false ? "bad" : "";
  const items = [pill(lapiCls, o.lapi.ok ? "Local API connected" : o.lapi.ok === false ? "Local API unreachable" : "Connecting…",
    o.lapi.syncedAt ? `Last sync ${when(o.lapi.syncedAt)}` : "")];
  if (o.metrics.ok !== null) items.push(pill(o.metrics.ok ? "ok" : "bad", o.metrics.ok ? "Metrics" : "Metrics unreachable"));
  if (o.crowdsec && o.crowdsec.version) items.push(pill("", `CrowdSec ${o.crowdsec.version.split("-")[0]}`));
  $("status").replaceChildren(...items);

  const banners = [];
  if (o.lapi.ok === false) banners.push(el("div", { class: "banner" }, el("strong", { text: "Can't read alerts from CrowdSec." }),
    `${o.lapi.error || ""} Showing the history already stored${o.lapi.syncedAt ? `, last synced ${ago(o.lapi.syncedAt)}` : ""}.`));
  if (o.metrics.ok === false) banners.push(el("div", { class: "banner warn" }, el("strong", { text: "Can't read CrowdSec's metrics." }), o.metrics.error || ""));
  const notParsing = ((o.crowdsec && o.crowdsec.sources) || []).filter((s) => s.notParsing);
  if (notParsing.length) banners.push(el("div", { class: "banner warn" },
    el("strong", { text: `${notParsing.length === 1 ? "A log source isn't" : `${notParsing.length} log sources aren't`} being parsed.` }),
    `None of the lines from ${notParsing.map((s) => s.source).join(", ")} parse, so scenarios on those logs never fire. See Log sources below.`));
  $("banners").replaceChildren(...banners);
}
function tile(label, value, sub, hero) {
  return el("div", { class: `tile${hero ? " hero" : ""}` }, el("div", { class: "label", text: label }),
    el("div", { class: "value", text: value }), sub ? el("div", { class: "sub", text: sub }) : null);
}
function rangeLabel(h) { return h <= 24 ? "last 24 hours" : h % 24 === 0 ? `last ${h / 24} days` : `last ${h} hours`; }
function renderTiles(o) {
  const s = o.summary, cs = o.crowdsec || {};
  const tiles = [
    tile("Alerts", num(s.total), rangeLabel(s.hours), true),
    tile("Source IPs", num(s.uniqueSources), `${num(s.countries)} countries`),
    tile("Active local bans", num(o.decisionsTotal), "decided by your CrowdSec"),
  ];
  if (cs.decisions) tiles.push(tile("Blocklisted IPs", compact(cs.decisions.total), "all active decisions, incl. community lists"));
  if (cs.appsec && cs.appsec.requests) tiles.push(tile("AppSec blocks", num(cs.appsec.blocked),
    `of ${compact(cs.appsec.requests)} requests inspected${cs.startedAt ? `, since ${fmtDay.format(new Date(cs.startedAt * 1000))}` : ""}`));
  tiles.push(tile("Alerts with a ban", num(s.withDecision), s.simulated ? `${num(s.simulated)} simulated` : `${num(s.waf)} WAF blocks without one`));
  $("tiles").replaceChildren(...tiles);
}

// ---------- timeline: stacked columns ----------
function niceMax(v) {
  if (v <= 4) return 4;
  const p = Math.pow(10, Math.floor(Math.log10(v))), n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
}
function colPath(x, y, w, h, round) { // square at the baseline, 4px rounded data-end when `round`
  if (h <= 0) return "";
  const r = round ? Math.min(4, w / 2, h) : 0;
  return `M${x},${y + h}V${y + r}${r ? `Q${x},${y} ${x + r},${y}` : ""}H${x + w - r}${r ? `Q${x + w},${y} ${x + w},${y + r}` : ""}V${y + h}Z`;
}
function renderTimeline(o) {
  const box = $("timeline"), t = o.summary.timeline;
  const W = Math.max(280, box.clientWidth), H = 220, padL = 40, padR = 8, padT = 8, padB = 24;
  const n = t.starts.length, waf = t.series.waf, scn = t.series.scenario;
  const totals = waf.map((v, i) => v + scn[i]);
  const max = niceMax(Math.max(1, ...totals));
  const plotW = W - padL - padR, plotH = H - padT - padB, band = plotW / n;
  const barW = Math.max(2, Math.min(24, band * 0.72));
  const y = (v) => padT + plotH - (v / max) * plotH;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, height: H, role: "img", "aria-label": "Alerts over time" });

  for (let k = 0; k <= 4; k++) {
    const v = (max / 4) * k, yy = Math.round(y(v)) + 0.5;
    root.append(svg("line", { x1: padL, x2: W - padR, y1: yy, y2: yy, class: k === 0 ? "baseline" : "gridline" }));
    const label = svg("text", { x: padL - 6, y: yy + 4, "text-anchor": "end" });
    label.textContent = compact(v);
    root.append(label);
  }
  const fmt = t.bucketSeconds >= 86400 ? fmtDay : t.bucketSeconds > 3600 ? fmtDayHour : fmtHour;
  const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(plotW / 70))));
  const marks = svg("g", {});
  for (let i = 0; i < n; i++) {
    const cx = padL + band * i + band / 2, x = cx - barW / 2;
    const hw = (waf[i] / max) * plotH, hs = (scn[i] / max) * plotH;
    const gap = hw > 0 && hs > 0 ? 2 : 0;
    if (hw > 0) marks.append(svg("path", { d: colPath(x, y(waf[i]), barW, hw, hs === 0), class: "m1" }));
    if (hs > 0) marks.append(svg("path", { d: colPath(x, y(waf[i]) - hs, barW, Math.max(0, hs - gap), true), class: "m2" }));
    if (i % every === 0) {
      const label = svg("text", { x: cx, y: H - 6, "text-anchor": "middle" });
      label.textContent = fmt.format(new Date(t.starts[i] * 1000));
      root.append(label);
    }
  }
  root.append(marks);
  const hover = svg("rect", { x: 0, y: padT, width: band, height: plotH, class: "hover", visibility: "hidden" });
  root.insertBefore(hover, marks);
  const hit = svg("rect", { x: padL, y: padT, width: plotW, height: plotH, class: "hit" });
  hit.addEventListener("pointermove", (evt) => {
    const r = root.getBoundingClientRect(), px = ((evt.clientX - r.left) / r.width) * W;
    const i = Math.min(n - 1, Math.max(0, Math.floor((px - padL) / band)));
    hover.setAttribute("x", padL + band * i);
    hover.setAttribute("visibility", "visible");
    const start = new Date(t.starts[i] * 1000), end = new Date((t.starts[i] + t.bucketSeconds) * 1000);
    const title = t.bucketSeconds >= 86400 ? fmtDay.format(start) : `${fmtTime.format(start)} – ${fmtHour.format(end)}`;
    showTip(evt, title, [
      { value: num(totals[i]), label: "alerts in total" },
      { value: num(waf[i]), label: "AppSec (WAF) blocks", cls: "s1" },
      { value: num(scn[i]), label: "Scenario alerts", cls: "s2" },
    ]);
  });
  hit.addEventListener("pointerleave", () => { hover.setAttribute("visibility", "hidden"); hideTip(); });
  root.append(hit);
  box.replaceChildren(root);
  const span = t.bucketSeconds >= 86400 ? "day" : t.bucketSeconds > 3600 ? `${t.bucketSeconds / 3600} hours` : "hour";
  $("timeline-hint").textContent = `Alerts per ${span}, ${rangeLabel(o.summary.hours)}`;
}

// ---------- horizontal bar lists ----------
function barList(target, items, label, total) {
  const box = $(target);
  if (!items || !items.length) return box.replaceChildren(el("div", { class: "empty", text: "Nothing in this range" }));
  const max = Math.max(...items.map((i) => i.count));
  const grid = el("div", { class: "bars" });
  for (const item of items) {
    const name = label ? label(item.name) : item.name;
    const pct = total ? ` (${Math.round((item.count / total) * 100)}%)` : "";
    const bar = el("span", { class: "bar" });
    bar.style.width = `calc((100% - 4.5em) * ${item.count / max})`;
    grid.append(el("div", { class: "name", title: item.name, text: name }),
      el("div", { class: "track", title: `${item.name}: ${num(item.count)}${pct}` }, bar, el("span", { class: "num", text: compact(item.count) })));
  }
  box.replaceChildren(grid);
}

// ---------- tables ----------
function table(id, head, rows) {
  const t = $(id);
  const thead = el("thead", {}, el("tr", {}, ...head.map((h) => el("th", { class: h.num ? "num" : null, text: h.label }))));
  const tbody = el("tbody", {}, ...rows);
  if (!rows.length) tbody.append(el("tr", {}, el("td", { colspan: head.length, class: "empty", text: "Nothing to show" })));
  t.replaceChildren(thead, tbody);
}
const td = (text, cls, title) => el("td", { class: cls, text: text === undefined || text === null ? "" : String(text), title });
function countryCell(cc) {
  return el("td", { title: country(cc), text: cc || "" });
}
function kindBadge(kind) {
  return kind === "waf" ? el("span", { class: "badge waf", text: "WAF" }) : el("span", { class: "badge scn", text: "Scenario" });
}

function renderDecisions(o) {
  const rows = o.decisions.slice(0, 200).map((d) => el("tr", {},
    td(d.value, "mono"), el("td", {}, el("span", { class: `badge ${d.type === "ban" ? "ban" : ""}`, text: d.type })),
    countryCell(d.cn), td(d.asName, "clip", d.asName), td(short(d.scenario), "clip", d.scenario),
    td(d.origin), td(when(d.createdAt), "when"), td(until(d.until), "when")));
  table("decisions", [{ label: "Source" }, { label: "Action" }, { label: "Country" }, { label: "Network" },
    { label: "Scenario" }, { label: "Origin" }, { label: "Decided" }, { label: "Expires in" }], rows);
  $("decisions-hint").textContent = `${num(o.decisionsTotal)} active, from your own CrowdSec (community blocklists are counted below)`;
  $("decisions-more").textContent = o.decisionsTotal > 200 ? `Showing the newest 200 of ${num(o.decisionsTotal)}.` : "";
}

function renderMetrics(o) {
  const cs = o.crowdsec;
  if (!cs) {
    for (const id of ["origins", "rules"]) $(id).replaceChildren(el("div", { class: "empty", text: "No metrics (CROWDSEC_METRICS_URL isn't set or isn't reachable)" }));
    table("sources", [{ label: "Source" }], []);
    table("clients", [{ label: "Client" }], []);
    return;
  }
  const origin = { CAPI: "Community blocklist (CAPI)", lists: "Blocklist subscriptions", crowdsec: "Your CrowdSec", cscli: "Manual (cscli)" };
  barList("origins", cs.decisions.byOrigin, (n) => origin[n] || n, cs.decisions.total);
  $("origins-hint").textContent = `${num(cs.decisions.total)} active decisions, by origin`;
  barList("rules", cs.appsec.topRules, short);
  $("appsec-hint").textContent = cs.appsec.requests
    ? `Rule hits since CrowdSec started: ${num(cs.appsec.blocked)} blocks out of ${num(cs.appsec.requests)} requests`
    : "AppSec isn't receiving requests";

  table("sources", [{ label: "Source" }, { label: "Type" }, { label: "Lines read", num: true },
    { label: "Parsed", num: true }, { label: "Unparsed", num: true }, { label: "" }],
  cs.sources.map((s) => el("tr", {}, td(s.source, "clip", s.source), td(s.type), td(num(s.read), "num"),
    td(num(s.parsed), "num"), td(num(s.unparsed), "num"),
    el("td", {}, s.notParsing ? el("span", { class: "warn-text", text: "⚠ Not parsing" })
      : s.errorLog ? el("span", { class: "muted", text: "Only failed logins and rate limits parse" }) : null))));
  $("sources-hint").textContent = `Since CrowdSec started${cs.startedAt ? ` (${when(cs.startedAt)})` : ""}. ` +
    (cs.whitelisted ? `${num(cs.whitelisted)} events were whitelisted.` : "");

  const clients = [
    ...cs.bouncers.map((b) => el("tr", {}, td(b.name), td("Bouncer"), td(compact(b.count), "num"))),
    ...cs.machines.map((m) => el("tr", {}, td(m.name), td("Machine"), td(compact(m.count), "num"))),
  ];
  table("clients", [{ label: "Name" }, { label: "Kind" }, { label: "Requests", num: true }], clients);
}

// ---------- alert detail: a row that opens below its alert ----------
const EVENT_COLS = [ // event meta shown as columns when any event has them; the rest go under "Other"
  ["Method", ["http_verb", "method"]], ["Path", ["http_path", "uri", "target_uri"]], ["Status", ["http_status", "status"]],
  ["Rule", ["rule_name"]], ["User agent", ["http_user_agent", "user_agent"]],
];
const EVENT_SKIP = new Set(["source_ip", "timestamp", "IsInEU", "IsoCode", "ASNNumber", "ASNOrg", "SourceRange"]);
const fmtFull = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
const full = (ts) => (ts ? fmtFull.format(new Date(ts * 1000)) : "–");
function span(seconds) {
  if (seconds === null || seconds === undefined || seconds < 0) return "–";
  if (seconds < 1) return "under a second";
  if (seconds < 120) return `${Math.round(seconds)} s`;
  if (seconds < 7200) return `${Math.round(seconds / 60)} min`;
  if (seconds < 172800) return `${Math.round(seconds / 360) / 10} h`;
  return `${Math.round(seconds / 8640) / 10} days`;
}
const joined = (v) => (Array.isArray(v) ? v.join(", ") : String(v));
function dl(title, pairs) {
  const rows = pairs.filter((p) => p && p[1] !== "" && p[1] !== null && p[1] !== undefined);
  if (!rows.length) return null;
  return el("section", {}, el("h4", { text: title }),
    el("dl", {}, ...rows.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", {}, v instanceof Node ? v : String(v))])));
}
function link(href, text) { return el("a", { href, text, target: "_blank", rel: "noopener noreferrer" }); }

function detailPanel(a) {
  const d = a.detail;
  const ip = a.ip || (a.scope && a.scope.toLowerCase() === "ip" ? a.value : "");
  const lookups = ip ? el("span", { class: "links" }, link(`https://app.crowdsec.net/cti/${encodeURIComponent(ip)}`, "CrowdSec CTI"),
    " · ", link(`https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`, "AbuseIPDB")) : null;
  const where = a.lat !== null && a.lat !== undefined ? `${a.lat.toFixed(2)}, ${a.lon.toFixed(2)}` : a.cn ? "Country only" : "";
  const sections = [
    dl("Source", [["Address", `${a.value || a.ip}${a.scope && a.scope !== "Ip" ? ` (${a.scope})` : ""}`], ["Network", a.ip_range],
      ["AS", a.as_name ? `${a.as_name}${a.as_number ? ` (AS${a.as_number})` : ""}` : ""],
      ["Country", a.cn ? `${flag(a.cn)} ${country(a.cn)}` : ""], ["Location", where], ["Look up", lookups]]),
    dl("Detection", [["Scenario", `${a.scenario}${d && d.scenarioVersion ? ` (v${d.scenarioVersion})` : ""}`],
      ["Kind", a.kind === "waf" ? "AppSec (WAF) block" : "Scenario alert"], ["Machine", a.machine],
      ["Started", d ? full(d.startedAt) : full(a.created_at)], ["Ended", d && d.stoppedAt ? full(d.stoppedAt) : ""],
      ["Lasted", d && d.startedAt && d.stoppedAt ? span(d.stoppedAt - d.startedAt) : ""], ["Events", num(a.events)],
      ["Bucket", d && d.capacity ? `capacity ${d.capacity}, leaks ${d.leakspeed || "?"}` : ""],
      ["Simulated", a.simulated ? "Yes (simulation mode: nothing enforced)" : ""]]),
  ];
  if (d && d.decisions.length) {
    sections.push(dl(d.decisions.length === 1 ? "Decision" : `Decisions (${d.decisions.length})`, d.decisions.map((x) => [
      `${x.type}${x.simulated ? " (simulated)" : ""}`,
      `${x.scope} ${x.value}, ${span(x.duration)}, from ${x.origin}; ` +
        (x.until > Date.now() / 1000 ? `expires in ${until(x.until)}` : `expired ${ago(x.until)}`)])));
  } else {
    sections.push(dl("Decision", [["None", a.kind === "waf" ? "The request was blocked; the source wasn't banned" : "Alert only, nothing enforced"]]));
  }
  if (d && d.context.length) sections.push(dl("Context", d.context.map(([k, v]) => [k, joined(v)])));

  const body = [el("p", { class: "msg", text: a.message || "" }), el("div", { class: "detail-grid" }, ...sections.filter(Boolean))];
  if (!d) body.push(el("p", { class: "muted", text: "Stored before the agent kept full details. Events and context are recorded for alerts from now on." }));
  else if (d.events.length) body.push(eventsTable(d.events, a.events));
  return el("div", { class: "detail-body" }, ...body);
}

function eventsTable(events, total) {
  const pick = (meta, keys) => { for (const k of keys) { const m = meta.find((p) => p[0] === k); if (m) return m; } return null; };
  const cols = EVENT_COLS.filter(([, keys]) => events.some((e) => pick(e.meta, keys)));
  const used = new Set(cols.flatMap(([, keys]) => keys));
  const rows = events.map((e) => {
    const other = e.meta.filter(([k]) => !used.has(k) && !EVENT_SKIP.has(k)).map(([k, v]) => `${k}=${joined(v)}`).join("  ·  ");
    return el("tr", {}, td(e.at ? fmtFull.format(new Date(e.at * 1000)) : "", "when"),
      ...cols.map(([label, keys]) => {
        const m = pick(e.meta, keys), text = m ? joined(m[1]) : "";
        return td(text, label === "Path" || label === "User agent" ? "clip mono" : "mono", text);
      }),
      td(other, "other"));
  });
  const head = el("tr", {}, el("th", { text: "Time" }), ...cols.map(([label]) => el("th", { text: label })), el("th", { text: "Other" }));
  return el("section", { class: "events" },
    el("h4", { text: total > events.length ? `Events (first ${events.length} of ${num(total)})` : `Events (${events.length})` }),
    el("div", { class: "table-wrap" }, el("table", {}, el("thead", {}, head), el("tbody", {}, ...rows))));
}

function detailRow(a, cols) {
  const cell = el("td", { colspan: cols });
  const d = state.details.get(a.uuid);
  if (d) cell.append(detailPanel(d));
  else {
    cell.append(el("div", { class: "muted", text: "Loading…" }));
    getJSON(`/api/alert?uuid=${encodeURIComponent(a.uuid)}`).then((found) => {
      state.details.set(a.uuid, found);
      if (cell.isConnected) cell.replaceChildren(detailPanel(found));
    }).catch((err) => cell.replaceChildren(el("div", { class: "warn-text", text: `Couldn't load the details: ${err.message}` })));
  }
  return el("tr", { class: "detail" }, cell);
}

function renderAlerts() {
  const list = (state.alerts || []);
  const head = [{ label: "" }, { label: "Time" }, { label: "Source" }, { label: "Country" }, { label: "Network" }, { label: "Scenario" },
    { label: "Kind" }, { label: "Target" }, { label: "Path" }, { label: "Events", num: true }, { label: "Decision" }];
  const rows = [];
  for (const a of list.slice(0, 300)) {
    const open = state.open.has(a.uuid);
    rows.push(el("tr", { class: `alert-row${open ? " open" : ""}`, "data-uuid": a.uuid },
      el("td", {}, el("button", { type: "button", class: "disclose", "aria-expanded": String(open), "aria-label": "Details", title: "Details" })),
      td(when(a.created_at), "when"), td(a.value || a.ip, "mono"), countryCell(a.cn),
      td(a.as_name, "clip", a.as_name ? `${a.as_name} (AS${a.as_number})` : ""), td(short(a.scenario), "clip", a.message || a.scenario),
      el("td", {}, kindBadge(a.kind)), td(a.target, "clip", a.target), td(a.uri, "clip mono", a.uri), td(num(a.events), "num"),
      el("td", {}, a.decision ? el("span", { class: `badge ${a.decision === "ban" ? "ban" : ""}`, text: a.decision }) : null,
        a.simulated ? el("span", { class: "badge", text: "simulated" }) : null)));
    if (open) rows.push(detailRow(a, head.length));
  }
  table("alerts", head, rows);
  $("alerts-hint").textContent = (state.query
    ? `${num(list.length)}${list.length >= 1000 ? "+" : ""} alerts matching “${state.query}”, ${rangeLabel(state.hours)}`
    : `Newest first, ${rangeLabel(state.hours)}`) + ". Click an alert for its details.";
  $("alerts-more").textContent = list.length > 300 ? "Showing the newest 300. Narrow it down with the filter." : "";
}
$("alerts").addEventListener("click", (evt) => {
  if (evt.target.closest("a, tr.detail") || String(window.getSelection())) return; // links, the panel, selecting text
  const row = evt.target.closest("tr.alert-row");
  if (!row) return;
  const uuid = row.dataset.uuid;
  if (state.open.has(uuid)) state.open.delete(uuid); else state.open.add(uuid);
  renderAlerts();
});

function render() {
  const o = state.overview;
  if (!o) return;
  renderStatus(o);
  renderTiles(o);
  renderMap();
  renderTimeline(o);
  const total = o.summary.total;
  barList("top-countries", o.summary.topCountries, (cc) => `${flag(cc)} ${country(cc)}`, total);
  barList("top-scenarios", o.summary.topScenarios, short, total);
  barList("top-targets", o.summary.topTargets, null, total);
  barList("top-as", o.summary.topAS, null, total);
  barList("top-sources", o.summary.topSources, null, total);
  renderDecisions(o);
  renderMetrics(o);
  renderAlerts();
  $("updated").textContent = `Updated ${fmtHour.format(new Date())}`;
}

// ---------- attack map: heat of where alerts came from, plus live pings ----------
// Equirectangular, cropped to 84°N–58°S (no Antarctica). Points without GeoIP coordinates sit on
// their country's centroid. Drawn on canvas: land + heat below, pings on an overlay above.
const LAT_N = 84, LAT_S = -58, LIVE_MS = 10000, PING_MS = 2600, FEED_MAX = 12;
const CATS = ["banned", "blocked", "flagged"];
const CAT_LABEL = { banned: "Banned", blocked: "Blocked", flagged: "Flagged" };
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const map = { world: null, worldP: null, data: null, show: new Set(CATS), cursor: null, feed: [], pings: [],
  hit: [], radius: 10, raf: 0, liveTimer: null, refreshTimer: null, ramp: null, rampKey: "" };

async function loadWorld() {
  if (!map.worldP) {
    map.worldP = getJSON("/world.json").then((w) => {
      const land = w.land.map((flat) => {
        const ring = [];
        let x = 0, y = 0;
        for (let i = 0; i < flat.length; i += 2) { x += flat[i]; y += flat[i + 1]; ring.push([x / 10, y / 10]); }
        return ring;
      });
      map.world = { land, centroids: w.centroids };
    }).catch((err) => { map.worldP = null; throw err; });
  }
  return map.worldP;
}
function where(p) { // [lon, lat] or null
  if (p.lat !== null && p.lat !== undefined && p.lon !== null && p.lon !== undefined) return [p.lon, p.lat];
  const c = map.world && p.cn && map.world.centroids[p.cn.toUpperCase()];
  return c || null;
}
function project(lonlat, W, H) {
  return [((lonlat[0] + 180) / 360) * W, ((LAT_N - lonlat[1]) / (LAT_N - LAT_S)) * H];
}
const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

function heatRamp() { // 256 RGBA steps; low intensity fades to transparent so the land shows through
  const stops = [1, 2, 3, 4, 5].map((i) => cssVar(`--heat-${i}`));
  const key = stops.join();
  if (map.ramp && map.rampKey === key) return map.ramp;
  const c = document.createElement("canvas");
  c.width = 256; c.height = 1;
  const ctx = c.getContext("2d"), g = ctx.createLinearGradient(0, 0, 256, 0);
  stops.forEach((s, i) => g.addColorStop(i / (stops.length - 1), s));
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, 256, 1);
  const px = ctx.getImageData(0, 0, 256, 1).data;
  for (let i = 0; i < 256; i++) px[i * 4 + 3] = Math.round(Math.min(1, 0.25 + (i / 255) * 1.5) * 230);
  map.rampKey = key;
  return (map.ramp = px);
}

function drawMap() {
  const box = $("map"), heat = $("map-heat"), fx = $("map-fx");
  const W = box.clientWidth, H = box.clientHeight;
  if (!W || !H || !map.world) return;
  const dpr = window.devicePixelRatio || 1, PW = Math.round(W * dpr), PH = Math.round(H * dpr);
  for (const c of [heat, fx]) if (c.width !== PW || c.height !== PH) { c.width = PW; c.height = PH; }
  const ctx = heat.getContext("2d");
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, PW, PH);

  // land, with country borders in the surface color
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.beginPath();
  for (const ring of map.world.land) {
    ring.forEach((pt, i) => { const [x, y] = project(pt, W, H); if (i) ctx.lineTo(x, y); else ctx.moveTo(x, y); });
    ctx.closePath();
  }
  ctx.fillStyle = cssVar("--land");
  ctx.fill();
  ctx.strokeStyle = cssVar("--surface");
  ctx.lineWidth = 0.6;
  ctx.stroke();

  // heat: a Gaussian kernel per place summed on a grid (2 CSS px cells), log-scaled to the busiest
  // spot so one alert still shows, then coloured from the ramp and smoothed up to full size
  map.radius = Math.max(8, Math.min(24, W / 55));
  map.hit = [];
  for (const p of (map.data && map.data.points) || []) {
    const n = CATS.reduce((sum, c) => sum + (map.show.has(c) ? p[c] : 0), 0);
    const ll = n && where(p);
    if (!ll) continue;
    const [x, y] = project(ll, W, H);
    map.hit.push({ x, y, n, p, approx: p.lat === null || p.lat === undefined });
  }
  if (!map.hit.length) return;
  const cell = 2, GW = Math.ceil(W / cell), GH = Math.ceil(H / cell), R = Math.ceil(map.radius / cell);
  const grid = new Float32Array(GW * GH), kernel = [], sigma2 = 2 * (R / 2.5) ** 2;
  for (let dy = -R; dy <= R; dy++) for (let dx = -R; dx <= R; dx++) {
    if (dx * dx + dy * dy <= R * R) kernel.push(dx, dy, Math.exp(-(dx * dx + dy * dy) / sigma2));
  }
  for (const h of map.hit) {
    const cx = Math.round(h.x / cell), cy = Math.round(h.y / cell);
    for (let k = 0; k < kernel.length; k += 3) {
      const gx = cx + kernel[k], gy = cy + kernel[k + 1];
      if (gx >= 0 && gx < GW && gy >= 0 && gy < GH) grid[gy * GW + gx] += h.n * kernel[k + 2];
    }
  }
  let max = 0;
  for (const v of grid) if (v > max) max = v;
  const scale = 255 / Math.log1p(max), ramp = heatRamp();
  const img = new ImageData(GW, GH), px = img.data;
  for (let i = 0; i < grid.length; i++) {
    if (grid[i] < 0.02) continue;
    const j = Math.min(255, Math.round(Math.log1p(grid[i]) * scale)) * 4;
    px[i * 4] = ramp[j]; px[i * 4 + 1] = ramp[j + 1]; px[i * 4 + 2] = ramp[j + 2]; px[i * 4 + 3] = ramp[j + 3];
  }
  const small = document.createElement("canvas");
  small.width = GW; small.height = GH;
  small.getContext("2d").putImageData(img, 0, 0);
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = "high";
  ctx.drawImage(small, 0, 0, GW * cell, GH * cell);
}

function renderMap() {
  const d = map.data;
  if (!d) return;
  const totals = Object.fromEntries(CATS.map((c) => [c, d.points.reduce((s, p) => s + p[c], 0)]));
  for (const c of CATS) $(`map-n-${c}`).textContent = compact(totals[c]);
  const poll = state.overview && state.overview.agent && state.overview.agent.pollSeconds;
  $("map-hint").textContent = `Where ${num(d.total)} alerts came from, ${rangeLabel(d.hours)}` +
    (d.unlocated ? ` (${num(d.unlocated)} without a location)` : "") +
    `. New alerts ripple in as the agent syncs${poll ? `, every ${poll}s` : ""}.`;
  drawMap();
}

// pings: an expanding ring in the category colour, with a 2px surface ring keeping the dot off the heat
function ping(ev) {
  const ll = where(ev);
  if (!ll || !map.show.has(ev.category)) return;
  map.pings.push({ ll, cat: ev.category, t0: performance.now() });
  if (!map.raf) map.raf = requestAnimationFrame(animatePings);
}
function animatePings(now) {
  const fx = $("map-fx"), box = $("map");
  const W = box.clientWidth, H = box.clientHeight, dpr = window.devicePixelRatio || 1;
  const ctx = fx.getContext("2d");
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, fx.width, fx.height);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  map.pings = map.pings.filter((p) => now - p.t0 < PING_MS);
  const colors = { banned: cssVar("--series-3"), blocked: cssVar("--series-1"), flagged: cssVar("--series-2") };
  const surface = cssVar("--surface");
  for (const p of map.pings) {
    const t = (now - p.t0) / PING_MS, [x, y] = project(p.ll, W, H);
    ctx.globalAlpha = 1 - t;
    if (!reducedMotion.matches) {
      ctx.beginPath();
      ctx.arc(x, y, 4 + 26 * (1 - Math.pow(1 - t, 3)), 0, Math.PI * 2);
      ctx.strokeStyle = colors[p.cat];
      ctx.lineWidth = 2;
      ctx.stroke();
    }
    ctx.beginPath();
    ctx.arc(x, y, 4.5, 0, Math.PI * 2);
    ctx.fillStyle = colors[p.cat];
    ctx.fill();
    ctx.strokeStyle = surface;
    ctx.lineWidth = 2;
    ctx.stroke();
  }
  ctx.globalAlpha = 1;
  map.raf = map.pings.length ? requestAnimationFrame(animatePings) : 0;
}

function renderFeed() {
  const items = map.feed.filter((e) => map.show.has(e.category));
  if (!items.length) return $("map-feed").replaceChildren(el("li", { class: "empty", text: "Waiting for alerts…" }));
  const today = new Date().toDateString();
  $("map-feed").replaceChildren(...items.map((e) => {
    const d = new Date(e.at * 1000);
    const what = [e.cn ? `${flag(e.cn)} ${country(e.cn)}` : "", short(e.scenario)].filter(Boolean).join(" · ");
    return el("li", { class: e.fresh ? "fresh" : null, title: [e.asName, e.target].filter(Boolean).join(" → ") },
      el("i", { class: `c-${e.category}` }),
      el("span", { class: "src" }, el("span", { class: "cat", text: CAT_LABEL[e.category] }), ` ${e.source || ""}`),
      el("span", { class: "t", text: d.toDateString() === today ? fmtHour.format(d) : fmtDay.format(d) }),
      el("span", { class: "what", text: what }));
  }));
  for (const e of map.feed) e.fresh = false;
}

function arrive(events) { // newest first from the API; play them oldest first, spread over the poll gap
  const list = events.slice().reverse(), gap = Math.min(700, (LIVE_MS * 0.8) / list.length);
  list.forEach((ev, i) => setTimeout(() => {
    ping(ev);
    map.feed.unshift({ ...ev, fresh: true });
    map.feed.length = Math.min(map.feed.length, FEED_MAX);
    renderFeed();
  }, i * gap));
  clearTimeout(map.refreshTimer); // the heat catches up once the pings have played
  map.refreshTimer = setTimeout(refreshMap, list.length * gap + 500);
}
async function refreshMap() {
  try {
    map.data = await getJSON(`/api/map?hours=${state.hours}`);
    renderMap();
  } catch { /* the next full refresh retries */ }
}
function setLive(cls, text, title) {
  const p = $("map-live");
  p.className = `pill live ${cls}`;
  p.lastChild.textContent = text;
  if (title) p.title = title;
}
async function pollLive() {
  clearTimeout(map.liveTimer);
  if (document.hidden) return setLive("", "Paused", "Live updates pause while the tab is hidden");
  try {
    await loadWorld();
    const r = await getJSON(`/api/live${map.cursor === null ? "" : `?after=${encodeURIComponent(map.cursor)}`}`);
    if (map.cursor === null) {
      map.feed = r.events.map((e) => ({ ...e, fresh: false }));
      renderFeed();
    } else if (r.events.length) arrive(r.events);
    map.cursor = r.cursor;
    setLive("ok", "Live", `Checked ${fmtHour.format(new Date())}`);
  } catch (err) {
    setLive("bad", "Offline", err.message);
  }
  map.liveTimer = setTimeout(pollLive, LIVE_MS);
}

$("map-filters").addEventListener("click", (evt) => {
  const btn = evt.target.closest("button[data-cat]");
  if (!btn) return;
  const cat = btn.dataset.cat, on = !map.show.has(cat);
  if (on) map.show.add(cat); else map.show.delete(cat);
  btn.setAttribute("aria-pressed", String(on));
  drawMap();
  renderFeed();
});
$("map-fx").addEventListener("pointermove", (evt) => {
  const r = evt.currentTarget.getBoundingClientRect(), mx = evt.clientX - r.left, my = evt.clientY - r.top;
  let best = null, bestD = map.radius * map.radius;
  for (const h of map.hit) {
    const d = (h.x - mx) ** 2 + (h.y - my) ** 2;
    if (d <= bestD) { best = h; bestD = d; }
  }
  if (!best) return hideTip();
  const p = best.p, name = p.cn ? `${flag(p.cn)} ${country(p.cn)}` : "Unknown country";
  showTip(evt, best.approx ? `${name} (country only)` : `${name}, near ${p.lat.toFixed(1)}, ${p.lon.toFixed(1)}`, [
    { value: num(best.n), label: `alert${best.n === 1 ? "" : "s"} here, ${rangeLabel(map.data.hours)}` },
    ...CATS.filter((c) => map.show.has(c)).map((c) => ({ value: num(p[c]), label: CAT_LABEL[c], cls: `c-${c}` })),
  ]);
});
$("map-fx").addEventListener("pointerleave", hideTip);
document.addEventListener("visibilitychange", () => { if (!document.hidden) pollLive(); });
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", drawMap);

// ---------- data ----------
async function getJSON(url) {
  const resp = await fetch(url, { cache: "no-store" });
  if (!resp.ok) throw new Error(`${url}: HTTP ${resp.status}`);
  return resp.json();
}
async function load() {
  const content = $("content");
  content.classList.add("loading"); // refetch keeps the frame
  try {
    const q = encodeURIComponent(state.query);
    const [overview, alerts, places] = await Promise.all([
      getJSON(`/api/overview?hours=${state.hours}`),
      getJSON(`/api/alerts?hours=${state.hours}&limit=1000&q=${q}`),
      getJSON(`/api/map?hours=${state.hours}`),
      loadWorld(),
    ]);
    state.overview = overview;
    state.alerts = alerts.alerts;
    map.data = places;
    render();
  } catch (err) {
    $("updated").textContent = `Couldn't refresh: ${err.message}`;
  } finally {
    content.classList.remove("loading");
    clearTimeout(state.timer);
    state.timer = setTimeout(load, REFRESH_MS);
  }
}

// ---------- controls ----------
function readHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  const h = parseInt(p.get("hours"), 10);
  if ([24, 168, 720, 2160].includes(h)) state.hours = h;
  state.query = p.get("q") || "";
  $("search").value = state.query;
  for (const b of $("range").querySelectorAll("button")) b.setAttribute("aria-pressed", String(+b.dataset.hours === state.hours));
}
function writeHash() {
  const p = new URLSearchParams({ hours: state.hours });
  if (state.query) p.set("q", state.query);
  history.replaceState(null, "", `#${p}`);
}
$("range").addEventListener("click", (evt) => {
  const b = evt.target.closest("button");
  if (!b) return;
  state.hours = +b.dataset.hours;
  for (const x of $("range").querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));
  writeHash();
  load();
});
$("search").addEventListener("input", () => {
  clearTimeout(state.searchTimer);
  state.searchTimer = setTimeout(() => { state.query = $("search").value.trim(); writeHash(); load(); }, 300);
});
$("theme").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : window.matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("theme", document.documentElement.dataset.theme); } catch { /* private mode */ }
  drawMap();
});
try { const t = localStorage.getItem("theme"); if (t) document.documentElement.dataset.theme = t; } catch { /* private mode */ }
let resizeTimer;
window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { drawMap(); if (state.overview) renderTimeline(state.overview); }, 150); });

readHash();
load();
pollLive();
