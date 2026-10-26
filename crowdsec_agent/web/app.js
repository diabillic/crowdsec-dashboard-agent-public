// CrowdSec dashboard. Everything from the API is inserted with textContent, never as HTML.
"use strict";

const REFRESH_MS = 60000;
const state = { hours: 24, query: "", overview: null, alerts: null, timer: null, searchTimer: null };
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

function renderAlerts() {
  const list = (state.alerts || []);
  const rows = list.slice(0, 300).map((a) => el("tr", {},
    td(when(a.created_at), "when"), td(a.value || a.ip, "mono"), countryCell(a.cn),
    td(a.as_name, "clip", a.as_name ? `${a.as_name} (AS${a.as_number})` : ""), td(short(a.scenario), "clip", a.message || a.scenario),
    el("td", {}, kindBadge(a.kind)), td(a.target, "clip", a.target), td(a.uri, "clip mono", a.uri),
    el("td", {}, a.decision ? el("span", { class: `badge ${a.decision === "ban" ? "ban" : ""}`, text: a.decision }) : null,
      a.simulated ? el("span", { class: "badge", text: "simulated" }) : null)));
  table("alerts", [{ label: "Time" }, { label: "Source" }, { label: "Country" }, { label: "Network" }, { label: "Scenario" },
    { label: "Kind" }, { label: "Target" }, { label: "Path" }, { label: "Decision" }], rows);
  $("alerts-hint").textContent = state.query
    ? `${num(list.length)}${list.length >= 1000 ? "+" : ""} alerts matching “${state.query}”, ${rangeLabel(state.hours)}`
    : `Newest first, ${rangeLabel(state.hours)}`;
  $("alerts-more").textContent = list.length > 300 ? `Showing the newest 300. Narrow it down with the filter.` : "";
}

function render() {
  const o = state.overview;
  if (!o) return;
  renderStatus(o);
  renderTiles(o);
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
    const [overview, alerts] = await Promise.all([
      getJSON(`/api/overview?hours=${state.hours}`),
      getJSON(`/api/alerts?hours=${state.hours}&limit=1000&q=${q}`),
    ]);
    state.overview = overview;
    state.alerts = alerts.alerts;
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
});
try { const t = localStorage.getItem("theme"); if (t) document.documentElement.dataset.theme = t; } catch { /* private mode */ }
let resizeTimer;
window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => state.overview && renderTimeline(state.overview), 150); });

readHash();
load();
