// MiniSOC web UI. Same model as the Quickshell widget: a read-only view of
// the state the engine publishes, every action through the `minisoc` CLI
// (POST /api/action). Data is only ever inserted as text (textContent), never
// as HTML.
"use strict";

const SEV = ["critical", "high", "medium", "low", "info", "unknown"];
const SEV_SHORT = { critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW", info: "INFO" };
const TOKEN_KEY = "minisoc.token";
const PREF_KEY = "minisoc.prefs";

const S = {
  token: "",
  st: {},
  stateKey: "",
  generatedAt: "",
  ui: {},
  tab: "active",
  selectedId: "",
  details: null,
  draft: "",
  explain: null,
  note: "",
  search: "",
  sev: new Set(),
  hidden: {},
  seen: {},
  notifyInit: false,
  notifySent: [], // ms timestamps, last minute
  notifyLastByFp: {}, // fingerprint -> ms of its last notification
  notifySuppressed: [],
  notifySummary: null,
  prefs: { notify: false },
  error: "",
  deepAlert: "",
};

// ------------------------------------------------------------------ helpers

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    // Through the CSSOM: the CSP (style-src 'self') blocks style attributes.
    else if (k === "style") {
      for (const decl of String(v).split(";")) {
        const i = decl.indexOf(":");
        if (i > 0) el.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim());
      }
    }
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function btn(label, cls, onClick, opts = {}) {
  const b = h("button", { class: "btn " + (cls || ""), type: "button", title: opts.title }, label);
  let armed = null;
  b.addEventListener("click", (ev) => {
    ev.stopPropagation();
    if (opts.confirm && !armed) {
      b.classList.add("confirming");
      b.textContent = "CONFIRM?";
      armed = setTimeout(() => { armed = null; b.classList.remove("confirming"); b.textContent = label; }, 3000);
      return;
    }
    if (armed) { clearTimeout(armed); armed = null; }
    onClick();
  });
  return b;
}

function sevOf(s) { return SEV.includes(s) ? s : "unknown"; }

function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  const now = new Date();
  const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  if (d.toDateString() === now.toDateString()) return hm;
  return d.toLocaleDateString([], { day: "2-digit", month: "2-digit" }) + " " + hm;
}

function ago(ts) {
  if (!ts) return "?";
  const s = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
  if (isNaN(s)) return "?";
  const span = (n) => n < 60 ? n + " s" : n < 3600 ? Math.round(n / 60) + " min"
    : n < 86400 ? Math.round(n / 3600) + " h" : Math.round(n / 86400) + " d";
  return s < 0 ? "in " + span(-s) : span(s) + " ago";
}

function toast(msg, err) {
  const t = h("div", { class: "toast" + (err ? " err" : "") }, msg);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), err ? 9000 : 4500);
}

function loadPrefs() {
  try { Object.assign(S.prefs, JSON.parse(localStorage.getItem(PREF_KEY) || "{}")); } catch (e) { /* defaults */ }
}
function savePrefs() {
  try { localStorage.setItem(PREF_KEY, JSON.stringify(S.prefs)); } catch (e) { /* private mode */ }
}

// ------------------------------------------------------------------ API

class AuthError extends Error {}

async function api(path, opts = {}) {
  const res = await fetch("/api/" + path, {
    method: opts.method || "GET",
    headers: Object.assign({ Authorization: "Bearer " + S.token },
      opts.body ? { "Content-Type": "application/json" } : {}),
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    cache: "no-store",
  });
  if (res.status === 401) throw new AuthError("unauthorized");
  const type = res.headers.get("Content-Type") || "";
  const data = type.startsWith("application/json") ? await res.json() : await res.text();
  if (!res.ok) {
    const msg = (data && (data.error || data.output)) || res.statusText;
    const e = new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    e.status = res.status;
    throw e;
  }
  return data;
}

async function act(action, id, extra) {
  try {
    const r = await api("action", { method: "POST", body: Object.assign({ action, id }, extra || {}) });
    setTimeout(poll, 300);
    if (S.selectedId) setTimeout(loadDetails, 600);
    return r;
  } catch (e) {
    if (e instanceof AuthError) return showLogin();
    toast((e.message || String(e)).trim(), true);
    throw e;
  }
}

// ------------------------------------------------------------------ token

// Fragment: token=<hex> (from `minisoc web --url`), alert=<id>, tab=<name>.
// The fragment never reaches the server; the token is dropped from the
// address bar once stored.
function takeTokenFromUrl() {
  const p = new URLSearchParams(location.hash.slice(1));
  if (/^[\w.:-]{1,128}$/.test(p.get("alert") || "")) S.deepAlert = p.get("alert");
  if (["active", "closed", "filtered", "rules", "proposals", "ai"].includes(p.get("tab"))) S.tab = p.get("tab");
  const tok = p.get("token") || "";
  if (/^[0-9a-fA-F]{64}$/.test(tok)) {
    S.token = tok;
    try { localStorage.setItem(TOKEN_KEY, S.token); } catch (e) { /* private mode */ }
    p.delete("token");
    history.replaceState(null, "", location.pathname + (p.toString() ? "#" + p.toString() : ""));
    return;
  }
  try { S.token = localStorage.getItem(TOKEN_KEY) || ""; } catch (e) { S.token = ""; }
}

function showLogin() {
  S.token = "";
  try { localStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ }
  const app = document.getElementById("app");
  const input = h("input", { class: "search", placeholder: "http://127.0.0.1:…/#token=… or the token", autocomplete: "off", spellcheck: "false" });
  const go = () => {
    const m = input.value.match(/([0-9a-fA-F]{64})/);
    if (!m) return toast("No token found in that text.", true);
    location.hash = "token=" + m[1];
    location.reload();
  };
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  app.replaceChildren(h("div", { class: "login brackets" }, h("span", { class: "b1" }), h("span", { class: "b2" }),
    h("h1", {}, "MINISOC"),
    h("p", {}, "This page needs the access token of your MiniSOC web service. Open the address printed by:"),
    h("pre", {}, "minisoc web --url"),
    h("p", { class: "muted" }, "or paste it here. The token stays in this browser; it changes when your session ends."),
    input,
    btn("Open", "accent", go)));
  input.focus();
  stopPolling();
}

// ------------------------------------------------------------------ theme

function applyUi(ui) {
  S.ui = ui || {};
  const c = S.ui.colors || {};
  const map = {
    background: "--bg", panel: "--panel", border: "--border", foreground: "--fg", muted: "--muted",
    accent: "--accent", ai: "--ai", critical: "--critical", high: "--high", medium: "--medium",
    low: "--low", info: "--info", unknown: "--unknown",
  };
  const root = document.documentElement.style;
  for (const [k, v] of Object.entries(map)) {
    // #AARRGGBB (Qt) -> #RRGGBBAA (CSS)
    let col = c[k];
    if (typeof col !== "string" || !/^#[0-9a-fA-F]{3,8}$/.test(col)) continue;
    if (col.length === 9) col = "#" + col.slice(3) + col.slice(1, 3);
    root.setProperty(v, col);
  }
  const font = (f) => typeof f === "string" && /^[\w\s,."'-]+$/.test(f);
  if (font(S.ui.font)) root.setProperty("--font", S.ui.font + ", system-ui, sans-serif");
  if (font(S.ui.monoFont)) root.setProperty("--mono", S.ui.monoFont + ", ui-monospace, monospace");
  if (Number.isFinite(S.ui.radius)) root.setProperty("--radius", Math.max(0, Math.min(16, S.ui.radius)) + "px");
}

// ------------------------------------------------------------------ data

function shown(list) {
  return (list || []).filter((e) => e && !e.closed && !e.discarded && !S.hidden[e.id]);
}
function matches(e) {
  if (S.sev.size && !S.sev.has(sevOf(e.severity))) return false;
  if (!S.search) return true;
  const q = S.search.toLowerCase();
  return [e.message, e.source, e.event_type, e.id, e.filtered_by, e.analysis && e.analysis.classification]
    .some((x) => typeof x === "string" && x.toLowerCase().includes(q));
}
function pinnedList() { return shown(S.st.pinned); }
function feedList() {
  const pinned = new Set(pinnedList().map((e) => e.id));
  return shown(S.st.recent).filter((e) => !pinned.has(e.id));
}
function engineAlive() {
  return S.generatedAt !== "" && Date.now() - new Date(S.generatedAt).getTime() < 45000;
}

let pollTimer = null;
function stopPolling() { if (pollTimer) clearInterval(pollTimer); pollTimer = null; }

async function poll() {
  let text;
  try {
    text = await fetch("/api/state", { headers: { Authorization: "Bearer " + S.token }, cache: "no-store" })
      .then(async (r) => {
        if (r.status === 401) throw new AuthError();
        if (!r.ok) {
          let msg = r.statusText;
          try { msg = (await r.json()).error || msg; } catch (e) { /* keep */ }
          throw new Error(msg);
        }
        return r.text();
      });
  } catch (e) {
    if (e instanceof AuthError) return showLogin();
    S.error = e.message || "web service unreachable";
    renderHeader();
    renderContent();
    return;
  }
  S.error = "";
  let parsed;
  try { parsed = JSON.parse(text); } catch (e) { return; }
  S.generatedAt = parsed.generated_at || "";
  renderHeader();
  // Only real changes rebuild the lists (scroll and hover kept).
  const key = text.replace(/"generated_at":"[^"]*"/, "");
  if (key === S.stateKey) return;
  S.stateKey = key;
  S.st = parsed;
  // Forget local hides the engine has caught up with.
  const live = new Set([...(S.st.pinned || []), ...(S.st.recent || [])].filter((e) => !e.discarded).map((e) => e.id));
  const kept = {};
  for (const id in S.hidden) if (live.has(id)) kept[id] = true;
  S.hidden = kept;
  notifyAlerts(parsed);
  renderAll();
}

// ------------------------------------------------------- browser notifications

function notifyAlerts(st) {
  const nc = S.ui.notify || {};
  const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const want = rank[nc.minimumSeverity] !== undefined ? rank[nc.minimumSeverity] : 1;
  const fresh = [];
  for (const e of st.recent || []) {
    if (!e || !e.id || S.seen[e.id]) continue;
    S.seen[e.id] = true;
    if (!S.notifyInit) continue; // first load only learns
    if (e.discarded || e.filtered_by) continue;
    if ((rank[e.severity] ?? -1) < want) continue;
    fresh.push(e);
  }
  S.notifyInit = true;
  const ids = Object.keys(S.seen);
  if (ids.length > 2000) {
    const s = {};
    for (const id of ids.slice(ids.length - 1000)) s[id] = true;
    S.seen = s;
  }
  if (!S.prefs.notify || !("Notification" in window) || Notification.permission !== "granted") return;
  // Same limits as the widget: one per similarity group per cooldown, at
  // most maxPerMinute, the rest in one summary a minute later.
  const now = Date.now();
  const perMinute = nc.maxPerMinute > 0 ? nc.maxPerMinute : 6;
  const cooldown = (nc.cooldown >= 0 ? nc.cooldown : 300) * 1000;
  S.notifySent = S.notifySent.filter((t) => now - t < 60000);
  for (const fp in S.notifyLastByFp) if (now - S.notifyLastByFp[fp] >= cooldown) delete S.notifyLastByFp[fp];
  for (const e of fresh) {
    const fp = e.fingerprint || e.id;
    if (S.notifyLastByFp[fp] !== undefined || S.notifySent.length >= perMinute) {
      S.notifySuppressed.push(e);
      if (!S.notifySummary) S.notifySummary = setTimeout(notifySummary, 60000);
      continue;
    }
    S.notifyLastByFp[fp] = now;
    S.notifySent.push(now);
    const n = new Notification((e.severity || "?").toUpperCase() + " — " + (e.source || "minisoc"), {
      body: e.message || "",
      tag: fp,
      icon: "/icon.svg",
      requireInteraction: e.severity === "critical" || e.severity === "high",
    });
    n.onclick = () => { window.focus(); select(e.id); };
  }
}

function notifySummary() {
  const list = S.notifySuppressed;
  S.notifySuppressed = [];
  S.notifySummary = null;
  if (!list.length || Notification.permission !== "granted") return;
  const by = {};
  for (const e of list) by[e.source || "minisoc"] = (by[e.source || "minisoc"] || 0) + 1;
  S.notifySent.push(Date.now());
  new Notification(list.length + " more alert(s) not notified", {
    body: Object.keys(by).sort((a, b) => by[b] - by[a]).map((k) => k + " ×" + by[k]).join(", "),
    tag: "minisoc-summary",
    icon: "/icon.svg",
  });
}

async function toggleNotify() {
  if (!("Notification" in window)) return toast("This browser has no notifications.", true);
  if (!S.prefs.notify && Notification.permission !== "granted") {
    const p = await Notification.requestPermission();
    if (p !== "granted") return toast("Notifications refused by the browser.", true);
  }
  S.prefs.notify = !S.prefs.notify;
  savePrefs();
  renderHeader();
}

// ------------------------------------------------------------------ details

async function loadDetails() {
  const id = S.selectedId;
  if (!id) return;
  try {
    const d = await api("show/" + encodeURIComponent(id));
    if (S.selectedId === id) { S.details = d; renderDetails(); }
  } catch (e) {
    if (e instanceof AuthError) return showLogin();
    if (S.selectedId === id) { S.details = { error: e.message }; renderDetails(); }
  }
}

function select(id) {
  if (S.selectedId === id) return closeDetails();
  S.selectedId = id;
  S.details = null;
  S.draft = "";
  S.explain = null;
  S.note = "";
  renderDetails();
  renderContent();
  loadDetails();
}

function closeDetails() {
  S.selectedId = "";
  S.details = null;
  S.draft = "";
  S.explain = null;
  S.note = "";
  renderDetails();
  renderContent();
}

function hideLocally(ids) {
  const hh = Object.assign({}, S.hidden);
  for (const id of ids) hh[id] = true;
  S.hidden = hh;
}

async function verdict(kind, id) {
  hideLocally([id]);
  if (S.selectedId === id) closeDetails(); else renderContent();
  renderNav();
  try { await act(kind, id); } catch (e) { delete S.hidden[id]; renderAll(); }
}

async function closeAllFp() {
  const ids = shown(S.st.recent).filter((e) => !e.pinned).map((e) => e.id);
  hideLocally(ids);
  if (S.selectedId && S.hidden[S.selectedId]) closeDetails();
  renderAll();
  try {
    const r = await act("fp-all");
    toast((r.output || "Closed as false positive.").trim());
  } catch (e) { S.hidden = {}; renderAll(); }
}

async function draftFilter(id) {
  try {
    S.draft = await api("draft/" + encodeURIComponent(id));
    S.explain = null;
    renderDetails();
  } catch (e) {
    if (e instanceof AuthError) return showLogin();
    toast(e.message, true);
  }
}

async function explain(id) {
  try {
    S.explain = await api("explain/" + encodeURIComponent(id));
    S.draft = "";
    renderDetails();
  } catch (e) {
    if (e instanceof AuthError) return showLogin();
    toast(e.message, true);
  }
}

function openModal(title, content) {
  const bg = h("div", { class: "modal-bg", onclick: (e) => { if (e.target === bg) bg.remove(); } },
    h("div", { class: "modal brackets" }, h("span", { class: "b1" }), h("span", { class: "b2" }),
      h("div", { class: "mhead" }, h("span", { class: "t" }, title), btn("✕ Close", "", () => bg.remove())),
      h("div", { class: "mbody" }, content)));
  document.body.append(bg);
}

async function showText(title, path) {
  try {
    const t = await api(path);
    openModal(title, h("pre", {}, typeof t === "string" ? t : JSON.stringify(t, null, 2)));
  } catch (e) {
    if (e instanceof AuthError) return showLogin();
    toast(e.message, true);
  }
}

// ------------------------------------------------------------------ render

let els = {};

function skeleton() {
  const search = h("input", {
    class: "search", type: "search", placeholder: "Search alerts  ( / )", spellcheck: "false",
    oninput: (e) => { S.search = e.target.value.trim(); renderContent(); },
  });
  els = {
    live: h("div", { class: "live" }),
    counters: h("div", { class: "counters" }),
    search,
    notify: h("div"),
    nav: h("nav"),
    toolbar: h("div", { class: "toolbar" }),
    list: h("div", { class: "list" }),
    details: h("aside", { class: "details hidden" }),
  };
  document.getElementById("app").replaceChildren(
    h("header", {},
      h("div", { class: "brand" }, h("img", { src: "/icon.svg", alt: "" }), "MINISOC"),
      els.live, els.counters, h("div", { class: "spacer" }), els.search, els.notify),
    h("main", {}, els.nav, h("section", { class: "content" }, els.toolbar, els.list), els.details));
}

function renderAll() {
  renderHeader();
  renderNav();
  renderContent();
  renderDetails();
}

function renderHeader() {
  if (!els.live) return;
  const alive = engineAlive();
  els.live.replaceChildren(
    h("span", { class: "dot " + (S.error ? "off" : alive ? "on" : "off") }),
    S.error ? "OFFLINE" : alive ? "ENGINE LIVE" : "ENGINE STALE",
    S.generatedAt ? h("span", { title: S.generatedAt }, " · " + ago(S.generatedAt)) : null);
  const by = (S.st.counts || {}).active_by_severity || {};
  els.counters.replaceChildren(...SEV.filter((s) => s !== "unknown" || by.unknown).map((s) =>
    h("span", {
      class: "chip" + (S.sev.has(s) ? " sel" : ""),
      style: "--c: var(--" + s + ")",
      title: "Show only " + s + " (click again to clear)",
      onclick: () => { S.sev.has(s) ? S.sev.delete(s) : S.sev.add(s); renderHeader(); renderContent(); },
    }, (SEV_SHORT[s] || "UNK"), h("b", {}, by[s] || 0))));
  const on = S.prefs.notify && "Notification" in window && Notification.permission === "granted";
  els.notify.replaceChildren(btn(on ? "Notify: on" : "Notify: off", on ? "accent" : "", toggleNotify,
    { title: "Browser notifications for new alerts (ui.json notify.minimumSeverity)" }));
}

function navButton(id, label, n, cls) {
  return h("button", {
    class: (S.tab === id ? "active " : "") + (cls || ""), type: "button",
    onclick: () => { S.tab = id; renderNav(); renderContent(); els.list.scrollTop = 0; },
  }, h("span", { class: "lbl" }, label), h("span", { class: "n" }, n));
}

function renderNav() {
  const c = S.st.counts || {};
  const f = S.st.filter || {};
  const active = pinnedList().length + feedList().length;
  els.nav.replaceChildren(
    h("div", { class: "group" }, "ALERTS"),
    navButton("active", "ACTIVE", active),
    navButton("closed", "CLOSED", c.closed || 0),
    navButton("filtered", "FILTERED", c.filtered || 0),
    h("div", { class: "group" }, "TUNING"),
    navButton("rules", "RULES", f.rules || 0),
    navButton("proposals", "AI PROPOSALS", (S.st.proposals || []).length, "ai-tab"),
    navButton("ai", "AI", (S.st.ai || {}).enabled ? ((S.st.ai || {}).state || "on").toUpperCase() : "OFF", "ai-tab"));
}

function alertRow(e, mode) {
  const sev = sevOf(e.severity);
  const an = e.analysis || {};
  const meta = [
    h("span", {}, [(e.source || ""), (e.event_type || "")].filter(Boolean).join(" · ")),
    e.pinned ? h("span", { class: "pin" }, "◆ PINNED") : null,
    an.classification ? h("span", { class: "aiv" }, "AI·" + an.classification.toUpperCase()) : null,
    mode === "closed" ? h("span", { class: e.verdict === "tp" ? "verdict-tp" : "" },
      (e.verdict === "tp" ? "TRUE POSITIVE" : "FALSE POSITIVE") + " · by " + (e.closed_by || e.discarded_by || "?")) : null,
    mode === "filtered" && e.filtered_by ? h("span", {}, "rule " + e.filtered_by) : null,
  ];
  const quick = mode === "active" ? [
    btn(e.pinned ? "Unpin" : "Pin", "accent", () => act(e.pinned ? "unpin" : "pin", e.id)),
    btn("TP", "tp", () => verdict("tp", e.id), { title: "True positive: real activity, handled" }),
    btn("FP", "", () => verdict("fp", e.id), { title: "False positive: noise (the AI filter review learns from it)" }),
  ] : mode === "closed" ? [btn("Reopen", "", () => act("reopen", e.id))] : [];
  return h("div", {
    class: "row sev-" + sev + (S.selectedId === e.id ? " selected" : ""),
    onclick: () => select(e.id),
  },
  h("div", { class: "bar" }),
  h("div", { class: "sev" }, SEV_SHORT[sev] || "UNK"),
  h("div", { class: "msg" }, h("div", { class: "text" }, e.message || ""), h("div", { class: "meta" }, meta)),
  h("div", { class: "right" },
    e.occurrences > 1 ? h("div", { class: "occ" }, "×" + e.occurrences) : null,
    h("div", { title: e.timestamp || "" }, fmtTime(e.last_seen || e.timestamp)),
    h("div", { class: "quick" }, quick)));
}

function renderContent() {
  if (!els.list) return;
  const scroll = els.list.scrollTop;
  const tb = [];
  const out = [];
  if (S.error) out.push(h("div", { class: "empty" }, "⚠ " + S.error));
  const c = S.st.counts || {};
  switch (S.tab) {
    case "active": {
      const pinned = pinnedList().filter(matches);
      const feed = feedList().filter(matches);
      tb.push(h("span", { class: "title" }, "ACTIVE ALERTS"),
        h("span", { class: "muted mono" }, String(pinned.length + feed.length)),
        h("div", { class: "spacer" }),
        btn("Close all as FP", "danger", closeAllFp, { confirm: true, title: "Every active alert except the pinned ones" }));
      if (pinned.length) out.push(h("div", { class: "sectionhead" }, "PINNED"), pinned.map((e) => alertRow(e, "active")));
      if (feed.length) {
        if (pinned.length) out.push(h("div", { class: "sectionhead" }, "FEED"));
        out.push(feed.map((e) => alertRow(e, "active")));
      }
      if (!pinned.length && !feed.length && !S.error) {
        out.push(h("div", { class: "empty" }, S.search || S.sev.size ? "No active alert matches." : "No active alert. All quiet."));
      }
      break;
    }
    case "closed": {
      const list = (S.st.closed || []).filter(matches);
      tb.push(h("span", { class: "title" }, "CLOSED"),
        h("span", { class: "muted mono" }, "TP " + (c.closed_tp || 0) + " · FP " + (c.closed_fp || 0) + " · by AI " + (c.closed_by_ai || 0)));
      out.push(list.length ? list.map((e) => alertRow(e, "closed"))
        : h("div", { class: "empty" }, "No closed alert. TP = real activity, handled; FP = noise. Closing never deletes logs; re-open anytime."));
      break;
    }
    case "filtered": {
      const list = (S.st.filtered || []).filter(matches);
      tb.push(h("span", { class: "title" }, "EXCLUDED BY A RULE"), h("span", { class: "muted mono" }, String(c.filtered || 0)));
      out.push(list.length ? list.map((e) => alertRow(e, "filtered")) : h("div", { class: "empty" }, "No alert excluded by a rule."));
      break;
    }
    case "rules": renderRules(tb, out); break;
    case "proposals": renderProposals(tb, out); break;
    case "ai": renderAi(tb, out); break;
  }
  els.toolbar.replaceChildren(...tb);
  els.list.replaceChildren(...out.flat(Infinity).filter(Boolean));
  els.list.scrollTop = scroll;
}

function renderRules(tb, out) {
  const f = S.st.filter || {};
  tb.push(h("span", { class: "title" }, "FILTER RULES"), h("div", { class: "spacer" }),
    btn("View my rules", "", () => showText("alert_filter.yaml — " + (f.user_file || ""), "rules/user")),
    btn("View AI rules", "aitint", () => showText("ai_filters.yaml — " + (f.ai_file || ""), "rules/ai")),
    (f.backups || 0) > 0 ? btn("Rollback last change", "danger", () => act("rollback").then((r) => toast((r.output || "Restored.").trim())), { confirm: true }) : null);
  for (const fl of f.files || []) {
    out.push(h("div", { class: "filestat" + (fl.error ? " err" : fl.warning ? " warn" : "") },
      (fl.owner || (fl.writable ? "user" : "system")).toUpperCase() + "  " + fl.path + " — " + fl.rules + " rule(s)",
      fl.error ? "  ✗ " + fl.error + (fl.using_last_good ? " (last valid version in force)" : "") : "",
      fl.warning ? "  ! " + fl.warning : ""));
  }
  const rules = (f.list || []).filter((r) => !S.search || JSON.stringify(r).toLowerCase().includes(S.search.toLowerCase()));
  const max = Math.max(1, ...rules.map((r) => r.hits || 0));
  out.push(h("div", { class: "sectionhead" }, "RULES — alerts excluded since the rule was created or last changed, and over the recent window"));
  for (const r of rules) {
    const isAi = r.owner === "ai";
    out.push(h("div", { class: "card" + (isAi ? " aicard" : "") },
      h("div", { class: "top" },
        h("span", { class: "id", style: r.enabled ? "" : "color: var(--muted)" }, r.id),
        isAi ? h("span", { class: "tag ai" }, "AI") : h("span", { class: "tag muted" }, (r.owner || "user").toUpperCase()),
        !isAi && r.generated_by ? h("span", { class: "tag ai", title: "written by " + r.generated_by }, "AI-MADE") : null,
        h("span", { class: "stats", title: r.last_hit ? "last hit " + r.last_hit : "" },
          r.enabled ? (r.hits || 0) + " since " + fmtTime(r.since) + " · " + (r.recent_hits || 0) + " in " + (r.recent_days || 14) + " d" : "disabled")),
      r.description ? h("div", { class: "desc" }, r.description) : null,
      h("div", { class: "match" }, JSON.stringify(r.match)),
      h("div", { class: "hits" }, h("div", { style: "width:" + Math.round(100 * (r.hits || 0) / max) + "%" }))));
  }
  if (!rules.length) out.push(h("div", { class: "empty" }, "No rule."));
}

function renderProposals(tb, out) {
  const ps = S.st.proposals || [];
  tb.push(h("span", { class: "title" }, "AI PROPOSALS"), h("span", { class: "muted mono" }, "pending " + ps.length));
  if (!ps.length) out.push(h("div", { class: "empty" }, "No pending AI proposal."));
  for (const p of ps) {
    const pl = p.payload || {};
    const kind = p.kind === "filter" ? "NEW EXCLUSION RULE"
      : p.kind === "review" ? "FILTER REVIEW: " + (pl.action || "").toUpperCase() + " " + (pl.id || "")
      : "CLOSE AS FP";
    out.push(h("div", { class: "card aicard" },
      h("div", { class: "top" }, h("span", { class: "id ai" }, "#" + p.id + " · " + kind),
        h("span", { class: "stats" }, "confidence " + Math.round((p.confidence || 0) * 100) + "%")),
      p.event_id ? h("div", {}, "[" + (p.severity || "?") + "] " + (p.source || "") + " — " + (p.message || "")) : null,
      p.reason ? h("div", { class: "desc" }, "why: " + p.reason) : null,
      pl.rule ? h("div", { class: "match" }, JSON.stringify(pl.rule.match)) : null,
      pl.reasons ? h("div", { class: "desc" }, pl.reasons.join(" · ")) : null,
      h("div", { class: "actions" },
        btn("Accept", "aitint", () => act("accept", String(p.id)), { confirm: p.kind !== "discard" }),
        btn("Reject", "", () => act("reject", String(p.id))),
        p.event_id ? btn("Alert", "", () => { S.tab = "active"; renderNav(); select(p.event_id); }) : null)));
  }
}

function renderAi(tb, out) {
  const ai = S.st.ai || { enabled: false };
  const c = S.st.counts || {};
  const rv = ai.filter_review || { mode: "off" };
  tb.push(h("span", { class: "title" }, "AI"), h("div", { class: "spacer" }),
    ai.enabled && rv.mode !== "off" ? btn("Review dry run", "aitint", async () => {
      toast("Filter review (dry run) running — this calls the model…");
      try {
        const r = await act("review-dry-run");
        let body = r.output;
        try { body = JSON.stringify(JSON.parse(r.output), null, 2); } catch (e) { /* text */ }
        openModal("Filter review — dry run (nothing applied)", h("pre", {}, body));
      } catch (e) { /* toasted */ }
    }) : null,
    ai.enabled && rv.mode !== "off" ? btn("Run review now", "aitint", () => act("review").then(() => toast("Filter review started.")), { confirm: true }) : null);
  if (!ai.enabled) {
    out.push(h("div", { class: "empty" }, "AI analysis is disabled. MiniSOC works fully without it (services.minisoc.ai.enable)."));
  } else {
    const kv = (k, v, cls) => [h("div", { class: "k" }, k), h("div", { class: cls || "" }, v)];
    out.push(h("div", { class: "card aicard" }, h("div", { class: "statgrid" },
      kv("provider", ai.provider + " / " + ai.model, "ai"),
      kv("endpoint", (ai.endpoint_host || "") + (ai.remote ? "   ⚠ REMOTE: redacted alerts leave this machine" : "   (local)"), ai.remote ? "warnline" : ""),
      kv("state", ai.state + " · queue " + ai.queue + " · in flight " + ai.in_flight + " · dropped " + ai.dropped),
      kv("today", ai.requests_today + " / " + ai.daily_quota + " requests, " + ai.errors_today + " error(s)"),
      kv("policies", "auto-close FP: " + ai.auto_discard + " · auto-filter: " + ai.auto_filter),
      kv("analyzed", (c.analyzed || 0) + " · closed as FP by AI " + (c.closed_by_ai || 0)),
      ai.last_success ? kv("last success", fmtTime(ai.last_success) + " (" + ago(ai.last_success) + ")") : null,
      ai.last_error ? kv("last error", ai.last_error, "warnline") : null)));
    const rep = rv.report || null;
    out.push(h("div", { class: "sectionhead" }, "FILTER REVIEW — AI rules learnt from your FP / TP closures"),
      h("div", { class: "card aicard" }, h("div", { class: "statgrid" },
        kv("mode", rv.mode + (rv.mode !== "off" ? " · every " + rv.interval_hours + " h" : "")),
        rv.mode !== "off" ? kv("last run", rv.last_run ? fmtTime(rv.last_run) + " (" + ago(rv.last_run) + ")" : "never") : null,
        rv.mode !== "off" ? kv("next run", rv.next_run ? fmtTime(rv.next_run) : "?") : null,
        rep ? kv("report", (rep.skipped || rep.summary || "") + "  (" + (rep.applied || []).length + " applied, "
          + (rep.proposed || []).length + " proposed, " + (rep.rejected || []).length + " rejected by the guardrails)") : null,
        rv.error ? kv("last error", rv.error, "warnline") : null)));
  }
  out.push(h("div", { class: "sectionhead" }, "PROMPTS — edit with `minisoc prompts edit <name>`; changes apply to the next request"),
    h("div", { class: "actions", style: "display:flex;gap:6px;flex-wrap:wrap" },
      ["system", "analysis", "enrichment", "classification", "filter", "review"].map((n) =>
        btn("View " + n, "aitint", () => showText("Prompt: " + n, "prompt/" + n)))));
}

function kv(k, v, color) {
  if (v === undefined || v === null || v === "" || v === "undefined") return [];
  return [h("div", { class: "k" }, k), h("div", { class: "v", style: color ? "color:" + color : "" }, String(v))];
}

function flatten(obj, depth, out) {
  for (const k of Object.keys(obj || {})) {
    const v = obj[k];
    if (v !== null && typeof v === "object" && !(Array.isArray(v) && v.every((x) => x === null || typeof x !== "object"))) {
      out.push({ depth, key: k, value: Array.isArray(v) ? "[" + v.length + "]" : "", container: true });
      flatten(v, depth + 1, out);
    } else {
      out.push({ depth, key: k, value: Array.isArray(v) ? v.join(", ") : String(v), container: false });
    }
  }
  return out;
}

function bullets(title, items) {
  if (!items || !items.length) return null;
  return [h("div", { class: "bullets-title" }, title), h("ul", { class: "bullets" }, items.map((i) => h("li", {}, String(i))))];
}

function renderDetails() {
  const aside = els.details;
  if (!aside) return;
  if (!S.selectedId) { aside.classList.add("hidden"); aside.replaceChildren(); return; }
  aside.classList.remove("hidden");
  const bodyEl = aside.querySelector(".body");
  const scroll = bodyEl ? bodyEl.scrollTop : 0;
  const d = S.details;
  if (!d) {
    aside.replaceChildren(h("div", { class: "head" }, h("div", { class: "kicker" }, "LOADING…", btn("✕", "", closeDetails))));
    return;
  }
  if (d.error) {
    aside.replaceChildren(h("div", { class: "head" }, h("div", { class: "kicker" }, "ERROR", btn("✕", "", closeDetails)),
      h("div", { class: "title" }, d.error)));
    return;
  }
  const sev = sevOf(d.severity);
  const aiOn = (S.st.ai || {}).enabled;
  const state = [d.pinned ? "pinned" : "",
    d.closed ? "closed as " + (d.verdict === "tp" ? "true" : "false") + " positive by " + d.closed_by : "",
    d.filtered_by ? "filtered" : "", d.analyzed ? "analyzed" : "",
    !d.closed && !d.filtered_by ? "active" : ""].filter(Boolean).join(", ");
  const actions = [
    btn(d.pinned ? "Unpin" : "Pin", "accent", () => act(d.pinned ? "unpin" : "pin", d.id)),
    !d.closed ? btn("True positive", "tp", () => verdict("tp", d.id)) : null,
    !d.closed ? btn("False positive", "", () => verdict("fp", d.id)) : null,
    d.closed ? btn("Reopen", "", () => act("reopen", d.id)) : null,
    btn("Create filter", "", () => draftFilter(d.id)),
    aiOn ? btn(d.analyzed ? "Re-analyze" : "AI analyze", "aitint", () => act("analyze", d.id).then(() => {
      S.note = "Analysis requested — results appear here when ready.";
      renderDetails();
      // The engine answers asynchronously.
      [4000, 10000, 20000, 40000].forEach((t) => setTimeout(() => { if (S.selectedId === d.id) loadDetails(); }, t));
    })) : null,
    btn("Explain", "", () => explain(d.id)),
  ];
  const an = d.analysis_full || null;
  const res = an ? an.result : null;
  const fields = flatten(d.fields || {}, 0, []);
  const body = h("div", { class: "body" },
    S.note ? h("div", { class: "note muted" }, S.note) : null,
    S.draft ? h("div", { class: "box draft" },
      h("div", { class: "boxhead" }, "NEW EXCLUSION RULE — appended to your alert_filter.yaml, backup kept"),
      h("pre", {}, S.draft),
      h("div", { class: "actions", style: "display:flex;gap:6px;margin-top:8px" },
        btn("Add rule", "accent", () => act("create-filter", d.id).then(() => {
          S.draft = "";
          S.note = "Rule added — the engine reloads it within a second.";
          renderDetails();
        }), { confirm: true }),
        btn("Cancel", "", () => { S.draft = ""; renderDetails(); }))) : null,
    S.explain ? h("div", { class: "box" },
      h("div", { class: "boxhead muted" }, "WHY — " + (S.explain.decision ? "excluded by " + S.explain.decision : "kept by the rules") + (S.explain.pinned ? " (pinned: never hidden)" : "")),
      h("pre", {}, JSON.stringify(S.explain.rules, null, 2))) : null,
    h("h3", {}, "EVENT"),
    h("div", { class: "kv" },
      kv("id", d.id),
      kv("time", d.timestamp),
      kv("severity", d.severity, "var(--" + sev + ")"),
      kv("type", d.event_type),
      kv("source", (d.source || "") + (d.meta && d.meta.file ? "  (" + d.meta.file + ")" : "")),
      kv("occurrences", d.occurrences + "  (first " + fmtTime(d.first_seen) + ", last " + fmtTime(d.last_seen) + ")"),
      d.similar ? kv("similar", d.similar.events + " event(s), " + d.similar.occurrences + " occurrence(s)") : null,
      kv("state", state)),
    d.filter_rule ? [h("h3", {}, "FILTERING"), h("div", { class: "kv" },
      kv("excluded by", d.filter_rule.id + (d.filter_rule.generated_by ? "  [" + d.filter_rule.generated_by + "]" : "")),
      kv("rule", d.filter_rule.description),
      d.filter_rule.match ? kv("match", JSON.stringify(d.filter_rule.match)) : null)] : null,
    res ? h("div", { class: "box aibox" },
      h("div", { class: "boxhead" }, "AI ANALYSIS · SOC N1 · " + (an.provider || "") + "/" + (an.model || "") + (an.cached ? " · cached" : "")),
      h("div", { class: "disclaimer" }, "Generated by a language model — verify before acting."),
      h("div", { class: "summary" }, res.summary || ""),
      res.confidence !== undefined ? h("div", { class: "meter" }, "confidence",
        h("div", { class: "track" }, h("div", { class: "fill", style: "width:" + Math.round((res.confidence || 0) * 100) + "%" })),
        h("span", { class: "ai" }, Math.round((res.confidence || 0) * 100) + "%"),
        res.benign_confidence !== undefined ? "benign " + Math.round(res.benign_confidence * 100) + "%" : null) : null,
      h("div", { class: "kv" },
        kv("classification", res.classification, "var(--ai)"),
        kv("assessment", res.severity_assessment, "var(--" + sevOf(res.severity_assessment) + ")"),
        kv("false positive", res.false_positive_likelihood),
        kv("suggested", res.suggested_action, "var(--ai)"),
        kv("context", res.context),
        kv("impact", res.impact)),
      bullets("Confirmed facts", res.facts),
      bullets("Indicators", res.indicators),
      bullets("Hypotheses", res.hypotheses),
      bullets("Missing information", res.missing_information),
      bullets("Investigation steps", res.recommended_investigations)) : null,
    d.proposals && d.proposals.length ? [h("h3", { class: "ai" }, "AI PROPOSALS"),
      d.proposals.map((p) => h("div", { class: "muted" }, "#" + p.id + " " + p.kind + " — " + p.status + (p.reason ? " — " + p.reason : "")))] : null,
    fields.length ? [h("h3", {}, "ORIGINAL FIELDS"), h("div", { class: "fields" }, fields.map((f) => [
      h("div", { class: "k" + (f.container ? " container" : ""), style: "padding-left:" + f.depth * 12 + "px" }, f.key),
      h("div", { class: "v" }, f.value)]))] : null,
    h("h3", {}, "RAW"),
    h("pre", {}, d.raw || ""),
    h("h3", {}, "HISTORY"),
    h("div", { class: "history" }, (d.history || []).length ? d.history.map((x) =>
      h("div", {}, h("span", { class: "muted" }, fmtTime(x.ts) + "  "), h("span", { class: "actor-" + x.actor }, x.actor), "  " + x.action,
        x.detail && Object.keys(x.detail).length ? h("span", { class: "muted" }, "  " + JSON.stringify(x.detail)) : null))
      : h("div", { class: "muted" }, "no action yet")));
  aside.replaceChildren(
    h("div", { class: "head sev-" + sev },
      h("div", { class: "kicker" }, h("span", {}, [d.severity, d.source, d.event_type].filter(Boolean).join(" · ").toUpperCase()), btn("✕ Close", "", closeDetails, { title: "Close (Esc)" })),
      h("div", { class: "title" }, d.message || ""),
      h("div", { class: "actions" }, actions)),
    body);
  body.scrollTop = scroll;
}

// ------------------------------------------------------------------ keys

function currentList() {
  if (S.tab === "active") return [...pinnedList(), ...feedList()].filter(matches);
  if (S.tab === "closed") return (S.st.closed || []).filter(matches);
  if (S.tab === "filtered") return (S.st.filtered || []).filter(matches);
  return [];
}

document.addEventListener("keydown", (e) => {
  if (e.target instanceof HTMLInputElement) {
    if (e.key === "Escape") e.target.blur();
    return;
  }
  const modal = document.querySelector(".modal-bg");
  if (e.key === "Escape") { if (modal) modal.remove(); else if (S.selectedId) closeDetails(); return; }
  if (modal || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === "/") { e.preventDefault(); els.search && els.search.focus(); return; }
  const list = currentList();
  const i = list.findIndex((x) => x.id === S.selectedId);
  if (e.key === "j" || e.key === "ArrowDown") { const n = list[Math.min(list.length - 1, i + 1)]; if (n && n.id !== S.selectedId) select(n.id); e.preventDefault(); }
  else if (e.key === "k" || e.key === "ArrowUp") { const n = list[Math.max(0, i - 1)]; if (n && n.id !== S.selectedId) select(n.id); e.preventDefault(); }
  else if (S.selectedId && S.tab === "active" && (e.key === "t" || e.key === "f")) verdict(e.key === "t" ? "tp" : "fp", S.selectedId);
  else if (S.selectedId && e.key === "p" && S.details && !S.details.error) act(S.details.pinned ? "unpin" : "pin", S.selectedId);
});

// ------------------------------------------------------------------ start

async function start() {
  document.body.append(h("div", { id: "toasts" }));
  loadPrefs();
  takeTokenFromUrl();
  if (!S.token) return showLogin();
  try { applyUi(await api("ui")); } catch (e) {
    if (e instanceof AuthError) return showLogin();
  }
  skeleton();
  renderAll();
  await poll();
  if (S.deepAlert) select(S.deepAlert);
  pollTimer = setInterval(poll, 2000);
  // The relative times and the engine liveness move without state changes.
  setInterval(renderHeader, 10000);
}

start();
