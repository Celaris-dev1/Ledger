/*
 * Live replay timeline for a goal. Records come from GET /v1/goals/{id}/replay and, in live
 * mode, from GET /v1/stream (Server-Sent Events). Everything untrusted is rendered with
 * textContent; links are built from fixed prefixes plus encodeURIComponent.
 */
(function () {
  "use strict";
  var root = document.getElementById("replay");
  if (!root || !window.LedgerCanon) return;
  var C = window.LedgerCanon;
  var goal = root.getAttribute("data-goal") || "";
  var $ = function (role) { return root.querySelector('[data-role="' + role + '"]'); };
  var track = $("track"), scrub = $("scrub"), list = $("events"), panel = $("panel"), clock = $("clock"), statusEl = $("status");
  var playBtn = root.querySelector('[data-act="play"]');
  var speedSel = root.querySelector('[data-act="speed"]');
  var liveBox = root.querySelector('[data-act="live"]');

  var events = [];        // sorted by time, then chain, then seq
  var byKey = new Map();  // "chain:seq" -> event
  var chains = [];        // lane order (first appearance)
  var t0 = 0, span = 0;   // ms
  var pos = 0;            // ms offset from t0
  var playing = false, speed = 1, lastFrame = 0;
  var selectedKey = null; // explicit selection among events sharing a timestamp
  var shownKey = null;
  var es = null, liveState = "off";
  var statusCache = new Map(), hashCache = new Map();

  // ---------- helpers ----------
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function str(v) { return typeof v === "string" ? v : ""; }
  function fmtT(ms) {
    var s = ms / 1000;
    if (s < 120) return "T+" + s.toFixed(1) + "s";
    var m = Math.floor(s / 60), r = Math.floor(s % 60);
    if (m < 120) return "T+" + m + "m" + (r < 10 ? "0" : "") + r + "s";
    return "T+" + Math.floor(m / 60) + "h" + (m % 60) + "m";
  }
  function category(type) {
    if (/approval|token\.issued|token\.revoked|call\.allowed|call\.denied|decision|authori[sz]/.test(type)) return "approval";
    if (/verif|stage\.completed|run\.decided|scored|captured|manifest|check/.test(type)) return "verify";
    if (/goal|plan|step|transition/.test(type)) return "plan";
    if (/effect|tool|call|run\.started|action|attempt|fetch/.test(type)) return "tool";
    return "other";
  }
  function actorsOf(rec) {
    var a = rec.get("actor_chain");
    if (!Array.isArray(a)) return [];
    return a.map(function (x) {
      var p = x instanceof C.Obj ? x : new C.Obj();
      return { kind: str(p.get("kind")), id: str(p.get("id")), model: str(p.get("model")), version: str(p.get("model_version")) };
    });
  }
  function recURL(chain, seq) { return "/r/" + encodeURIComponent(chain) + "/" + encodeURIComponent(String(seq)); }

  function makeEvent(rec) {
    var chain = str(rec.get("chain"));
    var seqV = rec.get("seq");
    var seq = seqV instanceof C.Num ? Number(seqV.lit) : NaN;
    var ts = Date.parse(str(rec.get("created_at")));
    if (!chain || !isFinite(seq) || !isFinite(ts)) return null;
    var type = str(rec.get("type"));
    var actors = actorsOf(rec);
    return { rec: rec, chain: chain, seq: seq, key: chain + ":" + seq, t: ts, type: type, cat: category(type), actors: actors,
      who: actors.map(function (a) { return a.id; }).join(" → ") };
  }

  function addEvents(recs) {
    var added = 0;
    recs.forEach(function (rec) {
      var ev = makeEvent(rec);
      if (!ev || byKey.has(ev.key)) return;
      byKey.set(ev.key, ev);
      events.push(ev);
      if (chains.indexOf(ev.chain) < 0) chains.push(ev.chain);
      added++;
    });
    if (!added) return 0;
    events.sort(function (a, b) { return a.t - b.t || (a.chain < b.chain ? -1 : a.chain > b.chain ? 1 : a.seq - b.seq); });
    t0 = events[0].t;
    span = Math.max(events[events.length - 1].t - t0, 0);
    return added;
  }

  // ---------- rendering ----------
  function pct(ev) { return span > 0 ? ((ev.t - t0) / span) * 100 : 0; }

  function renderTrack() {
    track.textContent = "";
    chains.forEach(function (c) {
      var lane = el("div", "lane");
      lane.appendChild(el("div", "lane-label", c));
      var line = el("div", "lane-line");
      events.forEach(function (ev) {
        if (ev.chain !== c) return;
        var m = el("button", "marker c-" + ev.cat);
        m.type = "button";
        m.tabIndex = -1;
        m.title = fmtT(ev.t - t0) + "  " + ev.chain + "#" + ev.seq + "  " + ev.type;
        m.style.left = pct(ev) + "%";
        m.addEventListener("click", function () { select(ev); });
        ev.marker = m;
        line.appendChild(m);
      });
      lane.appendChild(line);
      track.appendChild(lane);
    });
    var head = el("div", "playhead");
    track.appendChild(head);
    track._head = head;
  }

  function renderList() {
    list.textContent = "";
    events.forEach(function (ev) {
      var li = el("li", "ev c-" + ev.cat);
      var b = el("button", "ev-btn");
      b.type = "button";
      b.appendChild(el("span", "ev-t", fmtT(ev.t - t0)));
      b.appendChild(el("span", "ev-dot"));
      var main = el("span", "ev-main");
      main.appendChild(el("span", "ev-type", ev.type));
      main.appendChild(el("span", "ev-who", ev.who));
      b.appendChild(main);
      b.appendChild(el("span", "ev-src", ev.chain + "#" + ev.seq));
      b.addEventListener("click", function () { select(ev); });
      li.appendChild(b);
      ev.li = li;
      ev.btn = b;
      list.appendChild(li);
    });
  }

  function currentEvent() {
    if (!events.length) return null;
    var cur = null;
    for (var i = 0; i < events.length; i++) {
      if (events[i].t - t0 <= pos + 0.5) cur = events[i]; else break;
    }
    if (selectedKey) {
      var s = byKey.get(selectedKey);
      if (s && Math.abs(s.t - t0 - pos) < 1) return s;
    }
    return cur;
  }

  function update() {
    scrub.max = String(Math.max(span, 1000));
    scrub.value = String(Math.round(pos));
    var total = fmtT(span);
    clock.textContent = fmtT(pos) + " / " + total;
    scrub.setAttribute("aria-valuetext", fmtT(pos) + " of " + total);
    if (track._head) {
      var f = span > 0 ? Math.min(pos / span, 1) : 0;
      track._head.style.left = "calc(var(--lane-offset) + (100% - var(--lane-offset) - 8px) * " + f.toFixed(5) + ")";
    }
    var cur = currentEvent();
    events.forEach(function (ev) {
      var past = ev.t - t0 <= pos + 0.5;
      var isCur = cur === ev;
      if (ev.li) {
        ev.li.classList.toggle("future", !past);
        ev.li.classList.toggle("current", isCur);
        if (isCur) ev.btn.setAttribute("aria-current", "step"); else ev.btn.removeAttribute("aria-current");
      }
      if (ev.marker) {
        ev.marker.classList.toggle("future", !past);
        ev.marker.classList.toggle("current", isCur);
      }
    });
    if (cur && cur.key !== shownKey) showPanel(cur);
    if (!cur && shownKey !== null) { shownKey = null; panel.textContent = ""; panel.appendChild(el("p", "muted", "Before the first event.")); }
    playBtn.setAttribute("aria-pressed", playing ? "true" : "false");
    playBtn.setAttribute("aria-label", playing ? "Pause" : "Play");
    playBtn.classList.toggle("is-playing", playing);
  }

  function setStatus() {
    var parts = [events.length + " record" + (events.length === 1 ? "" : "s") + " across " + chains.length + " chain" + (chains.length === 1 ? "" : "s")];
    if (liveState === "connected") parts.push("live: streaming new records");
    else if (liveState === "connecting") parts.push("live: connecting…");
    else if (liveState === "error") parts.push("live: reconnecting…");
    statusEl.textContent = parts.join(" · ");
    statusEl.classList.toggle("live", liveState === "connected");
  }

  // ---------- side panel ----------
  function row(dl, term, node) {
    dl.appendChild(el("dt", null, term));
    var dd = el("dd");
    if (typeof node === "string") dd.textContent = node; else dd.appendChild(node);
    dl.appendChild(dd);
    return dd;
  }
  function pill(cls, text) { return el("span", "pill " + cls, text); }
  function withText(p, text) { var s = el("span"); s.appendChild(p); s.appendChild(document.createTextNode(" " + text)); return s; }

  function showPanel(ev) {
    shownKey = ev.key;
    var rec = ev.rec;
    panel.textContent = "";
    var head = el("div", "panel-head");
    head.appendChild(el("span", "pill cat c-" + ev.cat, ev.cat));
    head.appendChild(el("h3", "panel-title", ev.type));
    panel.appendChild(head);
    var meta = el("p", "panel-meta");
    var a = el("a", "ev", ev.chain + "#" + ev.seq);
    a.href = recURL(ev.chain, ev.seq);
    a.title = "Open the record permalink (re-verifies the hash in your browser)";
    meta.appendChild(a);
    meta.appendChild(document.createTextNode(" · " + fmtT(ev.t - t0) + " · " + str(rec.get("created_at"))));
    panel.appendChild(meta);

    var dl = el("dl", "kv panel-kv");
    var ol = el("ol", "actors");
    ev.actors.forEach(function (x, i) {
      var li = el("li", "actor k-" + x.kind);
      li.appendChild(pill("", x.kind || "?"));
      li.appendChild(document.createTextNode(" "));
      li.appendChild(el("strong", null, x.id));
      if (i === 0) li.appendChild(el("span", "muted small", x.kind === "human" ? " originating human" : " NOT a human: contract violation"));
      if (x.model) li.appendChild(el("span", "muted small", " " + x.model + (x.version ? " " + x.version : "")));
      ol.appendChild(li);
    });
    row(dl, "Actor chain", ol);
    row(dl, "Policy version", str(rec.get("policy_version")) || "none");
    row(dl, "Hash", el("span", "mono wrap", str(rec.get("hash"))));
    row(dl, "Prev hash", el("span", "mono wrap", str(rec.get("prev_hash")) || "(genesis)"));
    var hashDD = row(dl, "Browser check", pill("", "checking…"));
    var chainDD = row(dl, "Chain", pill("", "checking…"));
    var anchorDD = row(dl, "Anchor", pill("", "checking…"));
    panel.appendChild(dl);
    panel.appendChild(el("h4", "panel-sub", "Payload"));
    var pre = el("pre", "payload");
    pre.tabIndex = 0;
    var pl = rec.get("payload");
    pre.textContent = pl === undefined ? "{}" : C.pretty(pl);
    panel.appendChild(pre);

    var hp = hashCache.get(ev.key);
    if (!hp) { hp = C.recordHash(rec); hashCache.set(ev.key, hp); }
    hp.then(function (r) {
      if (shownKey !== ev.key) return;
      hashDD.textContent = "";
      hashDD.appendChild(r.hex === str(rec.get("hash")) ? withText(pill("ok", "match"), "SHA-256 recomputed here") : withText(pill("bad", "MISMATCH"), r.hex));
    }, function () { hashDD.textContent = "hashing failed"; });

    var sp = statusCache.get(ev.key);
    if (!sp) {
      sp = fetch("/ui/api/status?chain=" + encodeURIComponent(ev.chain) + "&seq=" + encodeURIComponent(String(ev.seq)), { credentials: "same-origin", headers: { Accept: "application/json" } })
        .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); });
      statusCache.set(ev.key, sp);
      sp.catch(function () { statusCache.delete(ev.key); });
    }
    sp.then(function (s) {
      if (shownKey !== ev.key) return;
      chainDD.textContent = "";
      if (s.record_ok) chainDD.appendChild(withText(pill("ok", "verified"), s.chain_ok ? "chain intact (" + s.length + " records)" : "verifies through this seq; broken later at #" + s.broken_at));
      else chainDD.appendChild(withText(pill("bad", "not verified"), "broken at #" + s.broken_at + (s.reason ? ": " + s.reason : "")));
      anchorDD.textContent = "";
      var an = s.anchor || {};
      if (!an.configured) anchorDD.appendChild(el("span", "muted", "anchoring not configured"));
      else if (an.error) anchorDD.appendChild(pill("warn", an.error));
      else if (an.covered) {
        var okA = an.cover_consistent !== false;
        anchorDD.appendChild(withText(pill(okA ? "ok" : "bad", okA ? "anchored" : "anchor mismatch"),
          "at #" + an.cover_seq + " by " + (an.cover_witnesses || []).join(", ")));
      } else anchorDD.appendChild(withText(pill("warn", "not yet anchored"), an.last_anchored_seq ? "last anchor #" + an.last_anchored_seq : "never anchored"));
    }, function () {
      if (shownKey !== ev.key) return;
      chainDD.textContent = "status unavailable";
      anchorDD.textContent = "status unavailable";
    });
  }

  // ---------- controls ----------
  function select(ev) {
    selectedKey = ev.key;
    pos = ev.t - t0;
    shownKey = null;
    update();
  }
  function step(dir) {
    if (!events.length) return;
    var cur = currentEvent();
    var i = cur ? events.indexOf(cur) : -1;
    var j = Math.min(Math.max(i + dir, 0), events.length - 1);
    if (dir < 0 && i < 0) j = 0;
    select(events[j]);
    if (events[j].btn) events[j].btn.focus({ preventScroll: false });
  }
  function frame(ts) {
    if (!playing) return;
    var dt = lastFrame ? ts - lastFrame : 0;
    lastFrame = ts;
    pos += dt * speed;
    // skip idle gaps: never wait more than ~1.2s of wall time for the next event
    for (var i = 0; i < events.length; i++) {
      var off = events[i].t - t0;
      if (off > pos + 0.5) {
        if ((off - pos) / speed > 1200) pos = off - 600 * speed;
        break;
      }
    }
    if (pos >= span) {
      pos = span;
      if (!liveBox.checked) { playing = false; }
    }
    selectedKey = null;
    update();
    if (playing) requestAnimationFrame(frame);
  }
  function play(on) {
    playing = on && events.length > 0;
    if (playing) {
      if (pos >= span && !liveBox.checked) pos = 0;
      lastFrame = 0;
      requestAnimationFrame(frame);
    }
    update();
  }

  root.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest("button[data-act]") : null;
    if (!b || !root.contains(b)) return;
    var act = b.getAttribute("data-act");
    if (act === "play") play(!playing);
    else if (act === "first") { play(false); pos = 0; selectedKey = null; update(); }
    else if (act === "last") { play(false); pos = span; selectedKey = null; update(); }
    else if (act === "prev") { play(false); step(-1); }
    else if (act === "next") { play(false); step(1); }
  });
  scrub.addEventListener("input", function () {
    play(false);
    pos = Number(scrub.value) || 0;
    if (pos > span) pos = span;
    selectedKey = null;
    update();
  });
  speedSel.addEventListener("change", function () { speed = Number(speedSel.value) || 1; });
  root.addEventListener("keydown", function (e) {
    var tag = (e.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "select" || tag === "textarea") return;
    if (e.key === "ArrowRight") { e.preventDefault(); play(false); step(1); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); play(false); step(-1); }
    else if (e.key === "Home") { e.preventDefault(); play(false); pos = 0; update(); }
    else if (e.key === "End") { e.preventDefault(); play(false); pos = span; update(); }
    else if ((e.key === " " || e.key === "k") && tag !== "button" && tag !== "a") { e.preventDefault(); play(!playing); }
  });

  // evidence links in the goal tree jump the replay
  document.addEventListener("click", function (e) {
    var a = e.target.closest ? e.target.closest("a[data-jump]") : null;
    if (!a || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    var ev = byKey.get(a.getAttribute("data-jump"));
    if (!ev) return;
    e.preventDefault();
    play(false);
    select(ev);
    root.scrollIntoView({ behavior: "smooth", block: "start" });
    if (ev.btn) ev.btn.focus({ preventScroll: true });
  });

  // ---------- live ----------
  function cursor() {
    var m = {};
    events.forEach(function (ev) { if (!m[ev.chain] || ev.seq > m[ev.chain]) m[ev.chain] = ev.seq; });
    var p = new URLSearchParams();
    Object.keys(m).sort().forEach(function (c) { p.set(c, String(m[c])); });
    return p.toString();
  }
  function startLive() {
    if (es || typeof EventSource === "undefined") return;
    liveState = "connecting";
    setStatus();
    var url = "/v1/stream?goal_id=" + encodeURIComponent(goal) + "&cursor=" + encodeURIComponent(cursor());
    es = new EventSource(url, { withCredentials: true });
    es.onopen = function () { liveState = "connected"; setStatus(); };
    es.onerror = function () { liveState = es && es.readyState === EventSource.CLOSED ? "off" : "error"; setStatus(); };
    es.addEventListener("record", function (m) {
      var rec;
      try { rec = C.parse(m.data); } catch (err) { return; }
      var following = pos >= span - 1;
      var hadEvents = events.length > 0;
      if (!addEvents([rec])) return;
      renderTrack();
      renderList();
      if (following || !hadEvents) pos = span;
      shownKey = null;
      setStatus();
      update();
    });
  }
  function stopLive() {
    if (es) { es.close(); es = null; }
    liveState = "off";
    setStatus();
  }
  liveBox.addEventListener("change", function () { if (liveBox.checked) startLive(); else stopLive(); });

  // ---------- load ----------
  fetch("/v1/goals/" + encodeURIComponent(goal) + "/replay", { credentials: "same-origin", headers: { Accept: "application/json" } })
    .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.text(); })
    .then(function (text) {
      var doc = C.parse(text);
      var recs = doc instanceof C.Obj && Array.isArray(doc.get("records")) ? doc.get("records") : [];
      addEvents(recs.filter(function (r) { return r instanceof C.Obj; }));
      renderTrack();
      renderList();
      setStatus();
      var params = new URLSearchParams(location.search);
      var at = params.get("at");
      if (at && byKey.has(at)) select(byKey.get(at));
      else update();
      if (!events.length) statusEl.textContent = "No records for this goal yet. Turn on Live to watch for new ones.";
      if (params.get("live") === "1") { liveBox.checked = true; startLive(); }
    })
    .catch(function (err) {
      statusEl.textContent = "Could not load the replay: " + err.message;
      statusEl.classList.add("bad");
    });
})();
