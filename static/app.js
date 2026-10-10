"use strict";
// Munshi front end (vanilla JS). SECURITY: log text is attacker-controlled, so it is only
// ever inserted through textContent / text nodes. Never as markup.

const NS = "http://www.w3.org/2000/svg";
const $ = (s) => document.querySelector(s);
// h(): build a DOM element. Strings become text nodes, so nothing is parsed as HTML.
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v != null && v !== false) e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c);
  return e;
}
function sv(tag, attrs, ...kids) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  for (const c of kids) e.append(c);
  return e;
}

// ---- state: one object, one render() ------------------------------------------------
const S = { view: "watch", dataset: null, analysis: null, score: null,
            selected: null, tab: "overview", filter: "all", busy: null, error: null };
const NAV = [["watch", "Watch"], ["analyze", "Analyze"], ["findings", "Findings"], ["investigate", "Investigate"],
             ["chronicle", "Chronicle"], ["evaluation", "Evaluation"], ["reports", "Reports"]];
const TYPE = { brute_force: "Brute force", brute_force_success: "Brute force · authentication observed",
               password_spray: "Password spray" };
const findings = () => (S.analysis ? S.analysis.findings : []);
const fmt = (n) => Number(n).toLocaleString("en-US");

// ---- wording rules: an IP is not a person; "authentication observed" is not "broke in" ----
function authContext(f) {
  // Newer detector versions separate successful authentication observed from
  // a confirmed/single-user compromise. Keep a fallback for older API payloads.
  const users = Array.isArray(f.episode_success_users) ? [...f.episode_success_users] : [];
  const rawCount = f.episode_success_count;
  let count = Number.isFinite(Number(rawCount)) && rawCount !== undefined && rawCount !== null
    ? Number(rawCount) : users.length;
  if (f.compromised && count === 0) {
    count = 1;
    if (f.compromised_user && !users.includes(f.compromised_user)) users.push(f.compromised_user);
  }
  return { observed: count > 0 || Boolean(f.compromised), count, users,
           lines: Array.isArray(f.episode_success_lines) ? f.episode_success_lines : [] };
}
function hasAuthenticationObserved(f) { return authContext(f).observed; }
function authText(f) {
  const auth = authContext(f);
  if (!auth.observed) return "No successful authentication observed after the failures";
  if (auth.count > 1) return `Successful authentication observed across ${auth.count} distinct usernames · ambiguous`;
  const user = auth.users[0] || f.compromised_user;
  return user ? `Authentication observed · user ${user}` : "Authentication observed";
}
// Log times carry no timezone. Read them as UTC so charts never shift with the viewer's clock.
const ms = (s) => Date.parse(s.replace(" ", "T") + "Z");
function windowText(f) { const s = Math.round((ms(f.end) - ms(f.start)) / 1000); return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`; }
function rateText(f) { const s = (ms(f.end) - ms(f.start)) / 1000; return s > 0 ? `${(f.failures / (s / 60)).toFixed(1)} failures per minute (average)` : "n/a"; }
const timeOf = (text) => { const m = /^([A-Z][a-z]{2}\s+\d+\s+[\d:]{8})/.exec(text); return m ? m[1] : "?"; };

// ---- backend calls (the only real endpoints) --------------------------------------------
async function call(url, opts) {
  const r = await fetch(url, opts);
  let d = {};
  try { d = await r.json(); } catch (e) { /* non-JSON error page, e.g. 413 */ }
  if (!r.ok) throw new Error(d.error || (r.status === 413 ? "File too large (limit 2 MB)." : `Server error (${r.status})`));
  return d;
}
async function run(kind, payload, goTo) {
  S.busy = kind === "file" ? `Uploading and analyzing ${payload.name}…` : `Analyzing the ${payload} sample…`;
  S.error = null;
  document.body.classList.add("processing");
  render();
  try {
    if (kind === "file") {
      const f = new FormData(); f.append("logfile", payload);
      S.analysis = await call("/api/analyze", { method: "POST", body: f });
      S.dataset = { name: payload.name, kind: "upload" }; S.score = null;
    } else {
      S.analysis = await call("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" },
                                                  body: JSON.stringify({ sample: payload }) });
      S.dataset = { name: `${payload} sample`, kind: "sample", key: payload };
      S.score = await call(`/api/score?set=${payload}`);
    }
    S.selected = null; S.filter = "all";
  } catch (e) { S.error = e.message; }
  document.body.classList.remove("processing");
  S.busy = null; S.view = goTo || "analyze"; render();
}
function pick(f, tab) { S.selected = f; S.tab = tab || "overview"; S.view = "investigate"; render(); }

// ---- reusable pieces ---------------------------------------------------------------------
const Empty = (title, text, ...btns) => h("div", { class: "empty" }, h("b", {}, title), text, h("div", {}, ...btns));
const Btn = (label, fn, cls) => h("button", { class: `btn ${cls || ""}`, onclick: fn }, label);
const Metric = (label, value, note, cls) => h("div", { class: `panel metric ${cls || ""}` }, h("small", {}, label), h("b", {}, value), h("span", {}, note));
const Head = (t, s) => [h("h2", {}, t), h("p", { class: "sub" }, s)];
const ranBtns = () => [Btn("Run easy sample", () => run("sample", "easy", S.view), "red"), Btn("Run hard sample", () => run("sample", "hard", S.view)),
                       Btn("Go to Analyze", () => go("analyze"))];
function needData(title) { return Empty("No analysis loaded", `${title} needs a log. Run a sample or upload a file.`, ...ranBtns()); }

function FindingRow(f) {
  return h("button", { class: `row ${f.compromised ? "" : "amber"}`, onclick: () => pick(f) },
    h("div", {}, h("b", {}, TYPE[f.label] || f.label), h("small", { class: "mono" }, `${f.ip} · ${f.start}`)),
    h("div", {}, h("span", { class: "wrap" }, `${fmt(f.failures)} failed attempts · ${f.n_users} username${f.n_users === 1 ? "" : "s"}`),
      h("small", { class: "wrap", style: null }, authText(f))),
    h("span", { class: "dim" }, "Investigate →"));
}

// ---- charts (SVG built from real findings only) -------------------------------------------
function TimelineChart(list) {
  const W = 720, H = 250, L = 34, B = 26, t0 = Math.min(...list.map((f) => ms(f.start)));
  const t1 = Math.max(...list.map((f) => ms(f.end))), span = Math.max(t1 - t0, 1);
  const max = Math.max(...list.map((f) => f.failures)), svg = sv("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Failures per finding over time" });
  [0, 0.5, 1].forEach((p) => { const y = H - B - p * (H - B - 10);
    svg.append(sv("line", { x1: L, x2: W, y1: y, y2: y, stroke: "#232c2a" }));
    const t = sv("text", { x: 0, y: y + 4 }); t.textContent = Math.round(max * p); svg.append(t); });
  list.forEach((f) => {
    const x = L + ((ms(f.start) - t0) / span) * (W - L - 8), bh = (f.failures / max) * (H - B - 10);
    const r = sv("rect", { class: `b ${hasAuthenticationObserved(f) ? "b0" : "b1"}`, x, y: H - B - bh, width: 6, height: bh, tabindex: 0 });
    const tt = sv("title", {}); tt.textContent = `${f.ip}: ${f.failures} failures`; r.append(tt);
    r.addEventListener("click", () => pick(f)); svg.append(r); });
  const first = list.reduce((a, b) => (a.start < b.start ? a : b)).start, last = list.reduce((a, b) => (a.end > b.end ? a : b)).end;
  [[first, L, "start"], [last, W - 4, "end"]].forEach(([label, x, anchor]) => { const t = sv("text", { x, y: H - 6, "text-anchor": anchor }); t.textContent = label.slice(0, 16); svg.append(t); });
  const key = h("div", { class: "key" }, h("span", {}, h("i", { class: "k0" }), "Authentication observed"), h("span", {}, h("i", { class: "k1" }), "Failures only"));
  return h("div", {}, svg, key);
}
function Donut(list) {
  const counts = {}; list.forEach((f) => { counts[f.label] = (counts[f.label] || 0) + 1; });
  const IDX = { brute_force_success: 0, brute_force: 1, password_spray: 2 };   // red = authentication observed, gold = failures only, stone = spray
  const keys = Object.keys(counts).sort((a, b) => IDX[a] - IDX[b]), total = list.length, R = 52, C = 2 * Math.PI * R, g = sv("g", { transform: "rotate(-90 70 70)" });
  let acc = 0; keys.forEach((k, i) => { const len = (counts[k] / total) * C;
    g.append(sv("circle", { cx: 70, cy: 70, r: R, fill: "none", "stroke-width": 16, class: `s${IDX[k]}`, "stroke-dasharray": `${len} ${C - len}`, "stroke-dashoffset": -acc })); acc += len; });
  const mid = sv("text", { class: "big", x: 70, y: 79, "text-anchor": "middle" }); mid.textContent = total;
  const svg = sv("svg", { class: "chart", viewBox: "0 0 140 140", role: "img", "aria-label": "Findings by type" }, g, mid);
  svg.style.maxWidth = "180px";
  return h("div", {}, svg, h("ul", { class: "legend" }, keys.map((k, i) => h("li", {}, h("span", {}, h("i", { class: `k${IDX[k]}` }), TYPE[k] || k), counts[k]))));
}

// ---- views ---------------------------------------------------------------------------------
const V = {};
V.watch = () => {
  const a = S.analysis; if (!a) return [Head("Security overview", "What Munshi observed in the loaded log."), needData("The overview")];
  const L = findings(), inFind = L.reduce((s, f) => s + f.evidence_total, 0), fa = S.score ? S.score.false_alarms : null;
  const authObserved = L.filter(hasAuthenticationObserved).length;
  const top = [...L].sort((x, y) => y.failures - x.failures).slice(0, 5);
  return [Head("Security overview", "Replay of the loaded log, not a live feed."),
    h("div", { class: "grid4" },
      Metric("Total events", fmt(a.summary.events), `${fmt(a.summary.skipped)} lines skipped (unreadable)`),
      Metric("Outside findings", fmt(a.summary.events - inFind), "Not necessarily normal: undetected attacks land here too", "gold"),
      Metric("Findings", fmt(L.length), `${authObserved} with authentication observed`, "red"),
      Metric("False alarms", fa == null ? "n/a" : fa, fa == null ? "Needs an answer key (samples only)" : "Known from the answer key", "gold")),
    h("div", { class: "grid2" },
      h("div", { class: "panel" }, h("h3", {}, "Findings over time (bar height = failed attempts)"), L.length ? TimelineChart(L) : "No findings."),
      h("div", { class: "panel" }, h("h3", {}, "Findings by type"), L.length ? Donut(L) : "No findings.")),
    h("div", { class: "panel" }, h("h3", {}, "Strongest current signals"), top.length ? top.map(FindingRow) : "No suspicious pattern found.")];
};
V.analyze = () => {
  // Stages we can honestly show: the server parses and applies the rules inside ONE request.
  const st = S.busy ? [1, 0, 0] : S.analysis ? [2, 2, 2] : [0, 0, 0];
  const cls = (i) => `step ${st[i] === 2 ? "done" : st[i] === 1 ? "on" : ""}`;
  const file = h("input", { type: "file", accept: ".log,.txt", hidden: true, id: "file" });
  file.addEventListener("change", () => file.files[0] && run("file", file.files[0], "analyze"));
  const zone = h("div", { class: "drop" }, h("b", {}, "Drop an SSH auth log here"), h("p", { class: "dim" }, "OpenSSH password lines · up to 2 MB"),
    Btn("Choose file", () => file.click(), "red"), file);
  ["dragenter", "dragover"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("over"); }));
  zone.addEventListener("drop", (e) => e.dataTransfer.files[0] && run("file", e.dataTransfer.files[0], "analyze"));
  const a = S.analysis, out = S.busy ? h("div", { class: "empty pulse" }, h("b", {}, S.busy), "Munshi reads, parses and applies its rules on the server.")
    : S.error ? h("div", { class: "empty err" }, h("b", {}, "Analysis failed"), S.error)
    : a ? h("div", { class: "panel metric" }, h("small", {}, "Analysis complete"), h("b", {}, `${fmt(a.summary.events)} events processed`),
        h("span", {}, `${fmt(a.summary.skipped)} lines skipped · ${a.summary.findings} findings · ${S.dataset.name}`), h("div", { class: "chip-row" }, Btn("View findings", () => go("findings"), "sm red"), Btn("Open overview", () => go("watch"), "sm")))
    : Empty("No event stream loaded", "Choose a file, or run one of the built-in synthetic samples.");
  return [Head("Analyze", "Ingest an SSH authentication log."),
    h("div", { class: "steps" }, h("div", { class: cls(0) }, "01 Upload"), h("div", { class: cls(1) }, "02 Analyze (parse + rules)"), h("div", { class: cls(2) }, "03 Results")),
    zone, h("div", { class: "chip-row noprint" }, Btn("Run easy sample", () => run("sample", "easy", "analyze")), Btn("Run hard sample", () => run("sample", "hard", "analyze"))), out];
};
V.findings = () => {
  if (!S.analysis) return [Head("Findings", "Suspicious patterns found in the log."), needData("The findings queue")];
  const L = findings(), labels = [...new Set(L.map((f) => f.label))], shown = L.filter((f) => S.filter === "all" || f.label === S.filter);
  const chip = (k, name, n) => h("button", { class: `chip ${S.filter === k ? "on" : ""}`, onclick: () => { S.filter = k; render(); } }, `${name} (${n})`);
  return [Head("Findings", "Rule-based findings. Severity is not scored at this stage, and an IP address is not a person."),
    h("div", { class: "chip-row" }, chip("all", "All", L.length), labels.map((k) => chip(k, TYPE[k] || k, L.filter((f) => f.label === k).length))),
    shown.length ? shown.map(FindingRow) : Empty("No suspicious pattern found", "Nothing in this log crossed the rules.")];
};
V.investigate = () => {
  const f = S.selected; if (!f) return [Head("Investigation", "Why a finding was flagged, and the evidence."), Empty("No finding selected", "Pick one from the findings queue.", Btn("Open findings", () => go("findings"), "red"))];
  const ev = f.evidence_preview, tabs = [["overview", "Overview"], ["timeline", "Event timeline"], ["raw", "Raw logs"], ["related", "Related activity"]];
  const note = f.evidence_total > ev.length ? h("p", { class: "dim" }, `Showing the first ${ev.length} of ${fmt(f.evidence_total)} evidence lines.`) : null;
  let body;
  if (S.tab === "overview") body = h("div", { class: "grid2" },
    h("div", { class: "panel" }, h("h3", {}, "Attack details"), h("dl", {}, h("dt", {}, "Source IP"), h("dd", { class: "mono" }, f.ip), h("dt", {}, "Pattern"), h("dd", {}, TYPE[f.label]),
      h("dt", {}, "Failed attempts"), h("dd", {}, fmt(f.failures)), h("dt", {}, "First seen"), h("dd", { class: "mono" }, f.start), h("dt", {}, "Last seen"), h("dd", { class: "mono" }, f.end),
      h("dt", {}, "Observed window"), h("dd", {}, windowText(f)), h("dt", {}, "Average rate"), h("dd", {}, rateText(f)),
      h("dt", {}, "Usernames"), h("dd", { class: "wrap mono" }, f.users.join(", ") + (f.n_users > f.users.length ? ` … (${f.n_users} total)` : "")), h("dt", {}, "Authentication"), h("dd", {}, authText(f)))),
    h("div", { class: "panel" }, h("h3", {}, "Why it was flagged"), h("p", {}, `Repeated authentication failures were observed from ${f.ip}: ${fmt(f.failures)} within one continuous episode.`),
      h("p", { class: "note" }, "This is a rule match, not proof of intent. The source address identifies a network location, not a person.")));
  else if (S.tab === "timeline") body = h("div", { class: "panel" }, h("ul", { class: "tl" }, ev.map((e) => h("li", { class: /Accepted/.test(e.text) ? "ok" : "" }, h("span", { class: "mono" }, timeOf(e.text)), "  ", /Accepted/.test(e.text) ? "Authentication observed" : "Failed password"))), note);
  else if (S.tab === "raw") body = h("div", {}, h("pre", { class: "log" }, ev.map((e) => h("span", { class: `ln ${/Accepted/.test(e.text) ? "pass" : "fail"}` }, h("span", {}, e.line), e.text))), note);
  else { const rel = findings().filter((x) => x.ip === f.ip && x !== f); body = h("div", { class: "panel" }, rel.length ? rel.map(FindingRow) : "No other findings from this source address in this log."); }
  return [Head("Investigation", `${TYPE[f.label]} from ${f.ip}`), h("div", { class: "tabs" }, tabs.map(([k, n]) => h("button", { class: `tab ${S.tab === k ? "on" : ""}`, onclick: () => { S.tab = k; render(); } }, n))), body];
};
V.chronicle = () => {
  const f = S.selected; if (!f) return [Head("Chronicle", "What happened, in what order."), Empty("No finding selected", "Pick one from the findings queue.", Btn("Open findings", () => go("findings"), "red"))];
  const ev = f.evidence_preview, first = ev[0], last = ev[ev.length - 1], steps = [
    ["Repeated authentication failures observed", `source ${f.ip} · ${f.start}`, first && `log line ${first.line}`],
    ["Volume of failures", `${fmt(f.failures)} failed attempts against ${f.n_users} username${f.n_users === 1 ? "" : "s"}`, `${fmt(f.evidence_total)} evidence lines`]];
  if (hasAuthenticationObserved(f)) steps.push([authText(f), `${f.end}`, f.evidence_total <= ev.length && last ? `log line ${last.line}` : "see raw logs"]);
  steps.push(["Episode ended", f.end, null]);
  return [Head("Chronicle", `Order of events for ${f.ip}. Only facts the log supports are listed.`),
    h("div", { class: "panel" }, h("ul", { class: "tl" }, steps.map((s, i) => h("li", { class: i === 2 && hasAuthenticationObserved(f) ? "gold" : "" }, h("b", {}, `${String(i + 1).padStart(2, "0")}  ${s[0]}`), h("div", { class: "dim wrap" }, s[1]), s[2] && h("div", { class: "mono dim" }, s[2]))))),
    h("p", { class: "note" }, "A verified plain-English narrative with per-sentence evidence is a later phase. This view never claims more than the counts and lines above.")];
};
V.evaluation = () => {
  const sc = S.score; if (!sc) return [Head("Evaluation", "Performance against a planted-attack answer key."), Empty("No answer key for this dataset", "Evaluation needs a built-in sample, which has known planted attacks.", ...ranBtns())];
  const pct = (a, b) => (b ? `${((100 * a) / b).toFixed(1)}%` : "n/a"), fl = findings().length;
  const causes = Object.entries(sc.false_alarm_causes).map(([k, n]) => `${k.replace(/_/g, " ")}: ${n}`).join(", ") || "none";
  const meter = (label, a, b, formula, red) => { const fill = h("i"); fill.style.width = b ? `${(100 * a) / b}%` : "0%";
    return h("div", { class: "meter" }, h("span", {}, label), h("div", { class: `bar ${red ? "red" : ""}` }, fill), h("small", {}, `${pct(a, b)} · ${formula}`)); };
  const ORDER = ["loud", "low_and_slow", "threshold_dodger", "distributed"], rank = (k) => (ORDER.includes(k) ? ORDER.indexOf(k) : 99);
  const v = h("div", {}, ...Head("Evaluation", "Synthetic benchmark with planted attacks. One random seed. Not real-world traffic."),
    h("div", { class: "grid4" }, Metric("Planted attacks", sc.planted, S.dataset.name), Metric("Detected", sc.detected, pct(sc.detected, sc.planted) + " detection rate", ""),
      Metric("Correct type", sc.correct_type, pct(sc.correct_type, sc.planted) + " type accuracy"), Metric("False alarms", sc.false_alarms, `${pct(sc.false_alarms, fl)} of ${fl} findings`, "red")),
    h("div", { class: "panel stack" }, h("h3", {}, "Detection performance"),
      meter("Detection rate", sc.detected, sc.planted, `${sc.detected} of ${sc.planted} planted attacks`),
      meter("Type accuracy", sc.correct_type, sc.planted, `${sc.correct_type} of ${sc.planted} correctly typed`),
      meter("False alarm share", sc.false_alarms, fl, `${sc.false_alarms} of ${fl} findings were not attacks`, true)),
    h("div", { class: "grid2" }, h("div", { class: "panel" }, h("h3", {}, "Attack variant breakdown"), h("table", {}, h("thead", {}, h("tr", {}, ["Variant", "Planted", "Detected", "Correct type", "Detected %"].map((c) => h("th", {}, c)))),
        h("tbody", {}, Object.entries(sc.by_variant).sort((a, b) => rank(a[0]) - rank(b[0])).map(([k, r]) => h("tr", {}, h("td", {}, k.replace(/_/g, " ")), h("td", {}, r.planted), h("td", {}, r.detected), h("td", {}, r.correct_type), h("td", {}, pct(r.detected, r.planted))))))),
      h("div", { class: "panel" }, h("h3", {}, "False alarm causes"), h("p", { class: "wrap" }, causes), h("p", { class: "note" }, "Stealth variants (low-and-slow, threshold-dodging, distributed) are designed to slip past per-IP rules. Low scores there are an expected, reported limitation, not a hidden one."))));
  return v;
};
V.reports = () => {
  if (!S.analysis) return [Head("Reports", "Export what Munshi found."), needData("A report")];
  const a = S.analysis, sc = S.score;
  const save = (name, type, text) => { const u = URL.createObjectURL(new Blob([text], { type })); const l = h("a", { href: u, download: name }); document.body.append(l); l.click(); l.remove(); URL.revokeObjectURL(u); };
  const csv = () => { const q = (x) => `"${String(x).replace(/"/g, '""')}"`;
    return ["type,source_ip,start,end,failed_attempts,usernames_targeted,authentication_observed,successful_users,confirmed_single_user_signal,evidence_lines,authentication_context_lines"].concat(findings().map((f) => {
      const auth = authContext(f);
      return [f.label, f.ip, f.start, f.end, f.failures, f.n_users, auth.observed, auth.users.join(";"), Boolean(f.compromised), f.evidence_total, auth.lines.join(";")].map(q).join(",");
    })).join("\n"); };
  return [Head("Reports", "Browser-side exports of the loaded analysis."),
    h("div", { class: "chip-row noprint" }, Btn("Download JSON", () => save("munshi_report.json", "application/json", JSON.stringify({ dataset: S.dataset, summary: a.summary, findings: findings(), score: sc }, null, 2)), "red"),
      Btn("Download CSV", () => save("munshi_findings.csv", "text/csv", csv())), Btn("Print / save as PDF", () => window.print())),
    h("div", { class: "paper" }, h("h2", {}, "Munshi incident report"), h("p", { class: "dim" }, `Dataset: ${S.dataset.name}`),
      h("h3", {}, "Detection summary"), h("p", {}, `${fmt(a.summary.events)} events read, ${fmt(a.summary.skipped)} lines skipped, ${a.summary.findings} findings.`),
      h("h3", {}, "Findings"), h("ul", {}, findings().slice(0, 12).map((f) => h("li", { class: "wrap" }, `${TYPE[f.label]} · ${f.ip} · ${fmt(f.failures)} failures · ${authText(f)}`))),
      findings().length > 12 && h("p", { class: "dim" }, `…and ${findings().length - 12} more in the exports.`),
      sc && [h("h3", {}, "Evaluation"), h("p", {}, `Detected ${sc.detected} of ${sc.planted} planted attacks; ${sc.false_alarms} false alarms (synthetic data, one seed).`)],
      h("h3", {}, "Limitations"), h("p", {}, "Rule-based and per-IP. Stealth, distributed and low-and-slow attacks can be missed; shared IPs can cause false alarms. An IP address is not a person."))];
};

// ---- shell: navigation + render --------------------------------------------------------------
function go(v) { S.view = v; render(); }
function render() {
  $("#nav").replaceChildren(...NAV.map(([k, n], i) => h("button", { class: `nav ${S.view === k ? "on" : ""}`, "aria-current": S.view === k ? "page" : null, onclick: () => go(k) }, h("i", {}, `0${i + 1}`), n)));
  $("#crumb").textContent = NAV.find((n) => n[0] === S.view)[1];
  const d = $("#dataset"); d.textContent = S.dataset ? S.dataset.name : "no dataset"; d.className = `pill ${S.dataset ? "live" : ""}`;
  const v = $("#view");
  if (S.busy && S.view !== "analyze") v.replaceChildren(h("div", { class: "empty pulse" }, h("b", {}, S.busy)));
  else if (S.error && S.view !== "analyze") v.replaceChildren(h("div", { class: "empty err" }, h("b", {}, "Analysis failed"), S.error));
  else v.replaceChildren(...[V[S.view]()].flat(2).filter(Boolean));
  // Re-trigger a short entrance transition when a view or result set changes.
  v.classList.remove("view-enter");
  void v.offsetWidth;
  v.classList.add("view-enter");
  window.scrollTo(0, 0);
}
function enter(v) { $("#landing").hidden = true; $("#app").hidden = false; S.view = v || "analyze"; render(); }
$("#enter").addEventListener("click", () => enter("analyze"));
$("#enter-top").addEventListener("click", () => enter("analyze"));
$("#demo").addEventListener("click", () => { enter("analyze"); run("sample", "hard", "watch"); });
