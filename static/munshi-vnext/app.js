const calm = matchMedia("(prefers-reduced-motion: reduce)").matches, fine = matchMedia("(pointer: fine)").matches;
"use strict";
// Munshi vNext. Log text is attacker-controlled: only text nodes / textContent are used (no innerHTML).
const $ = (s) => document.querySelector(s);
const NS = "http://www.w3.org/2000/svg";
function h(tag, a, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(a || {})) {
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v != null && v !== false) e.setAttribute(k, v);
  }
  for (const c of kids.flat(3)) if (c != null && c !== false) e.append(c);
  return e;
}
function sv(tag, a) { const e = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(a || {})) e.setAttribute(k, v); return e; }
const S = { view: "watch", data: null, ds: null, score: null, sel: null, line: null, filter: "all", q: "", sort: "start", busy: null, err: null };
const NAV = [["watch", "Watch"], ["analyze", "Analyze"], ["findings", "Findings"], ["investigate", "Investigate"], ["chronicle", "Chronicle"], ["evaluation", "Evaluation"], ["reports", "Reports"]];
const TYPE = { brute_force: "Brute force", brute_force_success: "Brute force, authentication observed", password_spray: "Password spray" };
const COL = { brute_force: "var(--blue)", brute_force_success: "var(--red)", password_spray: "var(--vio)" };
const fmt = (n) => Number(n).toLocaleString("en-US");
const list = () => (S.data ? S.data.findings : []);
const pct = (a, b) => (b ? `${((100 * a) / b).toFixed(1)}%` : "n/a");
const sourceIps = (f) => Array.isArray(f.source_ips) && f.source_ips.length ? f.source_ips : [f.ip];
const sourceFull = (f) => sourceIps(f).join(", ");
const sourceShort = (f, n = 4) => {
  const ips = sourceIps(f);
  if (ips.length === 1) return ips[0];
  const shown = ips.slice(0, n).join(", ");
  const more = ips.length > n ? `, +${fmt(ips.length - n)} more` : "";
  return `${fmt(ips.length)} addresses: ${shown}${more}`;
};
const Source = (f, n = 4) => h("span", { title: sourceFull(f) }, sourceShort(f, n));
function auth(f) {
  const u = f.episode_success_users || [], n = f.episode_success_count ?? u.length;
  if (!n && !f.compromised) return { on: false, text: "No successful authentication observed in the window" };
  if (n > 1) return { on: true, text: `Authentication observed for ${n} usernames (ambiguous)` };
  const who = u[0] || f.compromised_user; return { on: true, text: `Authentication observed${who ? ": " + who : ""}` };
}
const when = (t) => { const m = /^([A-Z][a-z]{2}\s+\d+\s+[\d:]{8})/.exec(t); return m ? m[1] : ""; };
async function call(url, opts) {
  const r = await fetch(url, opts); let d = {};
  try { d = await r.json(); } catch (e) { /* non-JSON error page */ }
  if (!r.ok) throw new Error(d.error || (r.status === 413 ? "File too large (limit 2 MB)." : `Server error (${r.status})`));
  return d;
}
async function run(kind, p, to) {
  S.busy = kind === "file" ? `Analyzing ${p.name}…` : `Analyzing the ${p} sample…`; S.err = null; render();
  try {
    if (kind === "file") {
      const fd = new FormData(); fd.append("logfile", p);
      S.data = await call("/api/analyze", { method: "POST", body: fd }); S.ds = { name: p.name, size: p.size }; S.score = null;
    } else {
      S.data = await call("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ sample: p }) });
      S.ds = { name: `${p} sample`, key: p }; S.score = null;
      try { S.score = await call(`/api/score?set=${p}`); } catch (e) { S.err = "Analysis loaded, but scoring failed: " + e.message; }
    }
    S.sel = null; S.line = null; S.filter = "all"; S.q = "";
  } catch (e) { S.err = e.message; }
  S.busy = null; S.view = to; render();
}
const open = (f, line) => { S.sel = f; S.line = line ?? null; go("investigate"); };
const Btn = (t, fn, c) => h("button", { class: `app-btn ${c || ""}`, onclick: fn }, t);
const Head = (t, s) => [h("h2", {}, t), h("p", { class: "sub" }, s)];
const Met = (l, v, n, c) => h("div", { class: `panel met ${c || ""}` }, h("small", {}, l), h("b", {}, v), h("span", {}, n));
const sampleBtns = (to) => h("div", { class: "chips" }, Btn("Load Easy Sample", () => run("sample", "easy", to), "pri"), Btn("Load Hard Sample", () => run("sample", "hard", to)));
const need = (what) => h("div", { class: "empty" }, h("b", {}, "No analysis loaded"), `${what} needs a log. Load a sample or upload a file.`, sampleBtns(S.view));
const copy = (text, btn) => { const o = btn.textContent; (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(() => { btn.textContent = "Copied"; }, () => { btn.textContent = "Copy unavailable"; }).finally(() => setTimeout(() => (btn.textContent = o), 1200)); };
const summary = (f) => `${TYPE[f.label] || f.label} from ${sourceShort(f)}, ${f.start} to ${f.end}: ${f.failures} failed attempts, ${f.n_users} usernames. ${auth(f).text}. Evidence lines: ${f.evidence_total}.`;
function PathViz(f) {
  const a = auth(f), steps = [["Failures", fmt(f.failures)], ["Rule match", f.kind === "password_spray" ? "Password spray" : "Brute force"], ["Evidence", `${fmt(f.evidence_total)} lines`], ["Authentication", a.on ? "observed" : "none observed"]];
  const svg = sv("svg", { class: "pv", viewBox: "0 0 560 76", role: "img", "aria-label": `Path: ${steps.map((t) => t.join(" ")).join(", then ")}` });
  steps.forEach((t, i) => {
    const x = 50 + i * 153, selectedEvidence = i === 2 && S.line != null, authObserved = i === 3 && a.on;
    if (i) svg.append(sv("path", { class: `seg s${i}`, pathLength: 1, d: `M${x - 153 + 9} 20 L${x - 9} 20` }));
    svg.append(
      sv("circle", { class: `nd-halo h${i} ${selectedEvidence ? "on" : ""} ${authObserved ? "red" : ""}`, cx: x, cy: 20, r: 11 }),
      sv("circle", { class: `nd n${i} ${selectedEvidence ? "on" : ""} ${authObserved ? "red" : ""}`, cx: x, cy: 20, r: 7 }),
      sv("circle", { class: `nd-core d${i} ${selectedEvidence ? "on" : ""} ${authObserved ? "red" : ""}`, cx: x, cy: 20, r: 2.5 })
    );
    const l = sv("text", { x, y: 48 }); l.textContent = t[0]; const v = sv("text", { class: "pv2", x, y: 64 }); v.textContent = t[1]; svg.append(l, v);
  });
  return svg;
}
function Donut(L) {
  const c = {}; L.forEach((f) => (c[f.label] = (c[f.label] || 0) + 1));
  const R = 54, C = 2 * Math.PI * R, svg = sv("svg", { class: "donut", viewBox: "0 0 140 140", role: "img", "aria-label": "Findings by type" }); let acc = 0;
  const ks = Object.keys(c); ks.forEach((k) => { const len = (c[k] / L.length) * C, ci = sv("circle", { cx: 70, cy: 70, r: R, stroke: COL[k] || "var(--tx2)", "stroke-dashoffset": -acc, "stroke-dasharray": `0 ${C}` }); svg.append(ci); requestAnimationFrame(() => requestAnimationFrame(() => ci.setAttribute("stroke-dasharray", `${len - 2} ${C - len + 2}`))); acc += len; });
  return h("div", {}, svg, h("ul", { class: "leg" }, ks.map((k) => h("li", {}, h("span", {}, (() => { const i = h("i"); i.style.background = COL[k] || "var(--tx2)"; return i; })(), TYPE[k] || k), c[k]))));
}
const V = {};
V.watch = () => {
  if (!S.data) return [Head("Watch", "Summary of the loaded log."), need("The overview")];
  const m = S.data.summary, L = list(), fa = S.score ? S.score.false_alarms : null, max = Math.max(1, ...L.map((f) => f.failures));
  const bars = h("div", { class: "bars", role: "group", "aria-label": "Failed attempts per finding in start-time order" }, L.map((f, i) => { const b = h("button", { class: `bar ${auth(f).on ? "a" : ""}`, title: `${sourceShort(f)}: ${f.failures} failures. Full source list: ${sourceFull(f)}`, "aria-label": `${sourceShort(f)}, ${f.failures} failures`, onclick: () => open(f) }); b.addEventListener("mouseenter", () => say(f)); b.addEventListener("focus", () => say(f)); b.style.height = `${(100 * f.failures) / max}%`; b.style.animationDelay = `${Math.min(i * 15, 400)}ms`; return b; }));
  const readout = h("div", { class: "bar-readout", id: "readout", "aria-live": "polite" },
    h("div", { class: "br-empty" }, h("span", { class: "br-empty-dot" }), h("span", {}, "Hover or focus a bar to inspect its finding.")));
  const say = (f) => {
    const a = auth(f);
    const state = h("span", { class: `br-state ${a.on ? "observed" : "quiet"}` }, a.on ? "Authentication observed" : "Failures only");
    const facts = [["Failed attempts", fmt(f.failures)], ["Usernames", fmt(f.n_users)], ["Evidence lines", fmt(f.evidence_total)]];
    readout.replaceChildren(
      h("div", { class: "br-head" },
        h("div", { class: "br-identity" },
          h("span", { class: "br-overline" }, "Selected finding"),
          h("strong", { class: "br-name" }, TYPE[f.label] || f.label),
          h("code", { class: "br-ip mono", title: sourceFull(f) }, sourceShort(f))), state),
      h("div", { class: "br-metrics" }, facts.map(([label, value]) => h("div", { class: "br-metric" }, h("span", {}, label), h("b", {}, value)))),
      h("div", { class: "br-foot" }, h("span", { class: "mono br-window" }, `${f.start}  →  ${f.end}`), h("span", { class: "br-auth" }, a.text))
    );
  };
  const lit = (f, on) => { const b = bars.children[L.indexOf(f)]; if (b) b.classList.toggle("hot", on); };
  const recent = [...L].sort((a, b) => b.start.localeCompare(a.start)).slice(0, 6);
  if (L[0]) { say(L[0]); lit(L[0], true); }
  const dots = h("div", { class: "ax" }, h("span", {}, L[0] ? L[0].start.slice(0, 16) : ""), h("span", {}, L.length ? L[L.length - 1].start.slice(0, 16) : ""));
  return [Head("Watch", "Replay of the loaded log, not a live feed."),
    h("div", { class: "g4" }, Met("Events analyzed", fmt(m.events), `${fmt(m.skipped)} lines skipped`), Met("Rule matches", fmt(m.findings), "findings from the rules", "red"),
      Met("Authentication observed", fmt(L.filter((f) => auth(f).on).length), "findings with a success in window", "jade"), Met("False alarms", fa == null ? "n/a" : fa, fa == null ? "known for built-in samples only" : "per the answer key")),
    h("div", { class: "g2" }, h("div", { class: "panel" }, h("h3", {}, "Failed attempts per finding, in start-time order (red: authentication observed)"), L.length ? [bars, dots, readout] : "No findings."),
      h("div", { class: "panel" }, h("h3", {}, "Findings by type"), L.length ? Donut(L) : "No findings.")),
    h("div", { class: "panel" }, h("h3", {}, "Most recent findings by start time"), h("ul", { class: "stream" }, recent.map((f) => h("li", {}, h("button", { onclick: () => open(f), onmouseenter: () => lit(f, true), onmouseleave: () => lit(f, false), onfocus: () => lit(f, true), onblur: () => lit(f, false), title: sourceFull(f) }, h("b", {}, TYPE[f.label] || f.label), h("small", { class: "mono" }, `${sourceShort(f)} · ${f.start} · ${fmt(f.failures)} failures`))))))];
};
V.analyze = () => {
  const inp = h("input", { type: "file", accept: ".log,.txt", hidden: true, "aria-label": "Choose log file" });
  inp.addEventListener("change", () => inp.files[0] && run("file", inp.files[0], "analyze"));
  const z = h("div", { class: "drop" }, h("b", {}, "Drop an SSH auth log here"), h("p", { class: "sub drop-help" }, "OpenSSH auth logs · 2 MB max · In-memory processing; never stored."), Btn("Choose file", () => inp.click(), "pri"), inp);
  ["dragenter", "dragover"].forEach((t) => z.addEventListener(t, (e) => { e.preventDefault(); z.classList.add("over"); }));
  ["dragleave", "drop"].forEach((t) => z.addEventListener(t, (e) => { e.preventDefault(); z.classList.remove("over"); }));
  z.addEventListener("drop", (e) => e.dataTransfer.files[0] && run("file", e.dataTransfer.files[0], "analyze"));
  const m = S.data && S.data.summary;
  const out = S.busy ? h("div", { class: "empty pulse" }, h("b", {}, S.busy), "The server parses and applies the rules in one request. No finer progress is reported, so none is shown.")
    : S.err ? h("div", { class: "empty err" }, h("b", {}, "Analysis problem"), S.err)
    : m ? h("div", { class: "panel met jade" }, h("small", {}, "Analysis complete"), h("b", {}, `${fmt(m.events)} events`), h("span", {}, `${S.ds.name}${S.ds.size != null ? ` · ${fmt(S.ds.size)} bytes` : ""} · ${fmt(m.skipped)} skipped · ${m.findings} findings`), h("div", { class: "chips" }, Btn("View findings", () => go("findings"), "pri"), Btn("Open Watch", () => go("watch"))))
    : h("div", { class: "empty" }, h("b", {}, "No log loaded"), "Choose a file or load a built-in synthetic sample.");
  return [Head("Analyze", "Load an SSH authentication log."), z, sampleBtns("analyze"), out];
};
V.findings = () => {
  if (!S.data) return [Head("Findings", "Rule matches in the loaded log."), need("The findings queue")];
  const L = list(), kinds = [...new Set(L.map((f) => f.label))], q = S.q.toLowerCase();
  let shown = L.filter((f) => (S.filter === "all" || (S.filter === "auth" ? auth(f).on : f.label === S.filter)) && (!q || sourceIps(f).some((ip) => ip.includes(q)) || f.users.some((u) => u.toLowerCase().includes(q)) || (TYPE[f.label] || "").toLowerCase().includes(q)));
  shown = shown.sort((a, b) => S.sort === "failures" ? b.failures - a.failures : a.start.localeCompare(b.start));
  const chip = (k, n, c) => h("button", { class: `chip ${S.filter === k ? "on" : ""}`, "aria-pressed": S.filter === k, onclick: () => { S.filter = k; render(); } }, `${n} (${c})`);
  const search = h("input", { class: "in-s", type: "search", placeholder: "Search IP, username, type", "aria-label": "Search findings", value: S.q });
  search.addEventListener("input", () => { S.q = search.value; const p = search.selectionStart; render(); const n = $("#view .in-s"); n.focus(); n.setSelectionRange(p, p); });
  const sort = h("select", { class: "in-s", "aria-label": "Sort", onchange: (e) => { S.sort = e.target.value; render(); } }, h("option", { value: "start", selected: S.sort === "start" }, "Sort: start time"), h("option", { value: "failures", selected: S.sort === "failures" }, "Sort: most failures"));
  const pvp = h("div", { class: "panel pvp" }), showPath = (f) => pvp.replaceChildren(h("h3", {}, `Signal path: ${sourceShort(f)}, ${TYPE[f.label] || f.label}`), PathViz(f));
  if (shown[0]) showPath(shown[0]);
  const tr = (f) => { const a = auth(f), r = h("tr", { tabindex: 0, class: S.sel === f ? "sel" : "", onclick: () => open(f) }, h("td", {}, h("b", {}, TYPE[f.label] || f.label)), h("td", { class: "mono" }, Source(f)), h("td", { class: "mono" }, f.start), h("td", {}, fmt(f.failures)), h("td", {}, f.n_users), h("td", {}, h("span", { class: `st ${a.on ? "j" : ""}` }, a.on ? (a.text.includes("ambiguous") ? "Observed, ambiguous" : "Authentication observed") : "Failures only")));
    r.addEventListener("keydown", (e) => e.key === "Enter" && open(f)); r.addEventListener("mouseenter", () => showPath(f)); r.addEventListener("focus", () => showPath(f)); return r; };
  return [Head("Findings", "Rule matches only. No severity score exists, and an IP address is not a person."), h("div", { class: "chips" }, search, sort), h("div", { class: "chips" }, chip("all", "All", L.length), kinds.map((k) => chip(k, TYPE[k] || k, L.filter((f) => f.label === k).length)), chip("auth", "Authentication observed", L.filter((f) => auth(f).on).length)),
    shown.length ? [pvp, h("div", { class: "panel" }, h("table", { class: "tbl" }, h("thead", {}, h("tr", {}, ["Rule", "Source", "First failure", "Failures", "Usernames", "Authentication"].map((c) => h("th", {}, c)))), h("tbody", {}, shown.map(tr))))] : h("div", { class: "empty" }, h("b", {}, "No findings match"), "Clear the search or pick another filter.")];
};
function pickLine(n) {
  S.line = n;
  document.querySelectorAll(".pv").forEach((svg) => {
    svg.querySelectorAll(".n2").forEach((e) => e.classList.add("on"));
    svg.querySelectorAll(".h2,.d2").forEach((e) => e.classList.add("on"));
  });
  document.querySelectorAll("[data-ln]").forEach((e) => { const on = Number(e.dataset.ln) === n; e.classList.toggle(e.classList.contains("lr") ? "sel" : "on", on); if (on && e.classList.contains("lr")) e.scrollIntoView({ block: "nearest" }); });
}
V.investigate = () => {
  const f = S.sel;

  if (!f) {
    return [
      Head("Investigate", "Why a rule matched, and the lines that show it."),
      h(
        "div",
        { class: "empty" },
        h("b", {}, "No finding selected"),
        "Pick one from the queue.",
        h("div", { class: "chips" },
          Btn("Open findings", () => go("findings"), "pri")
        )
      )
    ];
  }

  // Combine detector evidence and evidence explicitly referenced
  // by verified narrative claims. Keep original line numbers and text.
  const rawEntries = [
    ...(Array.isArray(f.evidence_preview) ? f.evidence_preview : []),
    ...(Array.isArray(f.narrative_evidence) ? f.narrative_evidence : [])
  ];

  const byLine = new Map();

  rawEntries.forEach((item) => {
    const line = Number(item.line);

    if (
      Number.isInteger(line) &&
      line > 0 &&
      !byLine.has(line)
    ) {
      byLine.set(line, {
        line,
        text: String(item.text ?? "")
      });
    }
  });

  const ev = [...byLine.values()].sort((a, b) => a.line - b.line);
  const succ = new Set(f.episode_success_lines || []);
  const a = auth(f);
  const row = (k, v, c) => [
    h("dt", {}, k),
    h("dd", { class: c || "" }, v)
  ];

  const narrative =
    f.narrative && typeof f.narrative === "object"
      ? f.narrative
      : null;

  const verifiedClaims = Array.isArray(narrative?.claims)
    ? narrative.claims.filter(
        (claim) =>
          claim &&
          claim.verified === true &&
          typeof claim.text === "string"
      )
    : [];

  const verifiedSummary =
    narrative?.summary?.verified === true &&
    typeof narrative.summary.text === "string"
      ? narrative.summary
      : null;

  // Show only claims verified by the backend.
  const claimCards = verifiedClaims.map((claim) => {
    const references = Array.isArray(claim.evidence_lines)
      ? claim.evidence_lines.filter(
          (line) => Number.isInteger(line) && byLine.has(line)
        )
      : [];

    return h(
      "article",
      { class: "narrative-claim" },
      h(
        "div",
        { class: "narrative-claim-title" },
        String(claim.kind || "Claim").replace(/_/g, " ")
      ),
      h("p", {}, claim.text),
      h(
        "div",
        { class: "chips narrative-links" },
        references.length
          ? references.map((line) =>
              Btn(`Line ${line}`, () => pickLine(line))
            )
          : h("span", { class: "sub" }, "No source lines available here")
      ),
      claim.evidence_truncated
        ? h(
            "p",
            { class: "sub" },
            `${fmt(claim.evidence_line_count)} supporting lines exist; only a subset is shown.`
          )
        : null
    );
  });

  const narrativePanel = h(
    "section",
    { class: "panel narrative-panel" },
    h(
      "div",
      { class: "narrative-head" },
      h(
        "div",
        {},
        h("h3", {}, "Evidence-linked explanation"),
        h(
          "p",
          { class: "sub" },
          "Deterministic claims checked against parsed events."
        )
      ),
      h(
        "span",
        {
          class: `pill ${
            narrative?.status === "verified" ? "on" : ""
          }`
        },
        narrative?.status === "verified"
          ? "Verified"
          : narrative?.status === "partial"
            ? "Partial"
            : "Unavailable"
      )
    ),
    verifiedSummary
      ? h("p", { class: "narrative-summary" }, verifiedSummary.text)
      : h(
          "p",
          { class: "sub" },
          "No verified summary is available. Inspect the original log evidence below."
        ),
    ...claimCards,
    verifiedClaims.length === 0
      ? h(
          "p",
          { class: "sub" },
          "No verified claims are available for this finding."
        )
      : null,
    narrative?.verification
      ? h(
          "p",
          { class: "sub narrative-foot" },
          `${fmt(narrative.verification.verified_claims || 0)} claims verified` +
            (
              narrative.verification.rejected_claims
                ? ` · ${fmt(narrative.verification.rejected_claims)} rejected`
                : ""
            )
        )
      : null
  );

  const tl = h(
    "ul",
    { class: "ev" },
    ev.map((e) => {
      const li = h(
        "li",
        {
          "data-ln": e.line,
          class: S.line === e.line ? "on" : ""
        },
        h(
          "button",
          {
            onclick: () => pickLine(e.line),
            "aria-label": `Evidence line ${e.line}`
          },
          h("span", {}, e.line),
          h("span", {}, when(e.text)),
          h("span", {}, succ.has(e.line) ? "success" : "failed")
        )
      );

      return li;
    })
  );

  const log = h(
    "div",
    {
      class: "log",
      role: "list",
      "aria-label": "Raw log lines"
    },
    ev.map((e) =>
      h(
        "div",
        {
          class: `lr ${
            succ.has(e.line) ? "ok" : ""
          } ${S.line === e.line ? "sel" : ""}`,
          role: "listitem",
          "data-ln": e.line,
          onclick: () => pickLine(e.line)
        },
        h("b", {}, e.line),
        h("span", {}, e.text)
      )
    )
  );

  const cb = h("button", { class: "app-btn" }, "Copy selected line");
  cb.addEventListener("click", () => {
    const entry = ev.find((item) => item.line === S.line);

    if (entry) {
      copy(entry.text, cb);
    } else {
      cb.textContent = "Select a line first";
    }
  });

  const cs = h("button", { class: "app-btn" }, "Copy finding summary");
  cs.addEventListener("click", () =>
    copy(verifiedSummary?.text || summary(f), cs)
  );

  return [
    Head(
      `${TYPE[f.label] || f.label}`,
      `Source ${sourceShort(f)}. A rule match, not proof of intent or identity.`
    ),

    h("div", { class: "panel pvp" }, PathViz(f)),

    narrativePanel,

    h(
      "div",
      { class: "ws" },
      h(
        "div",
        {},
        h(
          "div",
          { class: "panel" },
          h("h3", {}, "Finding facts"),
          h(
            "dl",
            { class: "f" },
            row("Source", h("span", { title: sourceFull(f) }, sourceShort(f)), "mono"),
            row("First failure", f.start, "mono"),
            row("Last", f.end, "mono"),
            row("Failures", fmt(f.failures)),
            row(
              "Usernames",
              f.users.join(", ") +
                (f.n_users > f.users.length
                  ? `, … (${f.n_users} total)`
                  : ""),
              "mono"
            ),
            row("Authentication", a.text),
            row("Detector evidence lines", fmt(f.evidence_total))
          )
        ),
        h(
          "div",
          { class: "panel" },
          h("h3", {}, "Evidence timeline — select a line to locate it"),
          tl,
          h("div", { class: "chips" }, cs)
        )
      ),
      h(
        "div",
        { class: "panel" },
        h(
          "div",
          { class: "logb" },
          h("h3", {}, "Raw log — exact source text"),
          cb
        ),
        log,
        h(
          "p",
          { class: "sub" },
          `Showing ${fmt(ev.length)} source lines available to this investigation, including narrative references. Detector evidence total: ${fmt(f.evidence_total)}.`
        )
      )
    )
  ];
};
V.chronicle = () => {
  if (!list().length) return [Head("Chronicle", "What was observed, and in what order?"), S.data ? h("div", { class: "empty" }, h("b", {}, "No findings to order")) : need("The chronicle")];
  const L = [...list()].sort((x, y) => x.start.localeCompare(y.start));
  return [Head("Chronicle", "Findings in time order. Recorded facts only; no narrative or interpretation is generated."),
    h("div", { class: "panel" }, h("ul", { class: "tl" }, L.map((f) => { const first = f.evidence_preview[0]; return h("li", { class: auth(f).on ? "a" : "" }, h("div", { class: "mono" }, `${f.start} to ${f.end}`), h("b", {}, TYPE[f.label] || f.label), h("div", { class: "sub" }, h("span", { title: sourceFull(f) }, sourceShort(f)), ` · ${fmt(f.failures)} failures · ${f.n_users} usernames · ${auth(f).text}`), h("div", { class: "chips" }, first ? Btn(`Evidence from line ${first.line}`, () => open(f, first.line)) : null)); }))),
    h("p", { class: "note" }, "Interpretation (intent, identity, compromise) is not made here. Investigation explains why a rule matched; Chronicle only orders what was recorded.")];
};
V.evaluation = () => {
  const sc = S.score;
  if (!sc) return [Head("Evaluation", "Detector results against a planted-attack answer key."), h("div", { class: "empty" }, h("b", {}, "No answer key for this dataset"), "Only the built-in samples have one; uploads do not.", sampleBtns("evaluation"))];
  const fl = list().length, meter = (l, a, b, red) => { const i = h("i"); i.style.width = "0%"; requestAnimationFrame(() => requestAnimationFrame(() => { i.style.width = b ? `${(100 * a) / b}%` : "0%"; })); return h("div", { class: `meter ${red ? "r" : ""}` }, h("span", {}, l), h("div", {}, i), h("small", {}, `${a} of ${b} · ${pct(a, b)}`)); };
  const causes = Object.entries(sc.false_alarm_causes);
  return [Head("Evaluation", `Dataset: ${S.ds.name}`), h("div", { class: "banner" }, "Synthetic data with planted attacks and a fixed seed. These numbers describe the rules on this dataset only, not accuracy or performance on real systems."),
    h("div", { class: "g4" }, Met("Planted attacks", sc.planted, "in the answer key"), Met("Detected", sc.detected, pct(sc.detected, sc.planted), "jade"), Met("Missed", sc.planted - sc.detected, "planted minus detected", "red"), Met("False alarms", sc.false_alarms, `of ${fl} findings`, "red")),
    h("div", { class: "panel" }, h("h3", {}, "Rates on this dataset"), meter("Detected", sc.detected, sc.planted), meter("Correct type", sc.correct_type, sc.planted), meter("Findings that were false alarms", sc.false_alarms, fl, true)),
    h("div", { class: "g2" }, h("div", { class: "panel" }, h("h3", {}, "By attack variant"), h("table", { class: "tbl" }, h("thead", {}, h("tr", {}, ["Variant", "Planted", "Detected", "Correct type", "Missed"].map((c) => h("th", {}, c)))), h("tbody", {}, Object.entries(sc.by_variant).map(([k, r]) => h("tr", {}, h("td", {}, k.replace(/_/g, " ")), h("td", {}, r.planted), h("td", {}, r.detected), h("td", {}, r.correct_type), h("td", {}, r.planted - r.detected)))))),
      h("div", { class: "panel" }, h("h3", {}, "False alarm causes"), causes.length ? h("table", { class: "tbl" }, h("tbody", {}, causes.map(([k, n]) => h("tr", {}, h("td", {}, k.replace(/_/g, " ")), h("td", {}, n))))) : "None.", h("p", { class: "note" }, "The API returns counts only, so individual missed attacks cannot be named.")))];
};
V.reports = () => {
  if (!S.data) return [Head("Reports", "Export the loaded analysis."), need("A report")];
  const save = (n, t, x) => { const u = URL.createObjectURL(new Blob([x], { type: t })); const l = h("a", { href: u, download: n }); document.body.append(l); l.click(); l.remove(); URL.revokeObjectURL(u); };
  const q = (x) => `"${String(x).replace(/"/g, '""')}"`, m = S.data.summary, sc = S.score, L = [...list()].sort((a, b) => a.start.localeCompare(b.start));
  const csv = () => ["type,n_source_ips,source_ips,representative_source_ip,start,end,failures,usernames,authentication_observed,evidence_lines"].concat(list().map((f) => [f.label, sourceIps(f).length, sourceIps(f).join(";"), f.ip, f.start, f.end, f.failures, f.n_users, auth(f).on, f.evidence_total].map(q).join(","))).join("\n");
  return [Head("Reports", "JSON and CSV download, and Print (choose “Save as PDF” in the print dialog). The page below is the report."),
    h("div", { class: "chips noprint" }, Btn("Download JSON", () => save("munshi_report.json", "application/json", JSON.stringify({ dataset: S.ds, summary: m, findings: list(), score: sc }, null, 2)), "pri"), Btn("Download CSV", () => save("munshi_findings.csv", "text/csv", csv())), Btn("Print", () => window.print())),
    h("div", { class: "paper print-ok" }, h("h2", {}, "Munshi analysis report"), h("p", { class: "mono" }, `Dataset: ${S.ds.name}`),
      h("h3", {}, "1. Analysis summary"), h("p", {}, `${fmt(m.events)} events read, ${fmt(m.skipped)} lines skipped, ${m.findings} rule matches.`),
      h("h3", {}, "2. Detection findings and evidence references"), h("table", {}, h("thead", {}, h("tr", {}, ["Rule", "Source", "Failures", "Evidence lines (shown)"].map((c) => h("th", {}, c)))), h("tbody", {}, L.slice(0, 20).map((f) => h("tr", {}, h("td", {}, TYPE[f.label] || f.label), h("td", { class: "mono", title: sourceFull(f) }, sourceShort(f)), h("td", {}, fmt(f.failures)), h("td", { class: "mono" }, f.evidence_preview.length ? `${fmt(f.evidence_preview.length)} of ${fmt(f.evidence_total)} lines shown` : "none"))))), L.length > 20 ? h("p", {}, `…${L.length - 20} more in the exports.`) : null,
      h("h3", {}, "3. Chronological sequence"), h("ul", {}, L.slice(0, 20).map((f) => h("li", { class: "mono", title: sourceFull(f) }, `${f.start}  ${TYPE[f.label] || f.label}  ${sourceShort(f)}`))),
      sc ? [h("h3", {}, "4. Evaluation (synthetic data)"), h("p", {}, `${sc.detected} of ${sc.planted} planted attacks detected; ${sc.planted - sc.detected} missed; ${sc.false_alarms} false alarms.`)] : null,
      h("h3", {}, "Limitations"), h("p", {}, "Rule-based detection with per-IP rules plus one cross-address rule. Thresholds are fixed and narrow, so activity just outside them can be missed. Shared addresses and forgotten-password retries can cause false alarms. An address is not a person. Results on synthetic data do not describe real-world performance."))];
};
function go(v) { S.view = v; render(); }
function render() {
  $("#nav").replaceChildren(...NAV.map(([k, n]) => h("button", { class: `nav ${S.view === k ? "on" : ""}`, "aria-current": S.view === k ? "page" : null, "aria-label": n, onclick: () => go(k) }, h("b", {}, n[0]), h("span", {}, n))));
  $("#crumb").textContent = NAV.find((n) => n[0] === S.view)[1];
  const d = $("#dataset"); d.textContent = S.ds ? S.ds.name : "no dataset"; d.className = `pill ${S.ds ? "on" : ""}`;
  d.dataset.state = S.busy ? "busy" : S.err ? "err" : S.ds ? "ok" : "none";
  $("#live").textContent = S.busy ? S.busy : S.err ? `Problem: ${S.err}` : S.data ? `${S.ds.name} loaded: ${fmt(S.data.summary.events)} events, ${S.data.summary.findings} findings.` : "";
  const v = $("#view"); let kids;
  if (S.busy && S.view !== "analyze") kids = [h("div", { class: "empty pulse" }, h("b", {}, S.busy))];
  else kids = [V[S.view]()].flat(3).filter(Boolean);
  const ae = document.activeElement, keep = ae && ae.classList.contains("in-s");
  v.replaceChildren(...kids); v.style.animation = "none"; void v.offsetWidth; v.style.animation = ""; if (!keep) v.scrollTop = 0;
}
// command palette (Ctrl/Cmd+K)
let palSel = 0, palItems = [];
function palRender() {
  const q = $("#pal-in").value.toLowerCase().trim();
  palItems = NAV.filter(([, n]) => n.toLowerCase().includes(q)).map(([k, n]) => ({ t: `Go to ${n}`, s: "screen", fn: () => go(k) }));
  if (q) list().filter((f) => sourceIps(f).some((ip) => ip.includes(q)) || f.users.some((u) => u.toLowerCase().includes(q)) || (TYPE[f.label] || "").toLowerCase().includes(q)).slice(0, 8).forEach((f) => palItems.push({ t: `${TYPE[f.label] || f.label}`, s: `${sourceShort(f)} · ${f.start}`, fn: () => open(f) }));
  palSel = Math.min(palSel, Math.max(palItems.length - 1, 0));
  $("#pal-list").replaceChildren(...(palItems.length ? palItems.map((it, i) => h("li", { role: "option", "aria-selected": i === palSel ? "true" : "false", onclick: () => palGo(i) }, h("span", {}, it.t), h("small", {}, it.s))) : [h("li", {}, "No match")]));
}
function palGo(i) { const it = palItems[i]; if (!it) return; palClose(); if ($("#app").hidden) enter(S.view); it.fn(); }
function palOpen() { $("#pal").hidden = false; $("#pal-in").value = ""; palSel = 0; palRender(); $("#pal-in").focus(); }
function palClose() { $("#pal").hidden = true; }
$("#pal-in").addEventListener("input", () => { palSel = 0; palRender(); });
$("#pal-in").addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { palSel = Math.min(palSel + 1, palItems.length - 1); palRender(); e.preventDefault(); }
  else if (e.key === "ArrowUp") { palSel = Math.max(palSel - 1, 0); palRender(); e.preventDefault(); }
  else if (e.key === "Enter") palGo(palSel);
});
$("#pal").addEventListener("click", (e) => e.target.id === "pal" && palClose());
$("#pal-open").addEventListener("click", palOpen);
document.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); $("#pal").hidden ? palOpen() : palClose(); } else if (e.key === "Escape" && !$("#pal").hidden) palClose(); });
function enter(view) { $("#site").hidden = true; $("#app").hidden = false; document.body.className = "is-app"; S.view = view; render(); $("#view").focus(); }
function home() { $("#app").hidden = true; $("#site").hidden = false; document.body.className = "is-site"; window.scrollTo(0, 0); }
let leaving = false;
function launch(view) { if (leaving) return; if (calm) { enter(view); return; } leaving = true; $("#site").classList.add("leave"); setTimeout(() => { enter(view); $("#site").classList.remove("leave"); leaving = false; }, 230); }
document.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => launch(b.dataset.open)));
document.querySelector("[data-home]").addEventListener("click", home);
// ---- landing live effects (all decorative; nothing here represents real security data) ----
const revs = document.querySelectorAll(".story .rv,.final.rv");
if ("IntersectionObserver" in window && !calm) { const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { threshold: 0.15 }); revs.forEach((n) => io.observe(n)); }
else revs.forEach((n) => n.classList.add("in"));
// signal node / stage-label linking (hover or keyboard focus lights the matching label)
const hot = (k, on) => document.querySelectorAll(`[data-s="${k}"]`).forEach((e) => e.classList.toggle("hot", on));
document.querySelectorAll(".node,.strip li").forEach((e) => { const k = e.dataset.s; ["mouseenter", "focusin"].forEach((t) => e.addEventListener(t, () => hot(k, true))); ["mouseleave", "focusout"].forEach((t) => e.addEventListener(t, () => hot(k, false))); });
// scroll-linked story progression
(function story() {
  const sec = $("#story"), chaps = [...document.querySelectorAll(".chap")], rl = [...document.querySelectorAll(".rail li")], bar = $(".rail .bar");
  if (!sec || !("IntersectionObserver" in window)) return;
  const io = new IntersectionObserver((es) => es.forEach((e) => { if (!e.isIntersecting) return; const i = chaps.indexOf(e.target); rl.forEach((l, j) => l.classList.toggle("on", j === i)); sec.dataset.stage = i; bar.style.transform = `scaleX(${(i + 1) / chaps.length})`; }), { rootMargin: "-45% 0px -50% 0px" });
  chaps.forEach((c) => io.observe(c));
})();
// living signal landscape: clean animated waves, layered parallax and pointer light
(function stage() {
  const hero = $(".hero"), cv = $("#fx"), spot = $(".spot"), ctx = cv && cv.getContext ? cv.getContext("2d") : null;
  if (calm || !hero || !ctx) return;
  const layers = [...document.querySelectorAll(".layer")].map((el) => ({ el, k: el.dataset.k.split(",").map(Number) }));
  let W = 0, H = 0, tx = 0, ty = 0, cx = 0, cy = 0, mx = 0, my = 0, sx = 0, sy = 0, raf = 0, run = false, last = 0, inView = false;
  function size() {
    const r = cv.getBoundingClientRect(), dpr = Math.min(devicePixelRatio || 1, 2); W = r.width; H = r.height; cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  function tick(t) {
    if (!run) return; raf = requestAnimationFrame(tick);
    const dt = Math.min((t - last) / 1000 || 0.016, 0.05); last = t;
    cx += (tx - cx) * 0.08; cy += (ty - cy) * 0.08; sx += (mx - sx) * 0.12; sy += (my - sy) * 0.12;
    const sc = Math.min(window.scrollY, innerHeight);
    layers.forEach((l) => { l.el.style.transform = `translate3d(${(-cx * l.k[0]).toFixed(2)}px,${(-cy * l.k[1] + sc * l.k[2]).toFixed(2)}px,0)`; });
    spot.style.transform = `translate3d(${sx.toFixed(1)}px,${sy.toFixed(1)}px,0)`;
    ctx.clearRect(0, 0, W, H);
    // Living signal ocean: broad, shape-changing swells with visible traveling crest highlights.
    // The left edge is intentionally quieter so the headline remains readable.
    const smoothstep = (a, b, x) => { const u = Math.max(0, Math.min(1, (x - a) / (b - a))); return u * u * (3 - 2 * u); };
    const envelope = (x) => 0.16 + 0.84 * smoothstep(W * 0.12, W * 0.88, x);
    ctx.save();
    ctx.globalCompositeOperation = "screen";
    for (let i = 0; i < 6; i++) {
      const base = H * (0.19 + i * 0.12);
      const amp = Math.min(H * 0.06, 24 + i * 4.1);
      const phase = t * (0.00031 + i * 0.000043) + i * 1.07;
      const waveY = (x) => {
        const e = envelope(x);
        const swell = Math.sin(x * 0.0022 + phase) * amp
          + Math.sin(x * 0.0057 - phase * 0.72 + i * 0.36) * amp * 0.28
          + Math.cos(x * 0.00115 + phase * 0.44 - i * 0.21) * amp * 0.22;
        return base + swell * e;
      };
      // A very low-opacity body gives the crest a watery surface rather than a bare wireframe.
      if (i % 2 === 0) {
        ctx.beginPath();
        for (let x = -8; x <= W + 8; x += 7) {
          const y = waveY(x);
          if (x <= -8) ctx.moveTo(x, y); else ctx.lineTo(x, y);
        }
        ctx.lineTo(W + 8, H * 1.15);
        ctx.lineTo(-8, H * 1.15);
        ctx.closePath();
        const body = ctx.createLinearGradient(0, base - amp, 0, H * 1.05);
        body.addColorStop(0, `rgba(42,111,194,${0.035 + i * 0.003})`);
        body.addColorStop(0.42, `rgba(32,91,166,${0.018 + i * 0.002})`);
        body.addColorStop(1, "rgba(8,14,28,0)");
        ctx.fillStyle = body;
        ctx.fill();
      }
      // Stable blue contour.
      ctx.beginPath();
      for (let x = -8; x <= W + 8; x += 6) {
        const y = waveY(x);
        if (x <= -8) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = `rgba(105,183,255,${0.11 + i * 0.018})`;
      ctx.lineWidth = 1.05 + i * 0.1;
      ctx.stroke();
      // A moving highlight travels along each evolving crest, so water movement is perceptible.
      const head = ((t * 0.052 + i * W / 5) % (W + 420)) - 210;
      const sheen = ctx.createLinearGradient(head - 210, 0, head + 210, 0);
      sheen.addColorStop(0, "rgba(105,183,255,0)");
      sheen.addColorStop(0.34, "rgba(105,183,255,0.035)");
      sheen.addColorStop(0.5, `rgba(198,231,255,${0.26 + i * 0.018})`);
      sheen.addColorStop(0.66, "rgba(105,183,255,0.06)");
      sheen.addColorStop(1, "rgba(105,183,255,0)");
      ctx.beginPath();
      for (let x = -8; x <= W + 8; x += 6) {
        const y = waveY(x);
        if (x <= -8) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = sheen;
      ctx.lineWidth = 1.35 + i * 0.08;
      ctx.stroke();
    }
    ctx.restore();
  }
  const setRun = (v) => { if (v && !run) { run = true; last = performance.now(); raf = requestAnimationFrame(tick); } else if (!v) { run = false; cancelAnimationFrame(raf); } };
  const sync = () => setRun(inView && !document.hidden);
  new IntersectionObserver((es) => { inView = es[0].isIntersecting; sync(); }).observe(hero);
  document.addEventListener("visibilitychange", sync);
  let rt = 0; window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(size, 150); });
  size();
  if (fine) {
    hero.addEventListener("pointermove", (e) => { const r = hero.getBoundingClientRect(); mx = e.clientX - r.left; my = e.clientY - r.top; tx = mx / r.width - 0.5; ty = my / r.height - 0.5; spot.style.opacity = 1; });
    hero.addEventListener("pointerleave", () => { tx = 0; ty = 0; spot.style.opacity = 0; });
  }
})();
