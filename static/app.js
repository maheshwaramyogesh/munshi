// app.js - talks to the Flask backend and draws the page.
// SECURITY RULE: log text is attacker-controlled, so we only ever insert it with
// textContent / createTextNode. Never innerHTML.

const $ = (id) => document.getElementById(id);

function setStatus(msg, isError) {
  const el = $("status");
  el.textContent = msg;
  el.className = isError ? "error" : "";
}

function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (cls) node.className = cls;
  return node;
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

const LABELS = {
  brute_force: "Brute force",
  brute_force_success: "Brute force, then broke in",
  password_spray: "Password spray",
};

function renderSummary(s) {
  const box = $("summary");
  clear(box);
  [["Events read", s.events], ["Lines skipped", s.skipped],
   ["Findings", s.findings], ["Break-ins", s.compromises]].forEach(([name, val]) => {
    const card = el("div", undefined, "stat");
    card.appendChild(el("b", String(val)));
    card.appendChild(el("span", name));
    box.appendChild(card);
  });
  box.hidden = false;
}

function showEvidence(f, row) {
  document.querySelectorAll("#findings tbody tr").forEach((r) => r.classList.remove("selected"));
  row.classList.add("selected");
  const shown = f.evidence_preview.length;
  $("evidence-note").textContent =
    `${f.ip}: ${f.evidence_total} log lines support this finding` +
    (shown < f.evidence_total ? ` (showing the first ${shown}).` : ".");
  $("evidence").textContent = f.evidence_preview.map((e) => `line ${e.line}: ${e.text}`).join("\n");
  $("evidence-section").hidden = false;
}

function renderFindings(findings) {
  const body = document.querySelector("#findings tbody");
  clear(body);
  findings.forEach((f) => {
    const tr = document.createElement("tr");
    const typeCell = el("td");
    typeCell.appendChild(el("span", LABELS[f.label] || f.label, f.compromised ? "tag danger" : "tag"));
    tr.appendChild(typeCell);
    tr.appendChild(el("td", f.ip));
    tr.appendChild(el("td", f.start));
    tr.appendChild(el("td", String(f.failures)));
    const names = f.users.join(", ") + (f.n_users > f.users.length ? ` ... (${f.n_users} total)` : "");
    tr.appendChild(el("td", names));
    tr.appendChild(el("td", f.compromised ? `YES (${f.compromised_user})` : "no",
                      f.compromised ? "yes" : "no"));
    tr.addEventListener("click", () => showEvidence(f, tr));
    body.appendChild(tr);
  });
  $("findings-section").hidden = false;
  $("evidence-section").hidden = true;
}

function renderScore(data, name) {
  const box = $("score");
  clear(box);
  const table = el("table", undefined, "score-table");
  const head = document.createElement("tr");
  ["Attack variant", "Planted", "Detected", "Correct type"].forEach((h) => head.appendChild(el("th", h)));
  table.appendChild(head);
  Object.entries(data.by_variant).forEach(([variant, v]) => {
    const tr = document.createElement("tr");
    tr.appendChild(el("td", variant.replace(/_/g, " ")));
    tr.appendChild(el("td", String(v.planted)));
    tr.appendChild(el("td", String(v.detected), v.detected === v.planted ? "good" : "badtxt"));
    tr.appendChild(el("td", String(v.correct_type)));
    table.appendChild(tr);
  });
  box.appendChild(table);
  const causes = Object.entries(data.false_alarm_causes).map(([k, n]) => `${k.replace(/_/g, " ")}: ${n}`).join(", ");
  box.appendChild(el("p",
    `Dataset: ${name}. Detected ${data.detected}/${data.planted}. False alarms: ${data.false_alarms}` +
    (causes ? ` (${causes}).` : "."), "hint"));
  $("score-section").hidden = false;
}

async function handle(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Server error (${response.status})`);
  return data;
}

async function loadSample(name) {
  setStatus(`Analyzing the ${name} sample...`);
  try {
    const result = await handle(await fetch("/api/analyze", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sample: name }),
    }));
    renderSummary(result.summary);
    renderFindings(result.findings);
    renderScore(await handle(await fetch(`/api/score?set=${name}`)), name);
    setStatus(`Done: ${result.summary.findings} findings from ${result.summary.events} events.`);
  } catch (err) {
    setStatus(err.message, true);
  }
}

async function uploadFile(file) {
  setStatus("Analyzing your file...");
  try {
    const form = new FormData();
    form.append("logfile", file);
    const result = await handle(await fetch("/api/analyze", { method: "POST", body: form }));
    renderSummary(result.summary);
    renderFindings(result.findings);
    $("score-section").hidden = true;   // no answer key exists for an uploaded file
    setStatus(`Done: ${result.summary.findings} findings from ${result.summary.events} events.`);
  } catch (err) {
    setStatus(err.message, true);
  }
}

$("btn-easy").addEventListener("click", () => loadSample("easy"));
$("btn-hard").addEventListener("click", () => loadSample("hard"));
$("file-input").addEventListener("change", (e) => { if (e.target.files[0]) uploadFile(e.target.files[0]); });
