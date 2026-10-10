"""
app.py - Munshi's web backend (Flask). Runs on YOUR laptop only.

Endpoints
  GET  /                 the page
  POST /api/analyze      analyze a log. Send EITHER a file (form field "logfile")
                         OR JSON like {"sample": "easy"} / {"sample": "hard"}
  GET  /api/score?set=easy|hard   detector scoreboard against the answer key

SECURITY CHOICES (good seminar talking points)
- Log text is attacker-controlled (usernames!). The server returns it as JSON data
  and the page shows it with textContent only, never as HTML (prevents XSS).
- Upload size is capped. Uploaded files are parsed in memory, never saved to disk,
  and the user-supplied filename is never used.
- Debug mode is OFF and the server binds to 127.0.0.1 (this machine only).
- Basic security headers are added to every response.

Run:  python app.py     then open http://127.0.0.1:5000
"""

import io
import json
from pathlib import Path

from flask import Flask, jsonify, redirect, request, send_from_directory

from munshi.detectors import Config, detect
from munshi.evaluate import score
from munshi.parsing import parse_file, parse_lines
from munshi.narrative import build_narrative

ROOT = Path(__file__).resolve().parent
SAMPLES = {
    "easy": {"log": ROOT / "logs" / "auth.log",
             "truth": ROOT / "logs" / "ground_truth.json", "benign": None},
    "hard": {"log": ROOT / "logs" / "auth_hard.log",
             "truth": ROOT / "logs" / "ground_truth_hard.json",
             "benign": ROOT / "logs" / "benign_hard.json"},
}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024     # 2 MB is plenty for this project
EVIDENCE_PREVIEW = 25                  # max evidence lines sent per finding


def finding_to_dict(f, raw_by_line):
    """Turn a Finding into plain JSON-safe data for the page."""
    return {
        "kind": f.kind, "label": f.label, "ip": f.ip,
        "source_ips": getattr(f, "source_ips", None) or [f.ip],
        "n_source_ips": len(getattr(f, "source_ips", None) or [f.ip]),
        "start": f.start.isoformat(sep=" "), "end": f.end.isoformat(sep=" "),
        "failures": f.failures, "n_users": len(f.users), "users": f.users[:10],
        "compromised": f.compromised, "compromised_user": f.compromised_user,
        "episode_success_users": f.episode_success_users,
        "episode_success_count": len(f.episode_success_users),
        "episode_success_lines": f.episode_success_lines,
        "evidence_total": len(f.evidence),
        "evidence_preview": [{"line": n, "text": raw_by_line.get(n, "")}
                             for n in f.evidence[:EVIDENCE_PREVIEW]],
    }


def analyze(parsed):
    config = Config()
    findings = detect(parsed.events, config)
    raw = {event.line_no: event.raw for event in parsed.events}

    serialized_findings = []

    for finding in findings:
        item = finding_to_dict(finding, raw)

        narrative = build_narrative(
            finding,
            parsed.events,
            config,
            max_evidence_lines=EVIDENCE_PREVIEW,
        )

        # Collect the unique source lines referenced by verified claims.
        referenced_lines = sorted({
            line
            for claim in narrative.get("claims", [])
            if claim.get("verified") is True
            for line in claim.get("evidence_lines", [])
            if isinstance(line, int) and line in raw
        })

        # Preserve all existing finding fields and add the narrative.
        item["narrative"] = narrative
        item["narrative_evidence"] = [
            {"line": line, "text": raw[line]}
            for line in referenced_lines
        ]

        serialized_findings.append(item)

    return {
        "summary": {
            "events": len(parsed.events),
            "skipped": len(parsed.skipped),
            "findings": len(findings),
            "compromises": sum(
                1 for finding in findings if finding.compromised
            ),
        },
        "findings": serialized_findings,
    }


def create_app():
    app = Flask(__name__, static_folder=str(ROOT / "static"), static_url_path="/static")
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.get("/")
    def index():
        return redirect("/static/munshi-vnext/index.html")

    @app.post("/api/analyze")
    def api_analyze():
        upload = request.files.get("logfile")
        if upload is not None:
            text = upload.stream.read().decode("utf-8", errors="replace")
            return jsonify(analyze(parse_lines(io.StringIO(text))))

        body = request.get_json(silent=True) or {}
        name = body.get("sample")
        if name not in SAMPLES:
            return jsonify(error="Send a file in 'logfile' or {'sample': 'easy'|'hard'}."), 400
        path = SAMPLES[name]["log"]
        if not path.exists():
            return jsonify(error=f"Sample '{name}' not found. Run generate_logs.py first."), 404
        return jsonify(analyze(parse_file(str(path))))

    @app.get("/api/score")
    def api_score():
        name = request.args.get("set", "")
        if name not in SAMPLES:
            return jsonify(error="set must be 'easy' or 'hard'"), 400
        s = SAMPLES[name]
        if not (s["log"].exists() and s["truth"].exists()):
            return jsonify(error=f"Sample '{name}' not found. Run generate_logs.py first."), 404
        findings = detect(parse_file(str(s["log"])).events, Config())
        truth = json.loads(s["truth"].read_text())
        benign = json.loads(s["benign"].read_text()) if s["benign"] else None
        r = score(findings, truth, benign)
        return jsonify({
            "planted": r["planted"], "detected": r["detected"],
            "correct_type": r["correct_type"], "false_alarms": len(r["false_alarms"]),
            "false_alarm_causes": r["false_alarm_causes"],
            "by_variant": {k: {"planted": v[0], "detected": v[1], "correct_type": v[2]}
                           for k, v in r["by_variant"].items()},
        })

    return app


if __name__ == "__main__":
    # debug=False and host=127.0.0.1 on purpose (see the security notes at the top)
    create_app().run(host="127.0.0.1", port=5000, debug=False)
