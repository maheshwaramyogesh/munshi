"""
Tests for the web backend. Run from the project root:  python -m unittest -v
Needs:  pip install flask   and the generated logs (easy and hard).
"""
import io
import unittest
from collections import Counter
from pathlib import Path

try:
    from app import create_app
except ImportError:                      # Flask not installed
    create_app = None

ROOT = Path(__file__).resolve().parent.parent
HAVE_DATA = all((ROOT / "logs" / n).exists() for n in
                ("auth.log", "ground_truth.json", "auth_hard.log",
                 "ground_truth_hard.json", "benign_hard.json"))


class TestStaticSafety(unittest.TestCase):
    def test_vnext_javascript_never_uses_innerhtml(self):
        js = (ROOT / "static" / "munshi-vnext" / "app.js").read_text(
            encoding="utf-8"
        )
        code = "\n".join(l for l in js.splitlines() if not l.strip().startswith("//"))
        self.assertNotIn("innerHTML", code)


@unittest.skipIf(create_app is None, "Flask not installed (pip install flask)")
class TestWeb(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_index_page_loads_and_has_security_headers(self):
        r = self.client.get("/", follow_redirects=True)
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Munshi: SSH log analysis", r.data)
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")

    def test_page_javascript_never_uses_innerhtml(self):
        # Log text is attacker-controlled. This guard catches a future XSS mistake.
        js = (ROOT / "static" / "app.js").read_text()
        code = "\n".join(l for l in js.splitlines() if not l.strip().startswith("//"))
        self.assertNotIn("innerHTML", code)

    def test_bad_request_is_rejected(self):
        r = self.client.post("/api/analyze", json={"sample": "../../etc/passwd"})
        self.assertEqual(r.status_code, 400)

    def test_upload_over_size_limit_is_rejected(self):
        big = io.BytesIO(b"x" * (2 * 1024 * 1024 + 10))
        r = self.client.post("/api/analyze", data={"logfile": (big, "big.log")},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 413)

    def test_upload_analyzes_and_never_returns_html(self):
        line = "Oct  1 09:00:00 server01 sshd[1]: Failed password for invalid user {u} from 9.9.9.9 port 22 ssh2\n"
        evil = "<script>alert(1)</script>"
        text = "".join(line.format(u=evil if i == 0 else "root") for i in range(15))
        r = self.client.post("/api/analyze", data={"logfile": (io.BytesIO(text.encode()), "x.log")},
                             content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.mimetype, "application/json")
        self.assertEqual(r.get_json()["summary"]["findings"], 1)
        self.assertIn(evil, r.get_json()["findings"][0]["users"])   # kept as plain data

    def test_empty_upload_returns_zero_findings(self):
        r = self.client.post(
            "/api/analyze",
            data={"logfile": (io.BytesIO(b""), "empty.log")},
            content_type="multipart/form-data",
        )

        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["summary"]["events"], 0)
        self.assertEqual(data["summary"]["skipped"], 0)
        self.assertEqual(data["summary"]["findings"], 0)
        self.assertEqual(data["findings"], [])

    def test_unreadable_text_upload_returns_skipped_count(self):
        r = self.client.post(
            "/api/analyze",
            data={
                "logfile": (
                    io.BytesIO(b"\xff\xfe\x00not an auth log\n\x00\x01still not ssh\n"),
                    "binary.log",
                )
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["summary"]["events"], 0)
        self.assertEqual(data["summary"]["skipped"], 2)
        self.assertEqual(data["summary"]["findings"], 0)
        self.assertEqual(data["findings"], [])

    def test_distributed_campaign_fields_are_exposed_by_api(self):
        lines = []
        expected_ips = []

        for source_index in range(20):
            ip = f"203.0.113.{50 + source_index}"
            expected_ips.append(ip)

            for attempt in range(3):
                event_index = len(lines)
                minute, second = divmod(event_index, 60)
                timestamp = f"Oct  1 09:{minute:02d}:{second:02d}"
                user = f"user{(source_index * 3 + attempt) % 54}"

                lines.append(
                    f"{timestamp} server01 sshd[1]: Failed password for "
                    f"{user} from {ip} port 22 ssh2"
                )

        log_text = "\n".join(lines) + "\n"

        response = self.client.post(
            "/api/analyze",
            data={
                "logfile": (
                    io.BytesIO(log_text.encode("utf-8")),
                    "distributed.log",
                )
            },
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        campaigns = [
            finding
            for finding in data["findings"]
            if finding.get("n_source_ips", 0) > 1
        ]

        self.assertEqual(len(campaigns), 1)
        campaign = campaigns[0]

        # All participating IPs and failures must reach the API response.
        self.assertEqual(campaign["n_source_ips"], 20)
        self.assertEqual(campaign["source_ips"], expected_ips)
        self.assertEqual(len(campaign["source_ips"]), 20)
        self.assertEqual(campaign["failures"], 60)

        # The narrative must describe the campaign accurately.
        narrative = campaign["narrative"]
        self.assertEqual(narrative["status"], "verified")

        summary = narrative["summary"]
        self.assertTrue(summary["verified"])
        self.assertIn("20 source IPs", summary["text"])
        self.assertIn("60 failed authentication attempts", summary["text"])

        claims = {
            claim["kind"]: claim
            for claim in narrative["claims"]
        }

        auth_claim = claims["authentication_context"]
        self.assertTrue(auth_claim["verified"])
        self.assertFalse(auth_claim["value"]["assessed"])
        self.assertIsNone(auth_claim["value"]["observed"])
        self.assertIsNone(auth_claim["value"]["compromised"])

        # Every API narrative-evidence line must come from a verified claim.
        expected_lines = {
            line
            for claim in narrative["claims"]
            if claim.get("verified") is True
            for line in claim.get("evidence_lines", [])
        }
        api_lines = {
            item["line"]
            for item in campaign["narrative_evidence"]
        }

        self.assertEqual(api_lines, expected_lines)

    @unittest.skipUnless(HAVE_DATA, "run generate_logs.py and generate_logs.py --hard first")
    def test_easy_sample_matches_known_planted_attacks(self):
        d = self.client.post("/api/analyze", json={"sample": "easy"}).get_json()
        self.assertEqual(Counter(f["label"] for f in d["findings"]),
                         {"brute_force": 4, "brute_force_success": 3, "password_spray": 3})
        self.assertEqual(d["summary"]["skipped"], 0)

    @unittest.skipUnless(HAVE_DATA, "run generate_logs.py and generate_logs.py --hard first")
    def test_scoreboard_matches_phase_2_results(self):
        easy = self.client.get("/api/score?set=easy").get_json()
        hard = self.client.get("/api/score?set=hard").get_json()
        self.assertEqual((easy["detected"], easy["planted"], easy["false_alarms"]), (10, 10, 0))
        self.assertEqual((hard["detected"], hard["planted"], hard["false_alarms"]), (16, 16, 2))


if __name__ == "__main__":
    unittest.main()
