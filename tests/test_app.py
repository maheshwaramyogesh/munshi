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


@unittest.skipIf(create_app is None, "Flask not installed (pip install flask)")
class TestWeb(unittest.TestCase):
    def setUp(self):
        self.client = create_app().test_client()

    def test_index_page_loads_and_has_security_headers(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
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
        self.assertEqual((hard["detected"], hard["planted"], hard["false_alarms"]), (10, 16, 2))


if __name__ == "__main__":
    unittest.main()
