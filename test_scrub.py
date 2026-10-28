import json
import os
import secrets
import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import scrub

SCRIPT = Path(__file__).resolve().parent / "scrub.py"


def fake_github_pat() -> str:
    return "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))


class ScrubTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name, "projects")
        self.state = Path(self.tmp.name, "state")
        self.root.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def write_old(self, name: str, content: str) -> Path:
        path = self.root / name
        path.write_text(content)
        old = 1_000_000_000
        os.utime(path, (old, old))
        return path

    def run_scrub(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.root), "--state-dir", str(self.state), *args],
            capture_output=True, text=True,
        )

    def test_apply_redacts_keeps_json_valid_and_backs_up(self):
        token = fake_github_pat()
        lines = [
            {"type": "user", "message": f"use GITHUB_TOKEN={token} please"},
            {"type": "assistant", "message": "no secrets here"},
        ]
        original = "\n".join(json.dumps(l) for l in lines) + "\n"
        path = self.write_old("session.jsonl", original)
        clean = self.write_old("clean.jsonl", json.dumps(lines[1]) + "\n")

        result = self.run_scrub("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(token, result.stdout + result.stderr)

        new = path.read_text()
        self.assertNotIn(token, new)
        parsed = [json.loads(l) for l in new.splitlines()]
        self.assertEqual(len(parsed), 2)
        self.assertIn("[REDACTED:github-pat]", parsed[0]["message"])
        self.assertEqual(parsed[1], lines[1])
        self.assertEqual(clean.read_text(), json.dumps(lines[1]) + "\n")

        backups = list((self.state / "backups").rglob("session.jsonl"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), original)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)

    def test_report_only_leaves_files_alone(self):
        token = fake_github_pat()
        content = json.dumps({"m": token}) + "\n"
        path = self.write_old("s.jsonl", content)
        result = self.run_scrub()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("would-redact", result.stdout)
        self.assertEqual(path.read_text(), content)
        self.assertFalse((self.state / "backups").exists() and any((self.state / "backups").iterdir()))

        # A later --apply still processes the file.
        self.run_scrub("--apply")
        self.assertNotIn(token, path.read_text())

    def test_unchanged_files_are_not_rescanned(self):
        self.write_old("s.jsonl", json.dumps({"m": "hello"}) + "\n")
        self.assertIn("scanning 1 ", self.run_scrub("--apply").stdout)
        self.assertIn("scanning 0 ", self.run_scrub("--apply").stdout)

    def test_recently_modified_files_are_skipped(self):
        token = fake_github_pat()
        path = self.root / "live.jsonl"
        path.write_text(json.dumps({"m": token}) + "\n")
        self.assertIn("scanning 0 ", self.run_scrub("--apply").stdout)
        self.assertIn(token, path.read_text())

    def test_replacement_that_breaks_json_is_rejected(self):
        # A match starting after a backslash leaves a dangling escape.
        old = '{"m": "x\\\\ySECRET"}'
        bad = {"\\ySECRET": "rule"}
        new, _ = scrub.redact_text(old, bad)
        self.assertEqual(scrub.validation_error(old, new, ".jsonl", bad),
                         "line 1 no longer parses as JSON")

    def test_secret_with_newlines_in_text_file(self):
        old = "before\n-----BEGIN KEY-----\nabc\n-----END KEY-----\nafter\n"
        s = {"-----BEGIN KEY-----\nabc\n-----END KEY-----": "private-key"}
        new, _ = scrub.redact_text(old, s)
        self.assertIsNone(scrub.validation_error(old, new, ".txt", s))
        self.assertEqual(new, "before\n[REDACTED:private-key]\nafter\n")


if __name__ == "__main__":
    unittest.main()
