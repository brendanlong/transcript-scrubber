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

    def test_partial_failure_still_redacts_other_secrets(self):
        token = fake_github_pat()
        old = '{"m": "x\\\\ySECRETSECRETSECRET", "t": "%s"}\n' % token
        path = self.write_old("s.jsonl", old)
        c = scrub.Candidate(path, path.stat().st_size, path.stat().st_mtime_ns)
        # A match starting after a backslash would leave a dangling escape.
        r = scrub.process_file(
            c, {"\\ySECRETSECRETSECRET": "bad-rule", token: "github-pat"}, True,
            self.state / "backups")
        self.assertEqual(r.status, "partial")
        self.assertEqual([rule for rule, _ in r.rejected], ["bad-rule"])
        new = json.loads(path.read_text())
        self.assertEqual(new["t"], "[REDACTED:github-pat]")
        self.assertIn("SECRETSECRETSECRET", new["m"])

    def test_match_spanning_messages_is_not_redacted(self):
        body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(200))
        lines = [
            {"type": "user", "message": "what does -----BEGIN RSA PRIVATE KEY----- mean?"},
            {"type": "assistant", "message": f"It starts a PEM block. {body}"},
            {"type": "assistant", "message": "It ends with -----END RSA PRIVATE KEY-----"},
        ]
        for name, content in [
            ("s.jsonl", "\n".join(json.dumps(l) for l in lines)),
            ("s.txt", "\n".join(l["message"] for l in lines) + "\n"),
            ("one-string.jsonl", json.dumps({"m": "\n".join(l["message"] for l in lines)}) + "\n"),
        ]:
            with self.subTest(name):
                path = self.write_old(name, content)
                self.run_scrub("--apply")
                self.assertEqual(path.read_text(), content)

    def test_pem_key_split_across_json_list_items_is_not_redacted(self):
        body = ["".join(secrets.choice(string.ascii_letters) for _ in range(64)) for _ in range(4)]
        patch = ["-----BEGIN PRIVATE KEY-----", *body, "-----END PRIVATE KEY-----"]
        content = json.dumps({"lines": patch}) + "\n"
        path = self.write_old("s.jsonl", content)
        self.run_scrub("--apply")
        self.assertEqual(path.read_text(), content)

    def test_pem_key_in_text_file_is_redacted(self):
        body = "\n".join("".join(secrets.choice(string.ascii_letters) for _ in range(64)) for _ in range(4))
        content = f"before\n-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\nafter\n"
        path = self.write_old("s.txt", content)
        result = self.run_scrub("--apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(path.read_text(), "before\n[REDACTED:private-key]\nafter\n")

    def test_relative_root_is_scanned(self):
        token = fake_github_pat()
        path = self.write_old("s.jsonl", json.dumps({"m": token}) + "\n")
        subprocess.run(
            [sys.executable, str(SCRIPT), "projects", "--state-dir", str(self.state), "--apply"],
            cwd=self.tmp.name, check=True, capture_output=True,
        )
        self.assertNotIn(token, path.read_text())

    def test_redaction_keeps_mtime(self):
        token = fake_github_pat()
        path = self.write_old("s.jsonl", json.dumps({"m": token}) + "\n")
        before = path.stat().st_mtime_ns
        self.run_scrub("--apply")
        self.assertNotIn(token, path.read_text())
        self.assertEqual(path.stat().st_mtime_ns, before)
        self.assertIn("scanning 0 ", self.run_scrub("--apply").stdout)

    def test_implausible_secrets(self):
        self.assertIsNotNone(scrub.implausible_secret("ab:cd"))
        self.assertIsNotNone(scrub.implausible_secret('abcdefghijklmnop","+qrstuvwxyz'))
        self.assertIsNotNone(scrub.implausible_secret("abcdefghijklmnop\\nqrstuvwxyz"))
        self.assertIsNone(scrub.implausible_secret(fake_github_pat()))


if __name__ == "__main__":
    unittest.main()
