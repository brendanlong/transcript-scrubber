#!/usr/bin/env python3
"""Redact secrets that gitleaks finds in Claude Code transcripts.

Gitleaks only reports; this script replaces each exact reported secret string
with a placeholder, and refuses to write a file unless the result still has the
same line structure and every JSON line that parsed before still parses.
"""

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
GITLEAKS = HERE / "bin" / "gitleaks"
CONFIG = HERE / "gitleaks.toml"
TEXT_SUFFIXES = {".jsonl", ".json", ".txt", ".md"}
DEFAULT_STATE_DIR = (
    Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    / "transcript-scrubber"
)


@dataclass(frozen=True)
class Candidate:
    path: Path
    size: int
    mtime_ns: int


def placeholder(rule: str) -> str:
    return f"[REDACTED:{rule}]"


def scan_fingerprint() -> str:
    version = subprocess.run(
        [GITLEAKS, "version"], check=True, capture_output=True, text=True
    ).stdout
    return hashlib.sha256(version.encode() + CONFIG.read_bytes()).hexdigest()


def open_state(state_dir: Path) -> sqlite3.Connection:
    db = sqlite3.connect(state_dir / "state.sqlite")
    db.execute(
        """CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            status TEXT NOT NULL
        )"""
    )
    return db


def find_candidates(
    roots: list[Path], db: sqlite3.Connection, fingerprint: str, quiet_seconds: float
) -> list[Candidate]:
    known = {
        row[0]: row[1:]
        for row in db.execute("SELECT path, size, mtime_ns, fingerprint FROM files")
    }
    cutoff_ns = time.time_ns() - int(quiet_seconds * 1e9)
    candidates = []
    for root in roots:
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                path = Path(dirpath, name)
                if path.suffix not in TEXT_SUFFIXES or path.is_symlink():
                    continue
                st = path.stat()
                if st.st_mtime_ns > cutoff_ns:
                    continue
                if known.get(str(path)) == (st.st_size, st.st_mtime_ns, fingerprint):
                    continue
                candidates.append(Candidate(path, st.st_size, st.st_mtime_ns))
    return candidates


def run_gitleaks(candidates: list[Candidate]) -> dict[Path, dict[str, str]]:
    """Returns {file: {secret: rule_id}}."""
    by_target = {}
    with tempfile.TemporaryDirectory(prefix="transcript-scrubber-") as tmp:
        farm = Path(tmp, "files")
        farm.mkdir()
        for i, c in enumerate(candidates):
            link_name = f"{i}{c.path.suffix}"
            (farm / link_name).symlink_to(c.path)
            by_target[c.path.resolve()] = c.path
        report = Path(tmp, "report.json")
        subprocess.run(
            [
                GITLEAKS, "dir", str(farm),
                "--config", str(CONFIG),
                "--follow-symlinks",
                "--report-format", "json",
                "--report-path", str(report),
                "--exit-code", "0",
                "--no-banner",
                "--log-level", "error",
            ],
            check=True,
        )
        findings = json.loads(report.read_text())

    secrets: dict[Path, dict[str, str]] = {}
    for f in findings:
        path = by_target[Path(f["File"]).resolve()]
        # Matches in JSON text can swallow the backslash of a following escape.
        secret = f["Secret"].rstrip("\\")
        secrets.setdefault(path, {}).setdefault(secret, f["RuleID"])
    return secrets


def redact_text(text: str, secrets: dict[str, str]) -> tuple[str, Counter]:
    counts: Counter = Counter()
    # Longest first so a secret containing another is replaced whole.
    for secret in sorted(secrets, key=len, reverse=True):
        n = text.count(secret)
        if n:
            text = text.replace(secret, placeholder(secrets[secret]))
            counts[secrets[secret]] += n
    return text, counts


def parses(s: str) -> bool:
    try:
        json.loads(s)
    except ValueError:
        return False
    return True


def validation_error(old: str, new: str, suffix: str, secrets: dict[str, str]) -> str | None:
    if any(s in new for s in secrets):
        return "secret still present after replacement"
    removed_newlines = sum(old.count(s) * s.count("\n") for s in secrets)
    if new.count("\n") != old.count("\n") - removed_newlines:
        return "unexpected line count change"
    if suffix == ".jsonl":
        old_lines, new_lines = old.split("\n"), new.split("\n")
        for i, (o, n) in enumerate(zip(old_lines, new_lines), 1):
            if o != n and parses(o) and not parses(n):
                return f"line {i} no longer parses as JSON"
    if suffix == ".json" and parses(old) and not parses(new):
        return "file no longer parses as JSON"
    return None


def backup_path(backup_dir: Path, path: Path) -> Path:
    try:
        rel = path.relative_to(Path.home())
    except ValueError:
        rel = path.relative_to(path.anchor)
    return backup_dir / rel


def write_atomically(c: Candidate, content: str) -> str | None:
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=".scrub-", dir=c.path.parent)
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        shutil.copymode(c.path, tmp_name)
        st = c.path.stat()
        if (st.st_size, st.st_mtime_ns) != (c.size, c.mtime_ns):
            return "file changed while redacting"
        os.replace(tmp_name, c.path)
        return None
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def process_file(
    c: Candidate, secrets: dict[str, str], apply: bool, backup_dir: Path
) -> tuple[str, Counter]:
    """Returns (status, redaction counts by rule). Status is 'redacted',
    'would-redact', 'changed' (retry next run) or 'failed: <reason>'."""
    st = c.path.stat()
    if (st.st_size, st.st_mtime_ns) != (c.size, c.mtime_ns):
        return "changed", Counter()
    raw = c.path.read_bytes()
    try:
        old = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "failed: not UTF-8", Counter()
    new, counts = redact_text(old, secrets)
    if not counts:
        return "failed: reported secret not found in file", Counter()
    if err := validation_error(old, new, c.path.suffix, secrets):
        return f"failed: {err}", Counter()
    if not apply:
        return "would-redact", counts

    backup = backup_path(backup_dir, c.path)
    backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup.write_bytes(raw)
    backup.chmod(0o600)
    if err := write_atomically(c, new):
        backup.unlink()
        return "changed", Counter()
    return "redacted", counts


def prune_backups(backups_root: Path, keep_days: float) -> None:
    if not backups_root.exists():
        return
    cutoff = time.time() - keep_days * 86400
    for d in backups_root.iterdir():
        if d.stat().st_mtime < cutoff:
            shutil.rmtree(d)


def record(db: sqlite3.Connection, path: Path, fingerprint: str, status: str) -> None:
    st = path.stat()
    db.execute(
        "INSERT OR REPLACE INTO files VALUES (?, ?, ?, ?, ?)",
        (str(path), st.st_size, st.st_mtime_ns, fingerprint, status),
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("roots", nargs="*", type=Path,
                   default=[Path.home() / ".claude" / "projects"])
    p.add_argument("--apply", action="store_true",
                   help="rewrite files (default: report only)")
    p.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    p.add_argument("--quiet-minutes", type=float, default=30,
                   help="skip files modified more recently than this")
    p.add_argument("--keep-backup-days", type=float, default=7)
    args = p.parse_args()

    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = open(args.state_dir / "lock", "w")
    fcntl.flock(lock, fcntl.LOCK_EX)

    backups_root = args.state_dir / "backups"
    prune_backups(backups_root, args.keep_backup_days)
    backup_dir = backups_root / time.strftime("%Y%m%dT%H%M%S")

    db = open_state(args.state_dir)
    fingerprint = scan_fingerprint()
    candidates = find_candidates(args.roots, db, fingerprint, args.quiet_minutes * 60)
    print(f"scanning {len(candidates)} new or changed files", flush=True)
    secrets_by_file = run_gitleaks(candidates) if candidates else {}

    totals: Counter = Counter()
    statuses: Counter = Counter()
    failures = []
    for c in candidates:
        secrets = secrets_by_file.get(c.path)
        if not secrets:
            status, counts = "clean", Counter()
        else:
            status, counts = process_file(c, secrets, args.apply, backup_dir)
            print(f"{status}: {c.path} ({', '.join(f'{r}×{n}' for r, n in sorted(counts.items()))})")
            if status.startswith("failed"):
                failures.append(c.path)
        statuses[status.split(":")[0]] += 1
        totals.update(counts)
        # Report-only runs don't record files with findings, so --apply still visits them.
        if status in ("clean", "redacted") or status.startswith("failed"):
            record(db, c.path, fingerprint, status)
    db.commit()

    print("files:", dict(statuses))
    print("redactions by rule:" if args.apply else "would redact by rule:", dict(totals))
    previous = db.execute(
        "SELECT COUNT(*) FROM files WHERE status LIKE 'failed%'"
    ).fetchone()[0]
    if previous:
        print(f"{previous} files have failed redaction and are left unchanged; "
              "see `SELECT path, status FROM files WHERE status LIKE 'failed%'` in state.sqlite")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
