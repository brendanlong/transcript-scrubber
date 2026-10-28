#!/usr/bin/env python3
"""Redact secrets that gitleaks finds in Claude Code transcripts.

Gitleaks only reports; this script replaces each exact reported secret string
with a placeholder. A secret is only redacted if the result keeps the file's
line structure and the structure of every JSON value in it.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
GITLEAKS = HERE / "bin" / "gitleaks"
CONFIG = HERE / "gitleaks.toml"
TEXT_SUFFIXES = {".jsonl", ".json", ".txt", ".md"}
MIN_SECRET_LENGTH = 16
DEFAULT_STATE_DIR = (
    Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    / "transcript-scrubber"
)


@dataclass(frozen=True)
class Candidate:
    path: Path
    size: int
    mtime_ns: int


@dataclass
class Result:
    # redacted | partial | would-redact | failed | changed | vanished
    status: str
    counts: Counter = field(default_factory=Counter)
    rejected: list[tuple[str, str]] = field(default_factory=list)
    chars_removed: int = 0
    # (size, mtime_ns) to record, or None to rescan next run
    recorded_stat: tuple[int, int] | None = None


def placeholder(rule: str) -> str:
    return f"[REDACTED:{rule}]"


def scan_fingerprint() -> str:
    version = subprocess.run(
        [GITLEAKS, "version"], check=True, capture_output=True, text=True
    ).stdout
    return hashlib.sha256(
        version.encode() + CONFIG.read_bytes() + Path(__file__).read_bytes()
    ).hexdigest()


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
                try:
                    st = path.stat()
                except FileNotFoundError:
                    continue
                if st.st_mtime_ns > cutoff_ns:
                    continue
                if known.get(str(path)) == (st.st_size, st.st_mtime_ns, fingerprint):
                    continue
                candidates.append(Candidate(path, st.st_size, st.st_mtime_ns))
    return candidates


def run_gitleaks(candidates: list[Candidate], work_dir: Path) -> dict[Path, dict[str, str]]:
    """Returns {file: {secret: rule_id}}."""
    by_target = {}
    # The report holds plaintext secrets, so keep it in the private state dir.
    with tempfile.TemporaryDirectory(prefix="scan-", dir=work_dir) as tmp:
        farm = Path(tmp, "files")
        farm.mkdir()
        for i, c in enumerate(candidates):
            (farm / f"{i}{c.path.suffix}").symlink_to(c.path)
            by_target[c.path.resolve()] = c.path
        report = Path(tmp, "report.json")
        proc = subprocess.run(
            [
                GITLEAKS, "dir", str(farm),
                "--config", str(CONFIG),
                "--follow-symlinks",
                "--report-format", "json",
                "--report-path", str(report),
                "--exit-code", "0",
                "--no-banner",
                "--log-level", "error",
                # Transcript text must not be able to exempt itself.
                "--ignore-gitleaks-allow",
            ],
            capture_output=True, text=True,
        )
        # Gitleaks logs skipped files as errors but still exits 0; recording
        # those files as clean would hide them forever.
        if proc.returncode != 0 or proc.stderr.strip():
            sys.exit(f"gitleaks failed (exit {proc.returncode}):\n{proc.stderr}")
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


PEM = re.compile(r"-----BEGIN[ A-Z0-9_-]*-----(.*)-----END[ A-Z0-9_-]*-----", re.S)
LINE_BREAKS = re.compile(r"\\[nrt]|\s")
# Raw newlines, or JSON-escaped ones (possibly escaped more than once).
PEM_LINE_SPLIT = re.compile(r"(?:\\)*\\[nr]|[\r\n]")
# Line numbers from `cat -n`, grep -n or Claude Code's Read tool.
LINE_NUMBER = re.compile(r"\s*\d+(?:\\t|\t|→|:|-)")
BASE64 = re.compile(r"[A-Za-z0-9+/=]+")


def is_pem_body(body: str) -> bool:
    """True if every line is unbroken base64, as in a real key. Prose has spaces."""
    lines = []
    for line in PEM_LINE_SPLIT.split(body):
        if m := LINE_NUMBER.match(line):
            line = line[m.end():]
        if line := line.strip():
            lines.append(line)
    return sum(map(len, lines)) >= 64 and all(BASE64.fullmatch(l) for l in lines)


def implausible_secret(secret: str) -> str | None:
    """Catches matches that probably cover more than a secret, which would
    delete surrounding content without breaking any structure."""
    if len(secret) < MIN_SECRET_LENGTH:
        return f"shorter than {MIN_SECRET_LENGTH} characters"
    if '"' in secret:
        return "spans more than one JSON string"
    if "-----BEGIN" in secret:
        # The private-key rule matches lazily up to the next "KEY-----", which
        # can be in a later message.
        m = PEM.fullmatch(secret)
        if not m or not is_pem_body(m[1]):
            return "PEM body isn't lines of base64"
    elif LINE_BREAKS.search(secret):
        return "contains whitespace or line breaks"
    return None


def json_shape(value):
    if isinstance(value, dict):
        return {k: json_shape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_shape(v) for v in value]
    if isinstance(value, str):
        return str
    return value


def shape_or_none(s: str):
    try:
        return json_shape(json.loads(s))
    except ValueError:
        return None


def validation_error(old: str, new: str, suffix: str, secrets: dict[str, str]) -> str | None:
    if any(s in new for s in secrets):
        return "secret still present after replacement"
    removed_newlines = (
        0 if suffix in (".jsonl", ".json")
        else sum(old.count(s) * s.count("\n") for s in secrets)
    )
    if new.count("\n") != old.count("\n") - removed_newlines:
        return "unexpected line count change"
    if suffix == ".jsonl":
        for i, (o, n) in enumerate(zip(old.split("\n"), new.split("\n")), 1):
            if o != n and (shape := shape_or_none(o)) is not None and shape != shape_or_none(n):
                return f"JSON structure of line {i} changed"
    if suffix == ".json" and (shape := shape_or_none(old)) is not None and shape != shape_or_none(new):
        return "JSON structure changed"
    return None


def backup_path(backup_dir: Path, path: Path) -> Path:
    try:
        rel = path.relative_to(Path.home())
    except ValueError:
        rel = path.relative_to(path.anchor)
    return backup_dir / rel


def write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def open_by_any_process(path: Path) -> bool:
    """A writer holding the file open would keep writing to the old inode
    after the rename, losing everything it writes from then on."""
    target = str(path.resolve())
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            fds = os.listdir(f"/proc/{pid}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(f"/proc/{pid}/fd/{fd}") == target and int(pid) != os.getpid():
                    return True
            except OSError:
                continue
    return False


def replace_file(c: Candidate, content: str) -> Result:
    """Atomically replaces c.path, keeping its mtime. Bytes appended to the old
    file during the swap are copied over, and the file is left for rescanning."""
    with open(c.path, "rb") as old:
        st = os.fstat(old.fileno())
        if (st.st_size, st.st_mtime_ns) != (c.size, c.mtime_ns):
            return Result("changed")
        tmp_fd, tmp_name = tempfile.mkstemp(prefix=".scrub-", dir=c.path.parent)
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8", newline="") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            shutil.copymode(c.path, tmp_name)
            os.utime(tmp_name, ns=(c.mtime_ns, c.mtime_ns))
            new_st = os.stat(tmp_name)
            st = os.fstat(old.fileno())
            current = os.stat(c.path)
            if (
                (st.st_size, st.st_mtime_ns) != (c.size, c.mtime_ns)
                or (current.st_dev, current.st_ino) != (st.st_dev, st.st_ino)
                or open_by_any_process(c.path)
            ):
                return Result("changed")
            os.replace(tmp_name, c.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        old.seek(c.size)
        if late := old.read():
            with open(c.path, "ab") as f:
                f.write(late)
            print(f"warning: {len(late)} bytes appended during rewrite were copied: {c.path}")
            return Result("redacted")
    return Result("redacted", recorded_stat=(new_st.st_size, new_st.st_mtime_ns))


def process_file(
    c: Candidate, secrets: dict[str, str], apply: bool, backup_dir: Path
) -> Result:
    raw = c.path.read_bytes()
    if len(raw) != c.size:
        return Result("changed")
    scanned = (c.size, c.mtime_ns)
    try:
        old = raw.decode("utf-8")
    except UnicodeDecodeError:
        return Result("failed", rejected=[("*", "not UTF-8")], recorded_stat=scanned)

    accepted: dict[str, str] = {}
    rejected = []
    for secret, rule in sorted(secrets.items(), key=lambda kv: len(kv[0]), reverse=True):
        if reason := implausible_secret(secret):
            rejected.append((rule, reason))
        elif secret not in old:
            rejected.append((rule, "not in file verbatim"))
        else:
            trial = accepted | {secret: rule}
            if err := validation_error(old, redact_text(old, trial)[0], c.path.suffix, trial):
                rejected.append((rule, err))
            else:
                accepted = trial
    if not accepted:
        return Result("failed", rejected=rejected, recorded_stat=scanned)

    new, counts = redact_text(old, accepted)
    status = "partial" if rejected else "redacted"
    result = Result(status, counts, rejected, len(old) - len(new), scanned)
    if not apply:
        result.status = "would-redact"
        return result

    write_private(backup_path(backup_dir, c.path), raw)
    written = replace_file(c, new)
    if written.status == "changed":
        return written
    result.recorded_stat = written.recorded_stat
    return result


def prune_backups(backups_root: Path, keep_days: float) -> None:
    if not backups_root.exists():
        return
    cutoff = time.time() - keep_days * 86400
    for d in backups_root.iterdir():
        if d.is_dir() and d.stat().st_mtime < cutoff:
            shutil.rmtree(d)


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
    roots = [r.absolute() for r in args.roots]

    os.umask(0o077)
    args.state_dir.mkdir(parents=True, exist_ok=True)
    lock = open(args.state_dir / "lock", "w")
    fcntl.flock(lock, fcntl.LOCK_EX)

    backups_root = args.state_dir / "backups"
    prune_backups(backups_root, args.keep_backup_days)
    backups_root.mkdir(exist_ok=True)
    backup_dir = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%dT%H%M%S-"), dir=backups_root))

    db = open_state(args.state_dir)
    fingerprint = scan_fingerprint()
    candidates = find_candidates(roots, db, fingerprint, args.quiet_minutes * 60)
    print(f"scanning {len(candidates)} new or changed files", flush=True)
    secrets_by_file = run_gitleaks(candidates, args.state_dir) if candidates else {}

    totals: Counter = Counter()
    statuses: Counter = Counter()
    any_rejected = False
    for c in candidates:
        secrets = secrets_by_file.get(c.path)
        try:
            if secrets:
                r = process_file(c, secrets, args.apply, backup_dir)
            else:
                r = Result("clean", recorded_stat=(c.size, c.mtime_ns))
        except FileNotFoundError:
            r = Result("vanished")
        if secrets:
            counts = ", ".join(f"{rule}×{n}" for rule, n in sorted(r.counts.items()))
            print(f"{r.status}: {c.path} ({counts}; {r.chars_removed} chars removed)")
            for rule, reason in r.rejected:
                print(f"  not redacted: {rule}: {reason}")
        any_rejected |= bool(r.rejected)
        statuses[r.status] += 1
        totals.update(r.counts)
        # Report-only runs don't record files with findings, so --apply still visits them.
        if r.recorded_stat and r.status != "would-redact":
            db.execute(
                "INSERT OR REPLACE INTO files VALUES (?, ?, ?, ?, ?)",
                (str(c.path), *r.recorded_stat, fingerprint, r.status),
            )
    db.commit()
    if not any(backup_dir.iterdir()):
        backup_dir.rmdir()

    print("files:", dict(statuses))
    print("redactions by rule:" if args.apply else "would redact by rule:", dict(totals))
    unresolved = db.execute(
        "SELECT COUNT(*) FROM files WHERE status IN ('failed', 'partial')"
    ).fetchone()[0]
    if unresolved:
        print(f"{unresolved} files have findings that weren't redacted; they are "
              "rescanned only when they change")
    return 1 if any_rejected else 0


if __name__ == "__main__":
    sys.exit(main())
