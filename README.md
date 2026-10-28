# transcript-scrubber

Redacts API keys and other secrets from Claude Code transcripts
(`~/.claude/projects`) using [gitleaks](https://github.com/gitleaks/gitleaks)'
rules, on a 15-minute systemd user timer.

## Install

```sh
git clone git@github.com:brendanlong/transcript-scrubber.git ~/opt/transcript-scrubber
~/opt/transcript-scrubber/install.sh
```

Logs: `journalctl --user -u transcript-scrubber`.

## How it avoids damaging transcripts

- Gitleaks only reports. The script replaces each exact reported secret with
  `[REDACTED:<rule-id>]`; it never applies a regex to the file itself.
- Rules that fire on ordinary transcript content (generic high-entropy
  strings, git SHAs) are disabled in `gitleaks.toml`.
- A match is skipped (and logged as `not redacted`) if it looks like it covers
  more than a secret: shorter than 16 characters, contains a `"` (spans JSON
  strings), contains whitespace or line breaks, or is a PEM block whose lines
  aren't each unbroken base64 (prose between markers has spaces). Gitleaks' private-key rule matches lazily up to the next
  `KEY-----`, which can be in a later message.
- Each redaction must keep the line count (except newlines inside a PEM block
  in a text file) and the exact JSON structure (same keys, same list lengths)
  of every line. One bad match doesn't block the other secrets in a file.
- Files modified in the last 30 minutes are skipped so live sessions aren't
  touched, as are files any process has open. The rewrite is an atomic rename that keeps the file's mtime, aborts
  if the file changed or was replaced, and copies over anything appended during the swap.
- The original of every rewritten file is kept (mode 0600) under
  `~/.local/state/transcript-scrubber/backups/<timestamp>/` for 7 days.
- `gitleaks:allow` comments in transcripts are ignored, so transcript text
  can't exempt itself.
- If gitleaks reports any error (e.g. a file it couldn't read), the run aborts
  before recording anything.

`state.sqlite` in the same directory records each file's size and mtime, so
only new or changed files are rescanned. Changing the gitleaks version,
`gitleaks.toml` or `scrub.py` rescans everything.

Run `./scrub.py` without `--apply` to see what would change.

## Tests

```sh
python3 -m unittest -v
```
