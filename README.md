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
- A file is only rewritten if no secret remains, the line count is unchanged
  (apart from newlines inside a multi-line secret such as a PEM key), and every
  JSON line that parsed before still parses. Otherwise it's left alone and
  logged as `failed`, and the run exits non-zero.
- Files modified in the last 30 minutes are skipped so live sessions aren't
  touched, and the write is an atomic rename that aborts if the file changed.
- The original of every rewritten file is kept (mode 0600) under
  `~/.local/state/transcript-scrubber/backups/<timestamp>/` for 7 days.

`state.sqlite` in the same directory records each file's size and mtime, so
only new or changed files are rescanned. Changing the gitleaks version or
`gitleaks.toml` rescans everything.

Run `./scrub.py` without `--apply` to see what would change.

## Tests

```sh
python3 -m unittest -v
```
