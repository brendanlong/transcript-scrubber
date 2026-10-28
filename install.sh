#!/bin/sh
# Installs gitleaks into bin/ and enables the systemd user timer.
# Expects this repo to be checked out at ~/opt/transcript-scrubber.
set -eu
cd "$(dirname "$0")"

VERSION=8.30.1
SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
TARBALL="gitleaks_${VERSION}_linux_x64.tar.gz"

if ! bin/gitleaks version 2>/dev/null | grep -qx "$VERSION"; then
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    curl -sSfL -o "$tmp/$TARBALL" "https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/${TARBALL}"
    echo "$SHA256  $tmp/$TARBALL" | sha256sum -c -
    mkdir -p bin
    tar -xzf "$tmp/$TARBALL" -C bin gitleaks
fi

mkdir -p ~/.config/systemd/user
ln -sf "$PWD/systemd/transcript-scrubber.service" "$PWD/systemd/transcript-scrubber.timer" ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now transcript-scrubber.timer
