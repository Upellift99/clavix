#!/usr/bin/env bash
# Install the system packages Tauri needs on the ubuntu runners, plus any
# extra packages given as arguments (the E2E jobs add webkit2gtk-driver and
# xvfb).
#
# Two failure modes of the runner's apt setup, neither of them ours:
#
# - Google's chrome-stable repo, which the runner image ships, intermittently
#   serves a Packages.gz whose hash does not match its Release file, and
#   `apt-get update` then fails wholesale. Seen on master 2026-09-09 (run
#   34385166551). Retrying does not help, so the source is dropped: every
#   package below lives in Ubuntu's own archive, and the E2E jobs drive
#   WebKitWebDriver, never Chrome.
# - azure.archive.ubuntu.com, the runner's default mirror, sometimes trickles
#   at a few kB/s. apt's own timeouts never fire on a slow-but-alive transfer,
#   so the step used to sit until the job timeout: 25 minutes in #312 and in a
#   CI run of 2026-10-23, and the v0.25.0 release build was cancelled after
#   27 minutes on the 25 MB libwebkit2gtk package. A healthy install takes
#   under a minute, so each attempt gets a hard time limit and the next one
#   switches to another mirror.
# - On 2026-11-11 the runners could not resolve any *.archive.ubuntu.com
#   host for hours (`Temporary failure resolving`), so every Ubuntu-hosted
#   fallback died with the default mirror. The last fallback is kernel.org's
#   full mirror, outside that domain.
set -euo pipefail

packages=(
  libwebkit2gtk-4.1-dev
  libjavascriptcoregtk-4.1-dev
  libsoup-3.0-dev
  libxdo-dev
  libssl-dev
  librsvg2-dev
  libayatana-appindicator3-dev
  libudev-dev
  build-essential
  pkg-config
  "$@"
)

sudo rm -f /etc/apt/sources.list.d/google-chrome.*

# Point apt at the given mirror. The runner image's sources read
# `mirror+file:/etc/apt/apt-mirrors.txt`, so that list is what decides the
# host (rewriting the sources alone changed nothing on 2026-10-23); plain
# archive URLs, in the deb822 file or the legacy list, are rewritten too in
# case an image ships without the mirror list.
use_mirror() {
  if [ -f /etc/apt/apt-mirrors.txt ]; then
    echo "$1" | sudo tee /etc/apt/apt-mirrors.txt >/dev/null
  fi
  local files=()
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources; do
    [ -f "$f" ] && files+=("$f")
  done
  sudo sed -i -E "s#https?://[a-z0-9.-]*archive\.ubuntu\.com/ubuntu/?#$1/#g" "${files[@]}"
}

attempt() {
  timeout 5m sudo apt-get update &&
    timeout 5m sudo apt-get install -y --no-install-recommends "${packages[@]}"
}

# A mirror whose name does not resolve is skipped instead of tried: apt
# spends minutes on its own retries before giving up on it, enough to push
# the job past its timeout before the last fallback gets a turn.
resolves() {
  local host=${1#*://}
  host=${host%%/*}
  timeout 10s getent hosts "$host" >/dev/null
}

default=$(awk 'NR == 1 { print $1 }' /etc/apt/apt-mirrors.txt 2>/dev/null || true)
if [ -z "$default" ] || resolves "$default"; then
  attempt && exit 0
else
  echo "::warning::$default does not resolve; skipping it"
fi
for mirror in http://archive.ubuntu.com/ubuntu http://us.archive.ubuntu.com/ubuntu http://mirrors.edge.kernel.org/ubuntu; do
  if ! resolves "$mirror"; then
    echo "::warning::$mirror does not resolve; skipping it"
    continue
  fi
  echo "::warning::apt install failed or exceeded 5 minutes; retrying from $mirror"
  # A kill during unpacking leaves dpkg half-configured; finish that first.
  sudo dpkg --configure -a || true
  use_mirror "$mirror"
  attempt && exit 0
done
echo "::error::apt install failed on every mirror"
exit 1
