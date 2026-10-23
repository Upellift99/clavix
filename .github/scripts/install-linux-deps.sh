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

# Rewrite every Ubuntu archive URL in the apt sources to the given mirror.
# Covers both the deb822 file (ubuntu.sources, 24.04) and the legacy list.
use_mirror() {
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

attempt && exit 0
for mirror in http://archive.ubuntu.com/ubuntu http://us.archive.ubuntu.com/ubuntu; do
  echo "::warning::apt install failed or exceeded 5 minutes; retrying from $mirror"
  # A kill during unpacking leaves dpkg half-configured; finish that first.
  sudo dpkg --configure -a || true
  use_mirror "$mirror"
  attempt && exit 0
done
echo "::error::apt install failed on every mirror"
exit 1
