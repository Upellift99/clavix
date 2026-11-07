#!/usr/bin/env bash
# Regenerate the offline sources the Flatpak build needs.
#
# flatpak-builder runs the build with no network, so every crate and every
# npm tarball has to be listed up front as a checksummed source. Run this
# after any change to src-tauri/Cargo.lock or pnpm-lock.yaml, and commit the
# two JSON files it rewrites in packaging/flatpak/.
#
# Needs flatpak-cargo-generator 0.1.5, the version CI checks with
# (`pipx install flatpak-cargo-generator==0.1.5`), and PyYAML. The npm side uses our own scripts/flatpak-node-sources.py: see its
# docstring for why a static registry is enough for a frozen pnpm lockfile.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/packaging/flatpak"

if ! command -v flatpak-cargo-generator >/dev/null 2>&1; then
  echo "error: flatpak-cargo-generator not found (pipx install flatpak-cargo-generator)" >&2
  exit 1
fi

flatpak-cargo-generator "$root/src-tauri/Cargo.lock" -o "$out/cargo-sources.json"
python3 "$root/scripts/flatpak-node-sources.py" "$root/pnpm-lock.yaml" > "$out/node-sources.json"
