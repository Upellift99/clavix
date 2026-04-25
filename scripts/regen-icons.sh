#!/usr/bin/env bash
# Regenerate every PNG/ICO/ICNS icon Tauri ships with from the
# canonical SVG source at `assets/clavix-logo.svg`. Run this any
# time the SVG changes; commit the resulting binaries alongside
# the SVG so contributors who don't have the toolchain installed
# still see the latest mark.
#
# Toolchain:
#   - ImageMagick (`convert`)        — for PNG + ICO. apt install imagemagick.
#   - libicns (`png2icns`)           — for ICNS. apt install libicns-utils
#                                       (Debian) / brew install libicns
#                                       (macOS). Optional: the script
#                                       skips ICNS regen if absent and
#                                       prints a warning, so the rest
#                                       of the icons still update.
#
# Usage:
#   ./scripts/regen-icons.sh
#
# Run from the repo root.

set -euo pipefail

SVG="assets/clavix-logo.svg"
OUT_DIR="src-tauri/icons"
FAVICON="static/favicon.png"

if [[ ! -f "$SVG" ]]; then
  echo "error: $SVG not found — run from the repo root." >&2
  exit 1
fi

# Quick cap on accidentally running this without ImageMagick installed.
if ! command -v convert >/dev/null 2>&1; then
  echo "error: ImageMagick 'convert' not found." >&2
  echo "  apt install imagemagick   # Debian/Ubuntu" >&2
  echo "  brew install imagemagick  # macOS" >&2
  exit 1
fi

echo "→ Regenerating PNG icons from $SVG"

# Tauri's bundle reads icon.png at 1024² — the largest single export.
convert -background none -density 300 "$SVG" -resize 1024x1024 "$OUT_DIR/icon.png"
convert -background none -density 300 "$SVG" -resize 256x256  "$OUT_DIR/128x128@2x.png"
convert -background none -density 300 "$SVG" -resize 128x128  "$OUT_DIR/128x128.png"
convert -background none -density 300 "$SVG" -resize 32x32    "$OUT_DIR/32x32.png"
convert -background none -density 300 "$SVG" -resize 32x32    "$FAVICON"

# Microsoft Square logos (Tauri ships these for the Windows .msix /
# .appx bundle path). All of them are flat re-rasters — no padding
# tweaks per size — to keep the silhouette consistent.
for size in 30 44 71 89 107 142 150 284 310; do
  convert -background none -density 300 "$SVG" -resize "${size}x${size}" \
    "$OUT_DIR/Square${size}x${size}Logo.png"
done
convert -background none -density 300 "$SVG" -resize 50x50 "$OUT_DIR/StoreLogo.png"

echo "→ Building multi-resolution icon.ico"
convert -background none -density 300 "$SVG" \
  \( -clone 0 -resize 16x16 \) \
  \( -clone 0 -resize 32x32 \) \
  \( -clone 0 -resize 48x48 \) \
  \( -clone 0 -resize 64x64 \) \
  \( -clone 0 -resize 128x128 \) \
  \( -clone 0 -resize 256x256 \) \
  -delete 0 \
  "$OUT_DIR/icon.ico"

echo "→ Building macOS icon.icns"
if command -v png2icns >/dev/null 2>&1; then
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  for size in 16 32 48 128 256 512 1024; do
    convert -background none -density 300 "$SVG" -resize "${size}x${size}" \
      "$TMP/icon_${size}.png"
  done
  png2icns "$OUT_DIR/icon.icns" \
    "$TMP/icon_16.png" "$TMP/icon_32.png" "$TMP/icon_48.png" \
    "$TMP/icon_128.png" "$TMP/icon_256.png" "$TMP/icon_512.png" \
    "$TMP/icon_1024.png"
elif command -v iconutil >/dev/null 2>&1; then
  # macOS native path. iconutil reads an .iconset directory of
  # specifically-named PNGs. See `man iconutil` for the naming
  # contract.
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  ICONSET="$TMP/clavix.iconset"
  mkdir "$ICONSET"
  declare -A SIZES=(
    ["icon_16x16.png"]=16
    ["icon_16x16@2x.png"]=32
    ["icon_32x32.png"]=32
    ["icon_32x32@2x.png"]=64
    ["icon_128x128.png"]=128
    ["icon_128x128@2x.png"]=256
    ["icon_256x256.png"]=256
    ["icon_256x256@2x.png"]=512
    ["icon_512x512.png"]=512
    ["icon_512x512@2x.png"]=1024
  )
  for name in "${!SIZES[@]}"; do
    convert -background none -density 300 "$SVG" \
      -resize "${SIZES[$name]}x${SIZES[$name]}" "$ICONSET/$name"
  done
  iconutil -c icns -o "$OUT_DIR/icon.icns" "$ICONSET"
else
  echo "  warning: neither png2icns nor iconutil found — icon.icns not regenerated."
  echo "  install one to update the macOS icon:"
  echo "    apt install libicns-utils    # Debian/Ubuntu"
  echo "    brew install libicns         # macOS"
fi

echo "✓ done."
