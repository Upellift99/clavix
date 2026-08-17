#!/usr/bin/env bash
#
# Watch for newly-yanked crates.
#
# `cargo audit --deny yanked` is not usable here: a yanked crate carries no
# RUSTSEC id, so it cannot be listed in audit.toml's `ignore`. Adding the flag
# would pin the Rust job red forever on the one yanked crate we already know
# about, and a permanently-red gate is a gate nobody reads.
#
# So instead of denying the category, we pin the exact set. Any yanked crate
# that is not in BASELINE below fails the build; the known one does not.
#
# When this fails, either the new crate is genuinely a problem (bump whatever
# pulls it) or it is another one we must live with (add it here, with the
# reason). Do not silence it by emptying the check.
#
# Usage: scripts/check-yanked-crates.sh [path/to/Cargo.lock]

set -euo pipefail

LOCKFILE="${1:-src-tauri/Cargo.lock}"

# name<TAB>version, one per line, sorted. Keep the reason next to each entry.
#
# Empty on purpose, and that is the good outcome: the tree currently has no
# yanked crate at all. The single entry that used to live here was spin 0.9.8,
# reached through lazy_static 1.5.0's `spin_no_std` feature (num-bigint-dig,
# x509-parser and zxcvbn all pull it in) and written off as not ours to move.
# The 2026-08-17 lockfile refresh moved spin to 0.9.9, which upstream has not
# yanked, so the entry was removed per the instructions below rather than left
# to rot — a baseline listing a crate that is no longer yanked would quietly
# tolerate that exact name/version reappearing.
#
# An empty baseline makes this check equivalent to `cargo audit --deny yanked`
# while still reporting *which* crate appeared, so there is no reason to add
# that flag to the audit step.
read -r -d '' BASELINE <<'EOF' || true
EOF

# cargo audit's exit code is the *other* gate's business - it is non-zero
# whenever any advisory is outstanding, and it also depends on whether
# .cargo/audit.toml is on the path from the current directory. We only want
# the yanked list out of the JSON, so take the report and ignore the status.
report="$(cargo audit --file "$LOCKFILE" --json 2>/dev/null || true)"

if [ -z "$report" ]; then
  echo "::error::cargo audit produced no report for $LOCKFILE (is cargo-audit installed?)."
  exit 1
fi

actual="$(printf '%s' "$report" \
  | jq -r '(.warnings.yanked // [])[] | "\(.package.name)\t\(.package.version)"' \
  | sort)"

expected="$(printf '%s\n' "$BASELINE" | sed '/^$/d' | sort)"

if [ "$actual" = "$expected" ]; then
  count="$(printf '%s\n' "$expected" | sed '/^$/d' | wc -l)"
  echo "Yanked crates match the baseline ($count known)."
  exit 0
fi

echo "::error::The set of yanked crates changed."
echo
echo "--- expected (baseline in $0) ---"
printf '%s\n' "$expected"
echo "--- actual (from $LOCKFILE) ---"
printf '%s\n' "$actual"
echo
echo "New entries mean a dependency was yanked upstream: bump whatever pulls"
echo "it, or add it to BASELINE with the reason. Entries that disappeared are"
echo "good news - remove them from BASELINE to keep the check meaningful."
exit 1
