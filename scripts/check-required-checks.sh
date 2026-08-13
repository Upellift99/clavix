#!/usr/bin/env bash
#
# Fail if a name in .github/required-checks.txt no longer matches a job that
# the workflows can actually produce.
#
# The failure this prevents: branch protection matches required checks by
# NAME. Rename a job and the old name stays required but never reports, so
# every PR sits blocked on "Expected - waiting for status" from a job that no
# longer exists. Nothing in the UI says why. Here the rename fails CI on the
# very PR that makes it, with the two names side by side.
#
# This deliberately checks the workflows, not the live protection settings:
# reading branch protection needs an admin-scoped token, and GITHUB_TOKEN
# does not have one. So it catches "job renamed, file not updated" - the
# direction that actually bites. Keeping the file and GitHub in step is the
# job of the re-apply command documented in required-checks.txt.
#
# Usage: scripts/check-required-checks.sh

set -euo pipefail

LIST=".github/required-checks.txt"
WORKFLOWS=".github/workflows"

[ -f "$LIST" ] || { echo "::error::$LIST not found."; exit 1; }

fail=0
checked=0

while IFS= read -r name; do
  # Skip blanks and comments.
  case "$name" in ''|'#'*) continue ;; esac
  checked=$((checked + 1))

  # Most jobs carry the name literally, e.g. `name: Frontend (svelte-check)`.
  if grep -rqF "name: $name" "$WORKFLOWS"; then
    continue
  fi

  # CodeQL builds its name from the matrix: `name: Analyze (${{ matrix.language }})`
  # expands to `Analyze (javascript-typescript)`. Accept that when both the
  # templated prefix and the matrix value are present.
  prefix="${name%% (*}"
  value="${name#*(}"
  value="${value%)}"
  if [ "$prefix" != "$name" ] \
     && grep -rqF "name: $prefix (\${{ matrix." "$WORKFLOWS" \
     && grep -rqF "$value" "$WORKFLOWS"; then
    continue
  fi

  echo "::error::Required check '$name' matches no job in $WORKFLOWS/."
  fail=1
done < "$LIST"

if [ "$fail" -ne 0 ]; then
  echo
  echo "A required check must name a job that still exists. If you renamed a"
  echo "job, update $LIST too, then re-apply branch protection with the"
  echo "command in that file's header - otherwise every PR will block on a"
  echo "check that can never report."
  exit 1
fi

echo "All $checked required checks match a job in $WORKFLOWS/."
