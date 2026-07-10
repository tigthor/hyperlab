#!/usr/bin/env bash
# Weekly upstream sync: rebase each fork's current branch onto upstream/main.
# Track-A discipline: topic branches stay surgically small so these rebases stay trivial.
#
# Usage: tools/sync-upstream.sh [package ...]   (default: all submodules under packages/)
set -euo pipefail

cd "$(dirname "$0")/.."

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=(packages/*/)
else
  targets=("${targets[@]/#/packages/}")
fi

failed=()
for d in "${targets[@]}"; do
  name=$(basename "$d")
  echo "==> $name"
  if ! git -C "$d" remote get-url upstream >/dev/null 2>&1; then
    echo "    no upstream remote, skipping"
    continue
  fi
  git -C "$d" fetch upstream --quiet
  default=$(git -C "$d" remote show upstream | sed -n 's/.*HEAD branch: //p')
  if git -C "$d" rebase "upstream/${default:-main}"; then
    echo "    rebased onto upstream/${default:-main}"
  else
    # If the rebase failed to START (e.g. dirty worktree) there is no rebase
    # in progress and --abort exits 128 - don't let set -e kill the loop.
    git -C "$d" rebase --abort >/dev/null 2>&1 || true
    failed+=("$name")
    echo "    CONFLICT - rebase aborted, resolve manually"
  fi
done

if [ ${#failed[@]} -gt 0 ]; then
  echo ""
  echo "Conflicts in: ${failed[*]}"
  exit 1
fi
echo ""
echo "All forks synced. Re-run baselines if hypercore moved: pnpm baseline"
