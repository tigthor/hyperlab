#!/usr/bin/env bash
# Record the exact commit each submodule is pinned to (plus its upstream describe).
# Run after every deliberate bump; PINS.json is the known-good manifest the
# baselines were measured against.
set -euo pipefail

cd "$(dirname "$0")/.."

{
  echo "{"
  echo "  \"recorded\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
  echo "  \"pins\": {"
  first=1
  for d in packages/*/; do
    name=$(basename "$d")
    sha=$(git -C "$d" rev-parse HEAD)
    # describe relies on locally-fetched tags, which lag behind the pinned
    # commit - record the package.json version too, it is the ground truth
    # for which upstream release the pin corresponds to.
    desc=$(git -C "$d" describe --tags --always 2>/dev/null || echo "$sha")
    version=$(node -p "try { require('./$d/package.json').version || 'unversioned' } catch { 'unversioned' }")
    [ $first -eq 0 ] && echo ","
    first=0
    printf '    "%s": { "commit": "%s", "version": "%s", "describe": "%s" }' "$name" "$sha" "$version" "$desc"
  done
  echo ""
  echo "  }"
  echo "}"
} > PINS.json

echo "Wrote PINS.json:"
cat PINS.json
