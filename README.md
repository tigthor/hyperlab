# hyperlab

Meta-repo for the Holepunch fork & research program: upstreamable fixes on the
forks (Track A) and new research packages layered on top (Track B). The
execution roadmap and research docs live locally and are deliberately not
committed.

## Layout

```
packages/   git submodules — forks of holepunchto/* (Track A: minimal upstreamable diffs)
labs/       new packages layered on the forks (Track B: sovereign research)
harness/    local testnet + two-peer rigs + lossy link + benchmarks
tools/      upstream-sync + pin-recording scripts
patches/    pnpm patches for deps we don't fork
```

The root `pnpm.overrides` force the **entire** transitive dependency tree onto the
local forks: when `hyperdrive` pulls in `hypercore`, pnpm resolves it to
`packages/hypercore`. One workspace, atomic cross-repo iteration.

## Quick start

```bash
git submodule update --init          # clone the forks
pnpm install                         # overrides pin the tree to the forks
pnpm test                            # harness test suite (in-process testnet)
pnpm bench                           # run benchmarks, compare against baselines
pnpm baseline                        # re-record baselines (do this after every pin bump)
pnpm sync                            # rebase all forks onto upstream main
pnpm pins                            # record current submodule commits to PINS.json
```

## Fork status

All 8 repos are forked to `tigthor/*` on GitHub. Each submodule's `origin`
points at the fork; `upstream` points at `holepunchto/*` for
`tools/sync-upstream.sh`.

## Discipline

- **One change = one topic branch = one PR.** `fix/…`, `perf/…`, `feat/…`. Never mix Track A into Track B.
- **Pin hypercore.** v11 is in flux — bump deliberately, re-run `pnpm baseline` on every bump, record with `pnpm pins`.
- **Every Track-B claim is a measured delta** against the recorded baselines, not an assertion.
- For deps we don't fork: `pnpm patch <pkg>` → edit → `pnpm patch-commit`, stored under `patches/`.
