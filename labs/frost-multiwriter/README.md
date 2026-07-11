# frost-multiwriter

**Research ID: FROST-1**

Real t-of-n threshold Schnorr multi-writer for *fixed* writer sets — any t of n
writers (e.g. a 2-of-3 or 3-of-5 org core) cooperatively produce **one
canonical group signature** per root, giving a single signed object instead of
Autobase's linearized DAG. No per-writer cores, no reorg.

## Why

Hypercore is single-writer by construction: one keypair signs the Merkle root.
Autobase bolts multi-writer on top by linearizing a causal DAG of per-writer
cores — an eventually-consistent layer with real reorg cost when checkpoints
move. The research plan (Stage 3) proposes FROST threshold signatures as a
principled alternative for the common case where the writer set is *fixed and
known*: keygen shards one group secret across n writers so any t of them can
jointly sign an append, and the whole group commit is ONE signature verifiable
against ONE public key. There is no DAG and nothing to reorg.

## What is real (implemented + tested)

FROST (RFC 9591) via `@noble/curves`, in **two ciphersuites** sharing one API
(`dealerKeygen`, `SignSession` two-round signing, `aggregate`, `verify`,
`thresholdSign`):

- **ristretto255** — FROST(ristretto255, SHA-512), the top-level exports.
- **ed25519** — FROST(Ed25519, SHA-512), exported as `ed25519`. The aggregate
  is a **standard RFC 8032 Ed25519 signature**: `test/ed25519.test.js` proves
  sodium's `crypto_sign_verify_detached` (hypercore's stock verifier) accepts
  it directly.

And the piece that used to be the honest gap, now real — **`createCore()`**:

```js
const frost = require('frost-multiwriter')

const dealt = frost.ed25519.dealerKeygen(2, 3)          // group key + 3 shares
const g = await frost.createCore(storage, dealt.publicKey)

// any 2 of the 3 writers sign this append (two FROST rounds + aggregate):
await g.append(block, [session1, session3])

// a COMPLETELY STOCK hypercore replicates and verifies it — no FROST anywhere:
const replica = new Hypercore(storage2, { manifest: g.manifest })
```

The core's manifest pins one ed25519 signer — the group public key — with
quorum 1. `append(blocks, sessions)` computes the exact tree signable
hypercore verifies (tree hash + length + fork bound to the manifest hash),
runs commit/sign across the given sessions, aggregates to one 64-byte
signature and wraps it in the standard v1 signature envelope. Demonstrated
end-to-end in `test/ed25519.test.js`: a live 2-of-3 core where three appends
are each signed by a *different* writer pair, then replicated into a stock
`Hypercore` that verifies every block; below-quorum signing fails closed,
forged shares are caught at aggregation (cheater identified), and a
non-quorum signature cannot append.

## Acceptance gate

- t-of-n signing produces ONE canonical group signature verifiable against ONE
  group public key — **met** (both suites).
- Fewer than t shares must never produce a valid signature — **met**
  (below-quorum throws; forged shares caught at aggregation).
- Signatures verify as standard Ed25519 on a stock hypercore replica —
  **met** (FROST-Ed25519 aggregate + live replication test).

## Honest limits that remain

- **Trusted-dealer keygen.** `dealerKeygen` is RFC 9591 Appendix C VSS — one
  dealer momentarily knows the group secret. noble ships the DKG rounds
  (`dkg.round1/2/3`); wiring them in removes the dealer and is mechanical, but
  is not done here.
- **In-process rounds.** The two signing rounds are message-shaped (plain
  buffers) but no network transport is provided; a deployment brings its own
  broadcast channel for commit/share messages.
- **Serial appends.** The signable commits to the current tree length, so a
  group must not race concurrent appends (that is inherent to the model — the
  group IS one writer).

## Status

23 tests / 2521 asserts (`npx brittle test/*.test.js`): ristretto255 suite,
fuzz + property tests, RFC 8032 compatibility, and the live 2-of-3 threshold
hypercore with stock-replica verification.
