# frost-multiwriter

**Research ID: FROST-1**

Real t-of-n threshold Schnorr multi-writer for *fixed* writer sets — any t of n writers (e.g. a 2-of-3 or 3-of-5 org core) cooperatively produce **one canonical group signature** per root, giving a single signed object instead of Autobase's linearized DAG. No per-writer cores, no reorg.

## Why

Hypercore is single-writer by construction: one keypair signs the Merkle root. Autobase bolts multi-writer on top by linearizing a causal DAG of per-writer cores — an eventually-consistent layer with real reorg cost when checkpoints move. The research plan (Stage 3) proposes FROST threshold signatures as a principled alternative for the common case where the writer set is *fixed and known*: keygen shards one group secret across n writers so any t of them can jointly sign an append, and the whole group commit is ONE signature verifiable against ONE public key. There is no DAG and nothing to reorg.

## What is real (implemented + tested)

FROST (RFC 9591) over the **ristretto255** prime-order group, via `@noble/curves` `ristretto255_FROST`:

- `dealerKeygen(t, n)` — trusted-dealer VSS: one group public key + n secret shares (any t reconstruct a signing quorum). Each share is `vss_verify`-checked.
- `SignSession` two-round signing — `commit()` (round 1, one-time nonce pair + public commitments) then `sign(message, commitments)` (round 2, this signer's response share). Below-quorum signing fails closed.
- `aggregate(message, commitments, shares, group)` — combines >= t shares into ONE 64-byte ristretto255 Schnorr signature; verifies each share and fails closed (identifying cheaters) on a forged share.
- `verify(sig, message, groupPublicKey)` — plain ristretto255 Schnorr verify against the single 32-byte group key.

Demonstrated by tests: a real 2-of-3 where every pair of writers independently produces a group signature that verifies against the single group key; one writer alone cannot; a fabricated co-signer is caught at aggregation; wrong-message / tampered-signature / wrong-key all reject.

```js
const frost = require('frost-multiwriter')

const dealt = frost.dealerKeygen(2, 3)              // group key + 3 shares
const a = new frost.SignSession({ id: 1, secret: dealt.shares[0].secret, group: dealt.group, threshold: 2, signers: 3 })
const b = new frost.SignSession({ id: 2, secret: dealt.shares[1].secret, group: dealt.group, threshold: 2, signers: 3 })

const commitments = [a.commit(), b.commit()]        // round 1
const shares = [a.sign(root, commitments), b.sign(root, commitments)] // round 2
const sig = frost.aggregate(root, commitments, shares, dealt.group)   // ONE signature
frost.verify(sig, root, dealt.publicKey)            // => true
```

## Honest gaps (still stubbed)

- **Not Ed25519-byte-compatible.** A ristretto255 Schnorr signature is NOT an RFC 8032 Ed25519 signature. It does **not** drop into hypercore's stock ed25519 verifier. Making a hypercore-compatible group core requires the **FROST-Ed25519** ciphersuite (RFC 9591 Ed25519 suite, SHA-512, cofactored group) so the aggregate is a valid RFC 8032 signature — that is the follow-up track.
- **`createCore(storage, opts)` throws** `not implemented: FROST-Ed25519 needed for hypercore-compatible (RFC 8032) signatures`. Wiring the aggregate signer into hypercore's manifest/signer abstraction (with an async two-round transport) is unbuilt.

## Acceptance gate

- t-of-n signing produces ONE canonical group signature verifiable against ONE group public key — **met** (ristretto255).
- Fewer than t shares must never produce a valid signature — **met** (below-quorum signing throws; forged shares caught at aggregation).
- Signatures verify as standard Ed25519 on a stock hypercore replica — **NOT met** (needs FROST-Ed25519; see gaps).

## Status

Real ristretto255 threshold Schnorr: keygen, both signing rounds, aggregation and verification are implemented and tested (8 tests, 36 asserts, `npx brittle test/*.test.js`). Ed25519-format output and the live hypercore signer hook remain stubs.
