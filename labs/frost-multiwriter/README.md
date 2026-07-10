# frost-multiwriter

**Research ID: FROST-1**

FROST threshold multi-writer for *fixed* writer sets — t-of-n writers (e.g. a 3-of-5 org core) cooperatively produce one standard Ed25519 signature per root, giving a single canonical signed core instead of Autobase's linearized DAG.

## Why

Hypercore is single-writer by construction: one keypair signs the Merkle root. Autobase bolts multi-writer on top by linearizing a causal DAG of per-writer cores — an eventually-consistent layer with real reorg cost when checkpoints move. The research plan (Stage 3) proposes FROST threshold signatures as a principled alternative for the common case where the writer set is *fixed and known*: keygen shards one Ed25519 secret across n writers so any t of them can jointly sign an append. The output is a bit-for-bit standard Ed25519 signature over one canonical log — readers and the entire replication path need zero changes, there is no DAG and nothing to reorg. The plan's escalation trigger: if Autobase reorg cost dominates Keet CPU profiles at scale, this track accelerates.

## API

```js
const frost = require('frost-multiwriter')

// real today
frost.validateConfig(3, 5)
const ok = frost.verify(signature, message, groupPublicKey) // plain ed25519 verify — the point of FROST

// throws 'not implemented'
const { publicKey, shares } = frost.dealerKeygen(3, 5)
const session = new frost.SignSession({ id: 1, secretShare: shares[0].secretShare, publicKey, threshold: 3, signers: 5 })
const commitment = session.commit() // round 1
const share = session.sign(message, commitments) // round 2
const signature = frost.aggregate(message, commitments, shares, publicKey)
const core = frost.createCore(storage, { publicKey, session, transport })
```

Signing is a two-round protocol (commit, then sign) among any t online writers; `createCore` plugs the aggregate signer into hypercore's manifest/signer abstraction. Blocker noted in-source: `sodium-universal` exposes ed25519 scalar add/sub/invert but no scalar multiplication, so Shamir evaluation needs a small scalar-arithmetic helper (or a sodium patch).

## Acceptance gate

- Signatures produced by t-of-n signing must verify as **standard Ed25519** on a stock hypercore replica (no fork of the read/replication path).
- End-to-end append latency with 3-of-5 signers on the harness testnet must stay within interactive bounds (target: < 2 RTT + single-signer baseline, since FROST adds exactly two rounds).
- Safety: fewer than t shares must never produce a valid signature; nonce reuse across sessions must be structurally impossible (fresh commit per message).

## Status

Skeleton. Config validation and group-signature verification are real and tested; keygen, both signing rounds, aggregation and the hypercore signer hook throw `not implemented`.
