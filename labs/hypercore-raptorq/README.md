# hypercore-raptorq

**Research ID: HC-R1** (research invention HC-E3)

Systematic **GF(256) random-linear fountain coding** for hypercore — repair symbols carried as an extension message alongside the existing block/hash messages.

## Honesty: what this is (and is not)

This is **not** literal RFC 6330 RaptorQ. It is a **systematic random linear network code (RLNC-style fountain)** over GF(256), which delivers the one property Chapter 10 actually needs — *any k linearly-independent symbols reconstruct the group* — without the XL cost of a full RaptorQ LDPC+HDPC precode and LT peeling layer. Concretely:

- **Systematic**: symbols with `esi < k` are the source blocks **verbatim**, so a no-loss transfer decodes for free (passthrough, no matrix solve).
- **Repair**: symbols with `esi >= k` are random linear combinations of all k blocks over GF(256). Their coefficient vector is derived deterministically from `esi` (a PRNG seed), so **no coefficient bytes travel on the wire**.
- **Decode**: online Gauss-Jordan elimination over GF(256). Once k independent symbols are in, reconstruction is an O(k) read-out of the reduced row-echelon matrix.

What it is **not**, versus RFC 6330: decode is **O(k² · symbolSize)** (dense Gaussian elimination), not near-linear; there is **no sparse LDPC/HDPC precode** and **no LT belief-propagation peeling**; and the overhead is the random-matrix full-rank overhead (~a few extra symbols), not RaptorQ's standardized *k+2 with prob >99.9999%* bound. For k≈64 the extra symbols are small and the decode cost is negligible next to the network, which is what the gate measures.

## Why

Hypercore's want/have replication is all-or-nothing per block: on lossy links every lost block costs a retransmit, and pulling from many partial holders requires coordinating which peer sends which block. Fountain coding removes both problems — any k-ish symbols from any mix of holders complete the group, and loss is absorbed by sending more repair symbols instead of retransmitting specific ones.

## API

```js
const { attach, Encoder, Decoder, encodeSymbol, decodeSymbol, gf } = require('hypercore-raptorq')

// --- codec (real) ---
const enc = new Encoder(blocks, { symbolSize: 4096 }) // k = blocks.length
enc.symbol(0)                 // systematic: === blocks[0] verbatim
enc.symbol(enc.k)             // repair: random linear combination over GF(256)
enc.systematicSymbols()       // the k systematic wire messages
enc.repairSymbols(20)         // 20 repair wire messages

const dec = new Decoder(enc.k, { symbolSize: 4096 })
for (const m of stream) if (dec.add(m)) break  // true once rank === k
const blocksBack = dec.decode()                // Buffer[] of the k source blocks

// --- extension plumbing (real) over live hypercore replication ---
const rq = attach(core, { onsymbol (message, peer) { /* { group, esi, k, symbol } */ } })
rq.send({ group: 0, esi: 17, k: 64, symbol }, core.peers[0])
rq.broadcast(enc.message(64))
rq.destroy()
```

`gf` exposes the GF(256) primitives (`mul`, `inv`, `div`) if you want to test the field directly.

Groups are k consecutive hypercore blocks. Decoded blocks are still verified against the signed Merkle tree, so coding adds availability without touching the trust model.

## Acceptance gate — PASSED

> **beat the stock want/have protocol on bytes-to-completion over a ≥5% loss link**, or this stays a research note.

Benchmark: `harness/bench/raptorq-gate.js`. It runs the **want/have** side over the recorded baseline path (real hypercore + UDX over the lossy rig, retransmissions included, matching `baselines.full.json` `replicate-lossy`) and the **coded** side by streaming real symbols through the same `lossy-link.js` UDP injector into the real GF(256) decoder. Bytes-to-completion, k=64 blocks × 4096 B:

| loss | want/have bytes | coded bytes | coded saving |
|-----:|----------------:|------------:|-------------:|
| 0%   | ~277k           | ~266k       | ~4% (no worse) |
| 5%   | ~382k–570k*     | ~275k       | ~28–52% |
| 10%  | ~339k–396k*     | ~295k       | ~13–25% |
| 20%  | ~377k–446k*     | ~336k       | ~10–25% |

*want/have varies run-to-run with real UDX retransmission timing; coded is deterministic (seeded link). Coded wins at every loss rate on repeated runs.* **PASSES = true.**

Run it: `node harness/bench/raptorq-gate.js` (flags: `--k=`, `--block=`, `--latency=`, `--jitter=`).

## Status

**Working codec + passing gate.** GF(256) arithmetic, systematic + repair encoding, and online Gaussian-elimination decode are real and tested (`test/gf.test.js`, `test/codec.test.js`: field laws, systematic passthrough, decode from exactly k independent symbols, decode under ~15% random loss). The extension channel is real and tested over live hypercore replication (`test/basic.test.js`). Remaining stub relative to the book: this is RLNC-style, not RFC 6330 RaptorQ (see Honesty above), and it is not yet wired into hypercore's live replication as an adaptive Protomux channel — the gate measures the codec over the lossy link, not an in-core coded replication mode.
