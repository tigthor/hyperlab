# hypercore-raptorq

**Research ID: HC-R1** (research invention HC-E3)

RaptorQ (RFC 6330) fountain-coded replication for hypercore — repair symbols carried as an extension message alongside the existing block/hash messages.

## Why

Hypercore's want/have replication is all-or-nothing per block: on lossy links every lost block costs a full retransmit round-trip, and pulling from many partial holders requires coordinating exactly which peer sends which block. Fountain coding removes both problems — encode each group of K blocks into RFC 6330 symbols and any K+epsilon received symbols reconstruct the group (K with >99% probability, K+2 with >99.9999%), so any mix of symbols from any mix of partial holders completes the download with near-zero coordination. The research plan (Stage 3, HC-E3) prototypes this as a new wire message carrying repair symbols next to the existing block/hash messages, benchmarked on the harness's lossy-link testbed.

## API

```js
const { attach, Encoder, Decoder, symbolEncoding, constants } = require('hypercore-raptorq')

// real today: wire codec + extension plumbing over live replication
const rq = attach(core, {
  onsymbol (message, peer) {
    // { group, esi, k, symbol } received from a peer
  }
})
rq.send({ group: 0, esi: 17, k: 16, symbol }, core.peers[0])
rq.broadcast({ group: 0, esi: 18, k: 16, symbol })
rq.destroy()

// throws 'not implemented': the actual RFC 6330 codec
const enc = new Encoder(blocks, { symbolSize: 1024 })
const sym = enc.symbol(17) // esi >= k => repair symbol
const dec = new Decoder(16)
const ready = dec.add({ esi: 17, symbol: sym })
const blocksBack = dec.decode()
```

Groups are K consecutive hypercore blocks (default K=16). Symbols with `esi < k` are systematic (raw source data); `esi >= k` are repair symbols. Decoded blocks are still verified against the signed Merkle tree, so coding adds availability without touching the trust model.

## Acceptance gate

From the plan: **beat the stock want/have protocol on bytes-to-completion over a >= 5% loss link** (harness lossy-link injector, same core, same peers) — **or this stays a research note**. Secondary: multi-holder sparse completion should approach the information-theoretic minimum (~K symbols per group regardless of which peers contribute).

## Status

Skeleton. The symbol wire codec and the extension channel are real and tested end-to-end over live hypercore replication; `Encoder.symbol`/`Decoder.decode` throw `not implemented` pending the RFC 6330 GF(256) precode + LT machinery.
