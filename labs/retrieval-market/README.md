# retrieval-market

**Research ID: INC-1** (research inventions HC-E7 / DHT-E5 / SW-E6)

Signed bandwidth/storage micro-receipts, aggregated off-chain and settled on an EVM L2 — the incentive layer that fixes the uncompensated-relay free-rider problem.

## Why

The stack has no economics: seeding is charity, and relay bandwidth is uncompensated — which is exactly why symmetric-NAT users stay stranded (HyperDHT does no relaying by default, and nobody volunteers to relay strangers' traffic). The research proposes signed micro-receipts for uploaded blocks and relayed bytes (HC-E7's on-log incentive layer, DHT-E5's incentivized relay market, SW-E6's verifiable bandwidth accounting), staged deliberately last and prototyped **off-chain first**: receipts are cheap ed25519 signatures exchanged inline, aggregation is state-channel style so only the latest cumulative receipt per channel matters, and periodic settlement lands on an EVM L2.

## API

```js
const rm = require('retrieval-market')

// ALL REAL today — the complete off-chain receipt layer
const consumer = rm.keyPair()
const receipt = rm.createReceipt({
  provider, // 32-byte pk of who served the bytes
  consumer: consumer.publicKey, // 32-byte pk of who acknowledges them
  channel, // 32-byte context: core discovery key / relay session id
  bytes: 65536, // CUMULATIVE bytes served on this channel
  sequence: 3 // monotonic; highest sequence wins at settlement
})
const signed = rm.signReceipt(receipt, consumer.secretKey)
rm.verifyReceipt(signed) // true

const buf = rm.encodeReceipt(signed) // compact-encoding, ~177 bytes
const back = rm.decodeReceipt(buf)

const { claims, totalBytes, invalid } = rm.aggregate(signedReceipts)

// throws 'not implemented'
await rm.settle({ claims }, { rpcUrl, contract })
```

The consumer signs cumulative totals, so the provider only ever needs to keep one receipt per channel, receipt loss is harmless, and a cheating consumer's best move is refusing to sign the *next* receipt — at which point the provider stops serving (cryptographic tit-for-tat).

## Acceptance gate

- **Prototype off-chain first, settle on an EVM L2 last** (research Stage 4 ordering).
- Receipt overhead must be negligible: one signature per accounting window, wire cost < 0.1% of the bandwidth being accounted (a ~177-byte receipt per 64 KiB window is ~0.27% — so windows of >= 256 KiB, or piggyback on existing frames).
- Aggregation must keep settlement O(channels): only the highest-sequence cumulative receipt per (provider, consumer, channel) is claimable — enforced by `aggregate` and eventually by the contract.

## Status

Working off-chain prototype: receipt create/sign/verify/encode/decode/aggregate are real and tested; `settle` throws `not implemented` pending the L2 payout contract.
