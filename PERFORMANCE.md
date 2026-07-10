# Performance

Measured on node v23.7.0, macOS arm64, single-threaded. Every "improvement" is a
delta against a recorded baseline (`harness/bench/baselines.full.json`) and was
re-attacked by an adversarial agent before it counted. PQ primitives are pure-JS
`@noble/post-quantum` / `@noble/curves` (audited, standardized, **not** constant-time —
a native Bare addon is the production path). Reproduce with the `harness/bench/*` gates
and per-package micro-benchmarks.

## The three book decision gates

| Gate (book ch.) | Claim | Measured | Verdict |
|---|---|---|---|
| HC-C1 · Ch.4 | hybrid PQ signing drops append tput >15% ⇒ batch first | per-append **−99.9%**, batched(64) −91.8%, **80×** batch recovery, crossover batch **827** | **fired & passes** |
| CRYPTO-1 · Ch.5 | hybrid first message >1KB (needs fragmentation), <1ms added CPU | first msg **1,216 B** (was 116) ✓ fragmentation; added CPU **1.38 ms** (pure-JS) ✗ <1ms | size half **passes**, CPU half honestly fails in JS |
| HC-R1 · Ch.10 | coded replication beats want/have bytes-to-completion at ≥5% loss | at 20 ms RTT: **−23.3%** @5%, **−28.9%** @10%, **−11.4%** @20% loss | **passes** under real RTT |

## Primitive throughput (ops/sec, p50 / p95 ms)

| Primitive | ops/sec | p50 ms | p95 ms |
|---|--:|--:|--:|
| receipt sign | 45,417 | 0.020 | 0.028 |
| receipt verify | 24,169 | 0.040 | 0.044 |
| ml-kem-768 keygen | 2,787 | 0.354 | 0.419 |
| ml-kem-768 encapsulate | 2,245 | 0.438 | 0.522 |
| ml-kem-768 decapsulate | 1,700 | 0.576 | 0.683 |
| frost verify | 480 | 2.051 | 2.354 |
| ml-dsa-65 keygen | 427 | 2.313 | 2.506 |
| hybrid verify (ed25519+ml-dsa) | 347 | 2.881 | 3.018 |
| ml-dsa-65 verify | 343 | 2.902 | 3.159 |
| cpace ristretto255 exchange+confirm | 138 | 7.215 | 7.570 |
| frost 2-of-3 threshold sign | 64 | 15.353 | 16.746 |
| ml-dsa-65 sign | 57 | 12.931 | **41.674** |
| hybrid sign | 54 | 15.848 | **37.469** |

The heavy p95 on ML-DSA sign is FIPS-204 rejection sampling — the variable-latency tail
the book warns about, and the reason batched-append amortization is mandatory.

## Baselines (context)

- Ed25519 append: 9,691/s single · 128,732/s batched(64).
- Classical X25519 handshake: 2.23 ms median, 761 B setup, 116 B first message.
- Sparse replicate: 332 B/block overhead clean · 1,233 B/block at 5% loss.

## Invention status after adversarial review

**real+proven** (implemented, tested, gate met, survived attack): bare-pqcrypto,
hybrid ed25519+ml-dsa-65 signer, retrieval-market receipts, hypercore-raptorq fountain codec.
**real+partial** (real crypto, honest remaining gap): pq-secretstream (KEM agreement real;
first-message fragmentation + native <1ms pending), hyperbeam-pake CPace (module-layer
proof done; live DHT `createPakeBeam` stubbed), frost-multiwriter (real ristretto threshold
Schnorr; ed25519/hypercore-format hook stubbed).
