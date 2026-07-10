# pq-secretstream

**Research ID: CRYPTO-1** (research inventions SW-E3 / DHT-E2)

Hybrid X25519 + ML-KEM-768 handshake layer wrapping `@hyperswarm/secret-stream`, with downgrade protection.

## Why

The whole Holepunch stack is classically cryptographic — every SecretStream key exchange is X25519, so a "harvest-now-decrypt-later" adversary that records traffic today can decrypt it once a cryptographically relevant quantum computer exists. NIST finalized ML-KEM (FIPS 203) on 2024-08-13, and TLS 1.3 hybrid deployments show the added handshake cost is small. The plan (research Stage 2) is a hybrid Noise handshake — X25519 ephemerals *and* an ML-KEM-768 encapsulation, both mixed into the key schedule — so the connection stays secure if either primitive holds. The >1 KB ML-KEM public key / ciphertext growth is the hard part: the DHT-relayed first handshake message may need fragmentation.

## API

```js
const { selectMode, bindModes, combineSecrets, keygen, encapsulate, decapsulate, initiate, respond, finalize, PQSecretStream } = require('pq-secretstream')

// negotiation + transcript binding (real)
const mode = selectMode(['classical', 'hybrid'], remoteModes, { requireHybrid: true })
const digest = bindModes(['classical', 'hybrid']) // mixed into the derived session key
const secret = combineSecrets(x25519Secret, mlkemSecret) // 32-byte hybrid secret

// real ML-KEM-768, delegated to @noble/post-quantum (FIPS 203)
const { publicKey, secretKey } = keygen()
const { ciphertext, sharedSecret } = encapsulate(publicKey)
const same = decapsulate(ciphertext, secretKey) // === sharedSecret

// real hybrid KEM key agreement (X25519 + ML-KEM-768), two messages:
const { state, offer } = initiate({ modes: ['classical', 'hybrid'], requireHybrid: true })
const r = respond(offer, { modes: ['classical', 'hybrid'], requireHybrid: true })
const i = finalize(state, r.message) // i.sessionKey === r.sessionKey

// still throws — the full Noise wire + first-message fragmentation is not built
const stream = new PQSecretStream(true, rawStream, { modes: ['hybrid'] })
```

Downgrade protection is two-sided: `selectMode({ requireHybrid })` makes a classical-only intersection a hard failure, and `bindModes` produces a digest of the *offered* mode list that must be mixed into the handshake transcript, so an attacker stripping the hybrid offer breaks the handshake instead of silently downgrading it.

## Acceptance gate

- **< 1 ms added handshake latency** vs stock secret-stream on the two-peer harness testnet (achievable per TLS 1.3 hybrid measurements).
- The ML-KEM-768 key (1184 B) and ciphertext (1088 B) must survive the DHT-relayed first message — fragmentation handled, holepunch success rate unchanged.
- A hybrid-capable peer pair must never silently negotiate classical (verified by transcript binding test).

## Status

Real: ML-KEM-768 keygen/encapsulate/decapsulate (noble FIPS 203), the X25519 half, mode negotiation, transcript binding, the secret combiner, and a real two-message **hybrid KEM key agreement** (`initiate`/`respond`/`finalize`) where both sides derive a byte-identical session key from `combineSecrets(X25519_dh, MLKEM_ss)` with both peers' offered-mode digests mixed in — so a stripped-hybrid transcript yields a *different* key (downgrade detection is cryptographic, not cosmetic). Tested in `test/basic.test.js` (13 tests): honest-run key agreement, both downgrade halves, and tampered-X25519 / wrong-ML-KEM-ciphertext divergence.

Still stub: the full Noise wire integration + first-message fragmentation (`PQSecretStream` throws `not implemented`).

### Gate (measured, `harness/bench/pq-handshake.js`)

Claim: hybrid first message >1 KB (needs fragmentation) **and** adds <1 ms CPU vs classical. Baseline `firstMessageBytes=116`, latency ~2.2 ms.

- First-message key material grows to **1216 B** (X25519 pk 32 + ML-KEM pk 1184), response **1120 B** (32 + ct 1088) — both past a single UDP datagram. **Fragmentation cost is real: PASS.**
- Added CPU (median, this machine, pure-JS noble): **~1.37 ms** over the full classical two-party handshake, dominated by the ML-KEM keygen+encapsulate+decapsulate triple (~1.34 ms). This is **above** the <1 ms claim. The book's <1 ms figure is for optimized/native (TLS 1.3) ML-KEM; Chapter 7's native constant-time addon is exactly what would bring this under 1 ms. **On pure-JS: FAIL the <1 ms half.**
