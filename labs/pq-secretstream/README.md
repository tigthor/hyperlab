# pq-secretstream

**Research ID: CRYPTO-1** (research inventions SW-E3 / DHT-E2)

Hybrid X25519 + ML-KEM-768 handshake layer wrapping `@hyperswarm/secret-stream`, with downgrade protection.

## Why

The whole Holepunch stack is classically cryptographic — every SecretStream key exchange is X25519, so a "harvest-now-decrypt-later" adversary that records traffic today can decrypt it once a cryptographically relevant quantum computer exists. NIST finalized ML-KEM (FIPS 203) on 2024-08-13, and TLS 1.3 hybrid deployments show the added handshake cost is small. The plan (research Stage 2) is a hybrid Noise handshake — X25519 ephemerals *and* an ML-KEM-768 encapsulation, both mixed into the key schedule — so the connection stays secure if either primitive holds. The >1 KB ML-KEM public key / ciphertext growth is the hard part: the DHT-relayed first handshake message may need fragmentation.

## API

```js
const { PQSecretStream, selectMode, bindModes, combineSecrets, keygen, encapsulate, decapsulate, constants } = require('pq-secretstream')

// real today
const mode = selectMode(['classical', 'hybrid'], remoteModes, { requireHybrid: true })
const digest = bindModes(['classical', 'hybrid']) // mix into the Noise handshake hash
const secret = combineSecrets(x25519Secret, mlkemSecret) // 32-byte hybrid secret

// throws 'not implemented' until a bare-pqcrypto backend lands
const { publicKey, secretKey } = keygen()
const { ciphertext, sharedSecret } = encapsulate(publicKey)
const same = decapsulate(ciphertext, secretKey)
const stream = new PQSecretStream(true, rawStream, { modes: ['hybrid'] })
```

Downgrade protection is two-sided: `selectMode({ requireHybrid })` makes a classical-only intersection a hard failure, and `bindModes` produces a digest of the *offered* mode list that must be mixed into the handshake transcript, so an attacker stripping the hybrid offer breaks the handshake instead of silently downgrading it.

## Acceptance gate

- **< 1 ms added handshake latency** vs stock secret-stream on the two-peer harness testnet (achievable per TLS 1.3 hybrid measurements).
- The ML-KEM-768 key (1184 B) and ciphertext (1088 B) must survive the DHT-relayed first message — fragmentation handled, holepunch success rate unchanged.
- A hybrid-capable peer pair must never silently negotiate classical (verified by transcript binding test).

## Status

Skeleton. Negotiation, transcript binding and the secret combiner are real and tested; KEM ops and the wire layer throw `not implemented` pending bare-pqcrypto (BARE-1).
