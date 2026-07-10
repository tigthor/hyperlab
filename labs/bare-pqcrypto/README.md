# bare-pqcrypto

**Research ID: BARE-1** (research invention BARE-E7)

ML-KEM (FIPS 203) and ML-DSA (FIPS 204) primitives packaged for Bare and Node — WASM/liboqs backend first for iteration speed, a constant-time native Bare addon later.

## Why

Every post-quantum plan in the fork program (hybrid handshake in pq-secretstream/CRYPTO-1, hybrid log signatures in hypercore) bottoms out on the same missing piece: there is no ML-KEM/ML-DSA implementation available inside the Bare runtime. The research plan (Stage 2, invention Bare-#7) calls for an ahead-of-time PQ-crypto module — start with a WASM/liboqs binding behind Bare as a native addon so the protocol layers can iterate immediately, then replace it with a constant-time native implementation (kokocrypt-style hybrid) once the wire formats settle. NIST finalized FIPS 203/204 on 2024-08-13, so the parameter sets are frozen and safe to build against.

## API

```js
const { detect, mlkem, mldsa, constants } = require('bare-pqcrypto')

// real today
detect() // { wasm, native, bare, backend } — backend is null until an impl lands
constants['ML-KEM-768'] // { publicKeyBytes: 1184, secretKeyBytes: 2400, ciphertextBytes: 1088, sharedSecretBytes: 32 }
constants['ML-DSA-65'] // { publicKeyBytes: 1952, secretKeyBytes: 4032, signatureBytes: 3309 }

// throws 'not implemented' until the WASM backend lands
const { publicKey, secretKey } = mlkem.keygen('ML-KEM-768')
const { ciphertext, sharedSecret } = mlkem.encapsulate(publicKey)
const ss = mlkem.decapsulate(ciphertext, secretKey)

const kp = mldsa.keygen('ML-DSA-65')
const sig = mldsa.sign(message, kp.secretKey)
const ok = mldsa.verify(sig, message, kp.publicKey)
```

Note: the research brief quotes 3,293 bytes for the level-3 signature; that is the round-3 Dilithium3 figure. Final FIPS 204 ML-DSA-65 signatures are 3,309 bytes — still ~50x a 64-byte Ed25519 signature.

## Acceptance gate

- Consumers must hit their gates through this module: pq-secretstream's **< 1 ms added handshake latency**, and for the hypercore hybrid signer, **<= 15% append-throughput drop — otherwise adopt batched-append amortization** (ML-DSA-65 signing has ~50% CoV latency from FIPS 204 rejection sampling).
- The eventual native addon must be constant-time (no secret-dependent branches/table lookups) and pass the NIST ACVP known-answer tests for FIPS 203/204.
- Must load in both Node and Bare (feature-detected via `detect()`), with WASM fallback where no native addon is built.

## Status

Skeleton. Parameter tables and feature detection are real and tested; all primitive operations throw `not implemented` pending the liboqs WASM binding.
