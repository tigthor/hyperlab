// bare-pqcrypto — ML-KEM (FIPS 203) and ML-DSA (FIPS 204) for Bare and Node.
// (BARE-1, research BARE-E7)
//
// Backend: @noble/post-quantum — a pure-JS implementation of the final
// FIPS 203/204 standards (ml_kem512/768/1024, ml_dsa44/65/87). Real,
// standardized primitives are available in-runtime today. A constant-time
// native Bare addon may replace this later; the API surface is stable.

const b4a = require('b4a')
const sodium = require('sodium-universal')
const { ml_kem512, ml_kem768, ml_kem1024 } = require('@noble/post-quantum/ml-kem.js')
const { ml_dsa44, ml_dsa65, ml_dsa87 } = require('@noble/post-quantum/ml-dsa.js')

// Bind each parameter set to its noble implementation.
const KEM_IMPL = {
  'ML-KEM-512': ml_kem512,
  'ML-KEM-768': ml_kem768,
  'ML-KEM-1024': ml_kem1024
}

const DSA_IMPL = {
  'ML-DSA-44': ml_dsa44,
  'ML-DSA-65': ml_dsa65,
  'ML-DSA-87': ml_dsa87
}

const BACKEND = 'noble-js'

// FIPS 203 (final, 2024-08-13) — ML-KEM parameter sizes in bytes
const MLKEM = {
  'ML-KEM-512': { publicKeyBytes: 800, secretKeyBytes: 1632, ciphertextBytes: 768, sharedSecretBytes: 32 },
  'ML-KEM-768': { publicKeyBytes: 1184, secretKeyBytes: 2400, ciphertextBytes: 1088, sharedSecretBytes: 32 },
  'ML-KEM-1024': { publicKeyBytes: 1568, secretKeyBytes: 3168, ciphertextBytes: 1568, sharedSecretBytes: 32 }
}

// FIPS 204 (final, 2024-08-13) — ML-DSA parameter sizes in bytes.
// Note: the research brief quotes 3,293 bytes for the level-3 signature —
// that is the round-3 Dilithium3 figure; final FIPS 204 ML-DSA-65 is 3,309.
const MLDSA = {
  'ML-DSA-44': { publicKeyBytes: 1312, secretKeyBytes: 2560, signatureBytes: 2420 },
  'ML-DSA-65': { publicKeyBytes: 1952, secretKeyBytes: 4032, signatureBytes: 3309 },
  'ML-DSA-87': { publicKeyBytes: 2592, secretKeyBytes: 4896, signatureBytes: 4627 }
}

const DEFAULT_KEM = 'ML-KEM-768'
const DEFAULT_DSA = 'ML-DSA-65'

/**
 * Detect which backends are loadable in the current runtime.
 * `backend` is 'noble-js' whenever the pure-JS FIPS 203/204 implementation
 * is present (always, since it is a hard dependency). A native/WASM addon
 * can override `native`/`backend` in the future.
 *
 * @returns {{ wasm: boolean, native: boolean, bare: boolean, backend: string }}
 */
function detect () {
  return {
    wasm: typeof WebAssembly !== 'undefined',
    native: hasNativeAddon(),
    bare: typeof Bare !== 'undefined', // eslint-disable-line no-undef
    backend: BACKEND // 'noble-js' pure-JS FIPS 203/204; 'bare-native' once a constant-time addon ships
  }
}

function hasNativeAddon () {
  try {
    require.resolve('bare-pqcrypto-native')
    return true
  } catch {
    return false
  }
}

function assertAlgorithm (table, algorithm) {
  if (!Object.hasOwn(table, algorithm)) throw new Error('unknown algorithm: ' + algorithm)
  return table[algorithm]
}

function kemImpl (algorithm) {
  const impl = KEM_IMPL[algorithm]
  if (!impl) throw new Error('unsupported level: ' + algorithm)
  return impl
}

const mlkem = {
  /**
   * Generate an ML-KEM keypair.
   * @param {string} [algorithm='ML-KEM-768']
   * @param {Buffer} [seed] optional 64-byte seed for deterministic keygen
   * @returns {{ publicKey: Buffer, secretKey: Buffer }}
   */
  keygen (algorithm = DEFAULT_KEM, seed) {
    assertAlgorithm(MLKEM, algorithm)
    const impl = kemImpl(algorithm)
    const kp = seed === undefined ? impl.keygen() : impl.keygen(seed)
    return { publicKey: b4a.from(kp.publicKey), secretKey: b4a.from(kp.secretKey) }
  },

  /**
   * Encapsulate a fresh shared secret against a public key.
   * @param {Buffer} publicKey
   * @param {string} [algorithm='ML-KEM-768']
   * @param {Buffer} [coins] optional 32-byte coins for deterministic encapsulation
   * @returns {{ ciphertext: Buffer, sharedSecret: Buffer }}
   */
  encapsulate (publicKey, algorithm = DEFAULT_KEM, coins) {
    const p = assertAlgorithm(MLKEM, algorithm)
    if (!b4a.isBuffer(publicKey) || publicKey.byteLength !== p.publicKeyBytes) {
      throw new Error(algorithm + ' public key must be ' + p.publicKeyBytes + ' bytes')
    }
    const impl = kemImpl(algorithm)
    const r = coins === undefined ? impl.encapsulate(publicKey) : impl.encapsulate(publicKey, coins)
    return { ciphertext: b4a.from(r.cipherText), sharedSecret: b4a.from(r.sharedSecret) }
  },

  /**
   * Decapsulate a ciphertext into the shared secret.
   * @param {Buffer} ciphertext
   * @param {Buffer} secretKey
   * @param {string} [algorithm='ML-KEM-768']
   * @returns {Buffer} 32-byte shared secret
   */
  decapsulate (ciphertext, secretKey, algorithm = DEFAULT_KEM) {
    const p = assertAlgorithm(MLKEM, algorithm)
    if (!b4a.isBuffer(ciphertext) || ciphertext.byteLength !== p.ciphertextBytes) {
      throw new Error(algorithm + ' ciphertext must be ' + p.ciphertextBytes + ' bytes')
    }
    if (!b4a.isBuffer(secretKey) || secretKey.byteLength !== p.secretKeyBytes) {
      throw new Error(algorithm + ' secret key must be ' + p.secretKeyBytes + ' bytes')
    }
    const impl = kemImpl(algorithm)
    return b4a.from(impl.decapsulate(ciphertext, secretKey))
  }
}

function dsaImpl (algorithm) {
  const impl = DSA_IMPL[algorithm]
  if (!impl) throw new Error('unsupported level: ' + algorithm)
  return impl
}

const mldsa = {
  /**
   * Generate an ML-DSA keypair.
   * @param {string} [algorithm='ML-DSA-65']
   * @param {Buffer} [seed] optional 32-byte seed for deterministic keygen
   * @returns {{ publicKey: Buffer, secretKey: Buffer }}
   */
  keygen (algorithm = DEFAULT_DSA, seed) {
    assertAlgorithm(MLDSA, algorithm)
    const impl = dsaImpl(algorithm)
    const kp = seed === undefined ? impl.keygen() : impl.keygen(seed)
    return { publicKey: b4a.from(kp.publicKey), secretKey: b4a.from(kp.secretKey) }
  },

  /**
   * Sign a message. Beware FIPS 204 rejection sampling: signing latency has
   * ~50% coefficient of variation — batch appends when driving hypercore.
   * @param {Buffer} message
   * @param {Buffer} secretKey
   * @param {string} [algorithm='ML-DSA-65']
   * @returns {Buffer} detached signature
   */
  sign (message, secretKey, algorithm = DEFAULT_DSA) {
    const p = assertAlgorithm(MLDSA, algorithm)
    if (!b4a.isBuffer(secretKey) || secretKey.byteLength !== p.secretKeyBytes) {
      throw new Error(algorithm + ' secret key must be ' + p.secretKeyBytes + ' bytes')
    }
    const impl = dsaImpl(algorithm)
    return b4a.from(impl.sign(message, secretKey))
  },

  /**
   * Verify a detached signature.
   * @param {Buffer} signature
   * @param {Buffer} message
   * @param {Buffer} publicKey
   * @param {string} [algorithm='ML-DSA-65']
   * @returns {boolean}
   */
  verify (signature, message, publicKey, algorithm = DEFAULT_DSA) {
    const p = assertAlgorithm(MLDSA, algorithm)
    if (!b4a.isBuffer(signature) || signature.byteLength !== p.signatureBytes) {
      throw new Error(algorithm + ' signature must be ' + p.signatureBytes + ' bytes')
    }
    if (!b4a.isBuffer(publicKey) || publicKey.byteLength !== p.publicKeyBytes) {
      throw new Error(algorithm + ' public key must be ' + p.publicKeyBytes + ' bytes')
    }
    const impl = dsaImpl(algorithm)
    return impl.verify(signature, message, publicKey)
  }
}

// --- Chapter 4 (HC-C1): Hybrid Post-Quantum Log Authenticity ---------------
//
// A hypercore root is signed with BOTH an Ed25519 signature (sodium, the
// classical half) AND an ML-DSA-65 signature (the post-quantum half) over the
// same root bytes. Verification requires BOTH to pass — a forgery therefore
// demands breaking elliptic curves AND module lattices. The signer is
// manifest-selectable via its `scheme` id so classical-only, hybrid, and
// (someday) PQ-only cores can coexist and a peer that does not recognize the
// scheme fails CLOSED rather than silently accepting the classical half.
//
// Wire layout of a hybrid signature (fixed 3373 bytes):
//   bytes [0    .. 64)    Ed25519 detached signature
//   bytes [64   .. 3373)  ML-DSA-65 detached signature (3309 bytes)

const HYBRID_SCHEME = 'hybrid-ed25519-mldsa65'
const ED25519_BYTES = sodium.crypto_sign_BYTES // 64
const HYBRID_DSA = 'ML-DSA-65'
const HYBRID_MLDSA_BYTES = MLDSA[HYBRID_DSA].signatureBytes // 3309
const HYBRID_SIG_BYTES = ED25519_BYTES + HYBRID_MLDSA_BYTES // 3373

/**
 * Generate a hybrid keypair: an Ed25519 pair (classical half) and an
 * ML-DSA-65 pair (post-quantum half).
 * @returns {{ ed: {publicKey: Buffer, secretKey: Buffer}, mldsa: {publicKey: Buffer, secretKey: Buffer} }}
 */
function hybridKeyPair () {
  const edPk = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const edSk = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(edPk, edSk)
  const mldsaKp = mldsa.keygen(HYBRID_DSA)
  return {
    ed: { publicKey: edPk, secretKey: edSk },
    mldsa: { publicKey: mldsaKp.publicKey, secretKey: mldsaKp.secretKey }
  }
}

function edSign (rootHash, edSecret) {
  const sig = b4a.alloc(ED25519_BYTES)
  sodium.crypto_sign_detached(sig, rootHash, edSecret)
  return sig
}

function edVerify (rootHash, sig, edPublic) {
  if (sig.byteLength !== ED25519_BYTES) return false
  if (edPublic.byteLength !== sodium.crypto_sign_PUBLICKEYBYTES) return false
  return sodium.crypto_sign_verify_detached(sig, rootHash, edPublic)
}

// Classical Ed25519 half, exposed on its own so the append benchmark can
// measure the pure-classical signing cadence (mode (a)) without pulling in
// sodium-universal at the call site. This is exactly the primitive hypercore
// signs its roots with (hypercore-crypto -> sodium crypto_sign_detached).
const ed25519 = {
  keyPair () {
    const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
    sodium.crypto_sign_keypair(publicKey, secretKey)
    return { publicKey, secretKey }
  },
  sign (message, secretKey) {
    return edSign(b4a.isBuffer(message) ? message : b4a.from(message), secretKey)
  },
  verify (message, sig, publicKey) {
    return edVerify(b4a.isBuffer(message) ? message : b4a.from(message), sig, publicKey)
  },
  signatureBytes: ED25519_BYTES
}

/**
 * Build a hybrid signer bound to a keypair (from `hybridKeyPair()`).
 *
 *   sign(rootHash)                 -> Buffer(3373) = ed25519(64) || mldsa65(3309)
 *   verify(rootHash, sig, publics) -> boolean; true iff BOTH halves verify
 *
 * `publics` is `{ ed: <32B Ed25519 pk>, mldsa: <1952B ML-DSA-65 pk> }`; when
 * omitted, `verify` falls back to the signer's own public keys. Verification
 * is fail-closed: a malformed signature length, an unrecognized scheme, or a
 * single tampered byte in EITHER half yields `false`, never a throw-through.
 *
 * @param {ReturnType<typeof hybridKeyPair>} keyPair
 */
function hybridSigner (keyPair = hybridKeyPair()) {
  const { ed, mldsa: pq } = keyPair

  return {
    scheme: HYBRID_SCHEME,
    signatureBytes: HYBRID_SIG_BYTES,
    publicKey: { ed: ed.publicKey, mldsa: pq.publicKey },

    /**
     * Sign a hypercore root. Both halves cover the identical `rootHash` bytes.
     * @param {Buffer} rootHash canonical serialization of the core root
     * @returns {Buffer} 3373-byte hybrid signature (ed25519 || mldsa65)
     */
    sign (rootHash) {
      if (!b4a.isBuffer(rootHash)) rootHash = b4a.from(rootHash)
      const cls = edSign(rootHash, ed.secretKey) // 64 bytes
      const pqSig = mldsa.sign(rootHash, pq.secretKey, HYBRID_DSA) // 3309 bytes
      return b4a.concat([cls, pqSig]) // 3373 bytes
    },

    /**
     * Verify a hybrid signature. Fail-closed: returns `true` only when the
     * length is exactly 3373 AND the Ed25519 half AND the ML-DSA-65 half both
     * verify against `publics` (or the signer's own keys).
     * @param {Buffer} rootHash
     * @param {Buffer} sig 3373-byte hybrid signature
     * @param {{ ed: Buffer, mldsa: Buffer }} [publics]
     * @returns {boolean}
     */
    verify (rootHash, sig, publics = { ed: ed.publicKey, mldsa: pq.publicKey }) {
      try {
        if (!b4a.isBuffer(sig) || sig.byteLength !== HYBRID_SIG_BYTES) return false
        if (!publics || !publics.ed || !publics.mldsa) return false
        if (!b4a.isBuffer(rootHash)) rootHash = b4a.from(rootHash)

        const cls = sig.subarray(0, ED25519_BYTES)
        const pqSig = sig.subarray(ED25519_BYTES)

        // Both halves must verify — logical AND of two independent hard
        // problems. Short-circuits on the cheaper classical half first.
        if (!edVerify(rootHash, cls, publics.ed)) return false
        return mldsa.verify(pqSig, rootHash, publics.mldsa, HYBRID_DSA)
      } catch {
        // Any unexpected error (bad-length key rejected by a backend, etc.)
        // must fail closed, never leak an exception past verification.
        return false
      }
    }
  }
}

module.exports = {
  detect,
  mlkem,
  mldsa,
  ed25519,
  hybridSigner,
  hybridKeyPair,
  constants: {
    ...MLKEM,
    ...MLDSA,
    DEFAULT_KEM,
    DEFAULT_DSA,
    BACKEND,
    HYBRID_SCHEME,
    HYBRID_SIG_BYTES,
    HYBRID_ED25519_BYTES: ED25519_BYTES,
    HYBRID_MLDSA_BYTES
  }
}
