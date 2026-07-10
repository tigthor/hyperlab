// pq-secretstream — hybrid X25519 + ML-KEM-768 handshake layer for
// @hyperswarm/secret-stream, with downgrade protection. (CRYPTO-1)
//
// What is real today: mode negotiation with downgrade protection, transcript
// binding of the offered modes, and the hybrid secret combiner. What throws:
// everything that needs an actual ML-KEM implementation (see bare-pqcrypto)
// or Noise wire-format changes.

const sodium = require('sodium-universal')
const b4a = require('b4a')

// FIPS 203 (final, 2024-08-13) ML-KEM-768 parameter sizes
const MLKEM768 = {
  publicKeyBytes: 1184,
  secretKeyBytes: 2400,
  ciphertextBytes: 1088,
  sharedSecretBytes: 32
}

const X25519 = {
  publicKeyBytes: 32,
  secretKeyBytes: 32,
  sharedSecretBytes: 32
}

const MODE_CLASSICAL = 'classical' // X25519 only (today's secret-stream)
const MODE_HYBRID = 'hybrid' // X25519 + ML-KEM-768
const MODES = [MODE_CLASSICAL, MODE_HYBRID]

const NS_COMBINE = b4a.from('pq-secretstream/combine/v0')
const NS_MODES = b4a.from('pq-secretstream/modes/v0')

/**
 * Pick the strongest handshake mode both peers support.
 *
 * Downgrade protection has two halves: (1) this policy check — if
 * `requireHybrid` is set a classical-only intersection is a hard failure,
 * not a fallback — and (2) `bindModes`, whose digest of the *offered* modes
 * must be mixed into the Noise handshake hash so a MITM stripping the hybrid
 * offer breaks the handshake.
 *
 * @param {string[]} localModes - modes we support, e.g. ['classical', 'hybrid']
 * @param {string[]} remoteModes - modes the peer offered
 * @param {{ requireHybrid?: boolean }} [opts]
 * @returns {string} the negotiated mode
 */
function selectMode (localModes, remoteModes, opts = {}) {
  if (!Array.isArray(localModes) || !Array.isArray(remoteModes)) {
    throw new Error('modes must be arrays')
  }
  for (const m of localModes.concat(remoteModes)) {
    if (!MODES.includes(m)) throw new Error('unknown mode: ' + m)
  }

  const common = localModes.filter((m) => remoteModes.includes(m))
  if (common.length === 0) throw new Error('no common handshake mode')

  const mode = common.includes(MODE_HYBRID) ? MODE_HYBRID : MODE_CLASSICAL
  if (opts.requireHybrid && mode !== MODE_HYBRID) {
    throw new Error('downgrade rejected: hybrid mode required but peer only offers classical')
  }
  return mode
}

/**
 * Deterministic 32-byte digest of an offered mode list, for mixing into the
 * Noise handshake hash (transcript binding — the anti-downgrade half that a
 * policy check alone cannot provide).
 *
 * @param {string[]} modes
 * @returns {Buffer} 32-byte digest
 */
function bindModes (modes) {
  if (!Array.isArray(modes) || modes.length === 0) throw new Error('modes must be a non-empty array')
  for (const m of modes) {
    if (!MODES.includes(m)) throw new Error('unknown mode: ' + m)
  }
  const sorted = modes.slice().sort()
  const out = b4a.alloc(32)
  sodium.crypto_generichash_batch(out, [NS_MODES, b4a.from(sorted.join(','))])
  return out
}

/**
 * Combine the classical (X25519 DH) and post-quantum (ML-KEM decapsulated)
 * shared secrets into one 32-byte hybrid secret. Secure if EITHER input
 * stays secret (concatenation-KDF construction, as in TLS 1.3 hybrid drafts).
 *
 * @param {Buffer} classicalSecret - 32-byte X25519 shared secret
 * @param {Buffer} pqSecret - 32-byte ML-KEM-768 shared secret
 * @returns {Buffer} 32-byte hybrid secret
 */
function combineSecrets (classicalSecret, pqSecret) {
  if (!b4a.isBuffer(classicalSecret) || classicalSecret.byteLength !== X25519.sharedSecretBytes) {
    throw new Error('classicalSecret must be a 32-byte buffer')
  }
  if (!b4a.isBuffer(pqSecret) || pqSecret.byteLength !== MLKEM768.sharedSecretBytes) {
    throw new Error('pqSecret must be a 32-byte buffer')
  }
  const out = b4a.alloc(32)
  sodium.crypto_generichash_batch(out, [NS_COMBINE, classicalSecret, pqSecret])
  return out
}

/**
 * Generate an ML-KEM-768 keypair.
 * @returns {{ publicKey: Buffer, secretKey: Buffer }}
 */
function keygen () {
  throw new Error('not implemented: ML-KEM-768 keygen (needs a bare-pqcrypto backend)')
}

/**
 * Encapsulate against a remote ML-KEM-768 public key.
 * @param {Buffer} publicKey - 1184-byte ML-KEM-768 public key
 * @returns {{ ciphertext: Buffer, sharedSecret: Buffer }}
 */
function encapsulate (publicKey) {
  throw new Error('not implemented: ML-KEM-768 encapsulation (needs a bare-pqcrypto backend)')
}

/**
 * Decapsulate a ciphertext with our ML-KEM-768 secret key.
 * @param {Buffer} ciphertext - 1088-byte ciphertext
 * @param {Buffer} secretKey - 2400-byte secret key
 * @returns {Buffer} 32-byte shared secret
 */
function decapsulate (ciphertext, secretKey) {
  throw new Error('not implemented: ML-KEM-768 decapsulation (needs a bare-pqcrypto backend)')
}

/**
 * Drop-in replacement for @hyperswarm/secret-stream's NoiseSecretStream that
 * runs a hybrid Noise_XXhfs-style handshake (X25519 ephemerals + ML-KEM-768
 * encapsulation mixed into the key schedule via combineSecrets).
 *
 * The >1 KB ML-KEM public key / ciphertext will not fit typical DHT-relayed
 * first messages, so the wire layer must fragment the first handshake payload.
 */
class PQSecretStream {
  /**
   * @param {boolean} isInitiator
   * @param {import('stream').Duplex} [rawStream]
   * @param {{ modes?: string[], requireHybrid?: boolean, keyPair?: object }} [opts]
   */
  constructor (isInitiator, rawStream, opts = {}) {
    if (typeof isInitiator !== 'boolean') throw new Error('isInitiator should be a boolean')
    throw new Error('not implemented: hybrid Noise wire integration (handshake fragmentation + key-schedule mixing)')
  }
}

module.exports = {
  PQSecretStream,
  selectMode,
  bindModes,
  combineSecrets,
  keygen,
  encapsulate,
  decapsulate,
  constants: {
    MODE_CLASSICAL,
    MODE_HYBRID,
    MODES,
    MLKEM768,
    X25519
  }
}
