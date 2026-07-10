// pq-secretstream — hybrid X25519 + ML-KEM-768 handshake layer for
// @hyperswarm/secret-stream, with downgrade protection. (CRYPTO-1)
//
// What is real today: mode negotiation with downgrade protection, transcript
// binding of the offered modes, and the hybrid secret combiner. What throws:
// everything that needs an actual ML-KEM implementation (see bare-pqcrypto)
// or Noise wire-format changes.

const sodium = require('sodium-universal')
const b4a = require('b4a')
const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js')

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
const NS_SESSION = b4a.from('pq-secretstream/session/v0')

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
 * Generate an ML-KEM-768 keypair. Delegates to @noble/post-quantum (FIPS 203).
 * @returns {{ publicKey: Buffer, secretKey: Buffer }}
 */
function keygen () {
  const kp = ml_kem768.keygen()
  return { publicKey: b4a.from(kp.publicKey), secretKey: b4a.from(kp.secretKey) }
}

/**
 * Encapsulate against a remote ML-KEM-768 public key.
 * @param {Buffer} publicKey - 1184-byte ML-KEM-768 public key
 * @returns {{ ciphertext: Buffer, sharedSecret: Buffer }}
 */
function encapsulate (publicKey) {
  if (!b4a.isBuffer(publicKey) || publicKey.byteLength !== MLKEM768.publicKeyBytes) {
    throw new Error('publicKey must be a ' + MLKEM768.publicKeyBytes + '-byte buffer')
  }
  const r = ml_kem768.encapsulate(publicKey)
  return { ciphertext: b4a.from(r.cipherText), sharedSecret: b4a.from(r.sharedSecret) }
}

/**
 * Decapsulate a ciphertext with our ML-KEM-768 secret key.
 * ML-KEM has implicit rejection: a tampered ciphertext does not error, it
 * yields a deterministic but *different* pseudo-random secret — which is what
 * makes the derived session key diverge instead of leaking the failure.
 * @param {Buffer} ciphertext - 1088-byte ciphertext
 * @param {Buffer} secretKey - 2400-byte secret key
 * @returns {Buffer} 32-byte shared secret
 */
function decapsulate (ciphertext, secretKey) {
  if (!b4a.isBuffer(ciphertext) || ciphertext.byteLength !== MLKEM768.ciphertextBytes) {
    throw new Error('ciphertext must be a ' + MLKEM768.ciphertextBytes + '-byte buffer')
  }
  if (!b4a.isBuffer(secretKey) || secretKey.byteLength !== MLKEM768.secretKeyBytes) {
    throw new Error('secretKey must be a ' + MLKEM768.secretKeyBytes + '-byte buffer')
  }
  return b4a.from(ml_kem768.decapsulate(ciphertext, secretKey))
}

// --- classical X25519 half -------------------------------------------------

/**
 * Generate an ephemeral X25519 keypair.
 * @returns {{ publicKey: Buffer, secretKey: Buffer }}
 */
function x25519Keygen () {
  const publicKey = b4a.alloc(X25519.publicKeyBytes)
  const secretKey = b4a.alloc(X25519.secretKeyBytes)
  sodium.randombytes_buf(secretKey)
  sodium.crypto_scalarmult_base(publicKey, secretKey)
  return { publicKey, secretKey }
}

function x25519Dh (secretKey, remotePublicKey) {
  const out = b4a.alloc(X25519.sharedSecretBytes)
  sodium.crypto_scalarmult(out, secretKey, remotePublicKey)
  return out
}

/**
 * Derive the final 32-byte session key from the hybrid secret and the
 * transcript-bound negotiation. The offered-mode digests of BOTH peers are
 * mixed in (positional: initiator first, responder second), so if a MITM
 * tampers with either offered-mode list the two sides feed different digests
 * here and their session keys diverge — cryptographic downgrade detection, not
 * a cosmetic policy check.
 *
 * @param {Buffer} hybridSecret - output of combineSecrets(dh, mlkemSs)
 * @param {string} negotiatedMode
 * @param {Buffer} initiatorModesDigest - bindModes(initiator's offered modes)
 * @param {Buffer} responderModesDigest - bindModes(responder's offered modes)
 * @returns {Buffer} 32-byte session key
 */
function deriveSessionKey (hybridSecret, negotiatedMode, initiatorModesDigest, responderModesDigest) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash_batch(out, [
    NS_SESSION,
    hybridSecret,
    b4a.from(negotiatedMode),
    initiatorModesDigest,
    responderModesDigest
  ])
  return out
}

/**
 * Initiator step 1. Produces the offer (first handshake message) and the
 * private state needed to finalize. The offer carries an X25519 ephemeral
 * public key (32 B) and an ML-KEM-768 public key (1184 B) — the interactive
 * pattern from Chapter 5 where the responder's KEM key is not pre-known, so the
 * ML-KEM public key rides in the first message. That first message is 1216+
 * bytes of key material, past a single UDP datagram — the fragmentation cost.
 *
 * @param {{ modes?: string[], requireHybrid?: boolean }} [opts]
 * @returns {{ state: object, offer: { modes: string[], x25519pk: Buffer, mlkemPk: Buffer } }}
 */
function initiate (opts = {}) {
  const modes = opts.modes || [MODE_CLASSICAL, MODE_HYBRID]
  const requireHybrid = !!opts.requireHybrid
  const x = x25519Keygen()
  const k = keygen()
  const state = {
    modes,
    requireHybrid,
    x25519sk: x.secretKey,
    x25519pk: x.publicKey,
    mlkemSk: k.secretKey,
    mlkemPk: k.publicKey
  }
  const offer = { modes: modes.slice(), x25519pk: x.publicKey, mlkemPk: k.publicKey }
  return { state, offer }
}

/**
 * Responder step. Consumes the initiator's offer, runs selectMode (policy-half
 * downgrade check, hard-fails under requireHybrid), performs the X25519 DH and
 * ML-KEM encapsulation, and derives the session key. Returns the session key
 * and the response message (second handshake message).
 *
 * @param {{ modes: string[], x25519pk: Buffer, mlkemPk: Buffer }} offer
 * @param {{ modes?: string[], requireHybrid?: boolean }} [opts]
 * @returns {{ sessionKey: Buffer, mode: string, message: { modes: string[], x25519pk: Buffer, ciphertext: Buffer } }}
 */
function respond (offer, opts = {}) {
  const modes = opts.modes || [MODE_CLASSICAL, MODE_HYBRID]
  const requireHybrid = !!opts.requireHybrid
  const mode = selectMode(modes, offer.modes, { requireHybrid })

  const x = x25519Keygen()
  const dh = x25519Dh(x.secretKey, offer.x25519pk)
  const { ciphertext, sharedSecret } = encapsulate(offer.mlkemPk)
  const hybrid = combineSecrets(dh, sharedSecret)

  const sessionKey = deriveSessionKey(hybrid, mode, bindModes(offer.modes), bindModes(modes))
  const message = { modes: modes.slice(), x25519pk: x.publicKey, ciphertext }
  return { sessionKey, mode, message }
}

/**
 * Initiator step 2. Consumes the responder's message, re-checks the negotiated
 * mode against its own policy, performs the matching X25519 DH and ML-KEM
 * decapsulation, and derives the session key. In an honest run this equals the
 * responder's key byte-for-byte.
 *
 * @param {object} state - the state returned by initiate()
 * @param {{ modes: string[], x25519pk: Buffer, ciphertext: Buffer }} message
 * @returns {{ sessionKey: Buffer, mode: string }}
 */
function finalize (state, message) {
  const mode = selectMode(state.modes, message.modes, { requireHybrid: state.requireHybrid })

  const dh = x25519Dh(state.x25519sk, message.x25519pk)
  const sharedSecret = decapsulate(message.ciphertext, state.mlkemSk)
  const hybrid = combineSecrets(dh, sharedSecret)

  const sessionKey = deriveSessionKey(hybrid, mode, bindModes(state.modes), bindModes(message.modes))
  return { sessionKey, mode }
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
  initiate,
  respond,
  finalize,
  constants: {
    MODE_CLASSICAL,
    MODE_HYBRID,
    MODES,
    MLKEM768,
    X25519
  }
}
