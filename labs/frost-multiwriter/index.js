// frost-multiwriter — FROST threshold multi-writer for fixed writer sets
// (e.g. a 3-of-5 org core): t-of-n writers cooperatively produce ONE standard
// Ed25519 signature over the hypercore root, so replication sees a single
// canonical signed core — no per-writer cores, no DAG, no reorg. (FROST-1)
//
// What is real today: config validation and group signature verification
// (a FROST output IS a standard Ed25519 signature, so verification is plain
// crypto_sign_verify_detached — that is the whole point). What throws:
// keygen, the two signing rounds, aggregation and the hypercore signer hook.

const sodium = require('sodium-universal')
const b4a = require('b4a')

const MIN_THRESHOLD = 2

/**
 * Validate a t-of-n configuration.
 * @param {number} threshold - t, signers needed to produce a signature
 * @param {number} signers - n, total writer set size
 */
function validateConfig (threshold, signers) {
  if (!Number.isInteger(threshold) || !Number.isInteger(signers)) {
    throw new Error('threshold and signers must be integers')
  }
  if (threshold < MIN_THRESHOLD) throw new Error('threshold must be >= ' + MIN_THRESHOLD)
  if (signers < threshold) throw new Error('signers must be >= threshold')
}

/**
 * Trusted-dealer FROST keygen: Shamir-share a group Ed25519 secret over the
 * ed25519 scalar field. (A DKG variant can replace the dealer later.)
 *
 * @param {number} threshold - t
 * @param {number} signers - n
 * @returns {{ publicKey: Buffer, shares: { id: number, secretShare: Buffer, verificationShare: Buffer }[] }}
 */
function dealerKeygen (threshold, signers) {
  validateConfig(threshold, signers)
  throw new Error('not implemented: FROST trusted-dealer keygen (Shamir sharing over the ed25519 scalar field — sodium-universal lacks scalar multiplication, needs a scalar-arithmetic helper)')
}

/**
 * One participant's view of a two-round FROST signing session.
 */
class SignSession {
  /**
   * @param {{ id: number, secretShare: Buffer, publicKey: Buffer, threshold: number, signers: number }} opts
   */
  constructor (opts = {}) {
    const { id, secretShare = null, publicKey = null, threshold, signers } = opts
    validateConfig(threshold, signers)
    if (!Number.isInteger(id) || id < 1 || id > signers) {
      throw new Error('id must be an integer in [1, signers]')
    }
    this.id = id
    this.secretShare = secretShare
    this.publicKey = publicKey
    this.threshold = threshold
    this.signers = signers
    this.nonces = null
  }

  /**
   * Round 1: generate a nonce pair (d, e), return the public commitments to
   * broadcast to the other signers.
   * @returns {{ id: number, hidingCommitment: Buffer, bindingCommitment: Buffer }}
   */
  commit () {
    throw new Error('not implemented: FROST round 1 (nonce pair generation + commitments)')
  }

  /**
   * Round 2: given the message and every participant's round-1 commitments,
   * produce this participant's signature share.
   * @param {Buffer} message - the hypercore root/tree hash to sign
   * @param {{ id: number, hidingCommitment: Buffer, bindingCommitment: Buffer }[]} commitments
   * @returns {{ id: number, share: Buffer }}
   */
  sign (message, commitments) {
    throw new Error('not implemented: FROST round 2 (binding factors + per-signer response share)')
  }
}

/**
 * Aggregate >= threshold signature shares into one standard 64-byte Ed25519
 * signature verifiable with the group public key.
 * @param {Buffer} message
 * @param {{ id, hidingCommitment, bindingCommitment }[]} commitments
 * @param {{ id, share }[]} shares
 * @param {Buffer} publicKey - 32-byte group public key
 * @returns {Buffer} 64-byte Ed25519 signature
 */
function aggregate (message, commitments, shares, publicKey) {
  throw new Error('not implemented: FROST share aggregation (Lagrange interpolation of response shares)')
}

/**
 * Verify a group signature. REAL: a FROST signature is a standard Ed25519
 * signature, so any stock hypercore replica verifies it with no code changes.
 * @param {Buffer} signature - 64 bytes
 * @param {Buffer} message
 * @param {Buffer} publicKey - 32-byte group public key
 * @returns {boolean}
 */
function verify (signature, message, publicKey) {
  if (!b4a.isBuffer(signature) || signature.byteLength !== sodium.crypto_sign_BYTES) {
    throw new Error('signature must be a 64-byte buffer')
  }
  if (!b4a.isBuffer(publicKey) || publicKey.byteLength !== sodium.crypto_sign_PUBLICKEYBYTES) {
    throw new Error('publicKey must be a 32-byte buffer')
  }
  if (!b4a.isBuffer(message)) message = b4a.from(message)
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}

/**
 * Create a hypercore whose appends are signed by the FROST group: plugs a
 * threshold signer into hypercore's manifest/signer abstraction, gathering
 * round-1/round-2 messages from `opts.transport` before each root signature.
 *
 * @param {*} storage - hypercore storage (directory or hypercore-storage)
 * @param {{ publicKey: Buffer, session: SignSession, transport: object }} opts
 * @returns {import('hypercore')}
 */
function createCore (storage, opts = {}) {
  throw new Error('not implemented: hypercore manifest signer backed by the FROST group key (needs async signing hook + signer round-trip transport)')
}

module.exports = {
  dealerKeygen,
  SignSession,
  aggregate,
  verify,
  createCore,
  validateConfig,
  constants: {
    MIN_THRESHOLD,
    SIGNATURE_BYTES: sodium.crypto_sign_BYTES,
    PUBLICKEY_BYTES: sodium.crypto_sign_PUBLICKEYBYTES
  }
}
