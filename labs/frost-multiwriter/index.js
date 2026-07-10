// frost-multiwriter — real t-of-n threshold Schnorr multi-writer for fixed
// writer sets (e.g. a 2-of-3 org core). Any t of n writers cooperatively
// produce ONE canonical group signature over the hypercore root, so a group
// commit is a single signed object — no per-writer cores, no DAG, no reorg.
//
// CRYPTO: this is FROST (RFC 9591) over the ristretto255 prime-order group,
// via @noble/curves ristretto255_FROST. The output is a 64-byte ristretto255
// Schnorr signature verifiable against the single 32-byte group public key.
//
// HONEST GAP: a ristretto255 Schnorr signature is NOT byte-compatible with
// Ed25519 / RFC 8032. It does NOT drop into hypercore's stock ed25519
// verifier. Making a hypercore-compatible group core needs FROST-Ed25519
// (RFC 9591 Ed25519 ciphersuite) so the aggregate is a valid RFC 8032
// signature — that is the follow-up, and createCore() stays an honest stub.

const b4a = require('b4a')
const { ristretto255_FROST: FROST } = require('@noble/curves/ed25519.js')

const MIN_THRESHOLD = 2
const SIGNATURE_BYTES = 64
const PUBLICKEY_BYTES = 32

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

function asBytes (message) {
  if (b4a.isBuffer(message)) return message
  if (message instanceof Uint8Array) return message
  return b4a.from(message)
}

// Rebuild the canonical RFC 9591 commitment list from the public commit()
// messages broadcast by the participating signers. Sorted by identifier so
// every signer and the aggregator derive identical binding factors regardless
// of the order messages arrived in — one canonical signature, no reorg.
function toCommitmentList (commitments) {
  return commitments
    .map((c) => ({
      identifier: c.identifier,
      hiding: asBytes(c.hidingCommitment),
      binding: asBytes(c.bindingCommitment)
    }))
    .sort((a, b) => (a.identifier < b.identifier ? -1 : a.identifier > b.identifier ? 1 : 0))
}

/**
 * Trusted-dealer FROST keygen: verifiably secret-share one group secret over
 * the ristretto255 scalar field into n shares, of which any t reconstruct a
 * signing quorum. (RFC 9591 Appendix C; swap for the DKG rounds to drop the
 * dealer.)
 *
 * @param {number} threshold - t
 * @param {number} signers - n
 * @returns {{ publicKey: Buffer, group: object, shares: { id: number, identifier: string, secret: object, verificationShare: Buffer }[] }}
 */
function dealerKeygen (threshold, signers) {
  validateConfig(threshold, signers)

  const dealt = FROST.trustedDealer({ min: threshold, max: signers })
  const group = dealt.public
  const publicKey = b4a.from(group.commitments[0]) // group public key = first VSS commitment

  const shares = []
  for (let id = 1; id <= signers; id++) {
    const identifier = FROST.Identifier.fromNumber(id)
    const secret = dealt.secretShares[identifier]
    // fail closed if the dealer produced an inconsistent share
    FROST.validateSecret(secret, group)
    shares.push({
      id,
      identifier,
      secret,
      verificationShare: b4a.from(group.verifyingShares[identifier])
    })
  }

  return { publicKey, group, shares }
}

/**
 * One participant's view of a two-round FROST signing session.
 */
class SignSession {
  /**
   * @param {{ id: number, secret: object, group: object, threshold: number, signers: number }} opts
   *   - `secret` and `group` come straight from dealerKeygen() (a share + the group package).
   */
  constructor (opts = {}) {
    const { id, secret = null, group = null, threshold, signers } = opts
    validateConfig(threshold, signers)
    if (!Number.isInteger(id) || id < 1 || id > signers) {
      throw new Error('id must be an integer in [1, signers]')
    }
    this.id = id
    this.identifier = FROST.Identifier.fromNumber(id)
    this.secret = secret
    this.group = group
    this.threshold = threshold
    this.signers = signers
    this.nonces = null
  }

  /**
   * Round 1: generate a one-time nonce pair (d, e) and return the public
   * commitments to broadcast to the other signers.
   * @returns {{ id: number, identifier: string, hidingCommitment: Buffer, bindingCommitment: Buffer }}
   */
  commit () {
    if (!this.secret) throw new Error('session has no secret share to commit with')
    const gen = FROST.commit(this.secret)
    this.nonces = gen.nonces // one-time-use; consumed (zeroed) by sign()
    return {
      id: this.id,
      identifier: this.identifier,
      hidingCommitment: b4a.from(gen.commitments.hiding),
      bindingCommitment: b4a.from(gen.commitments.binding)
    }
  }

  /**
   * Round 2: given the message and every participating signer's round-1
   * commitments (including this signer's own), produce this signer's
   * signature share. Throws if fewer than `threshold` commitments are present
   * (the protocol fails closed below quorum).
   * @param {Buffer} message - the root/tree hash being signed
   * @param {{ id, identifier, hidingCommitment, bindingCommitment }[]} commitments
   * @returns {{ id: number, identifier: string, share: Buffer }}
   */
  sign (message, commitments) {
    if (!this.nonces) throw new Error('must commit() before sign()')
    if (!Array.isArray(commitments) || commitments.length < this.threshold) {
      throw new Error('need at least threshold commitments to sign (below quorum)')
    }
    const list = toCommitmentList(commitments)
    const share = FROST.signShare(this.secret, this.group, this.nonces, list, asBytes(message))
    this.nonces = null // consumed
    return { id: this.id, identifier: this.identifier, share: b4a.from(share) }
  }
}

/**
 * Aggregate >= threshold signature shares into ONE 64-byte ristretto255
 * Schnorr signature verifiable against the single group public key. Each share
 * is verified individually; a bad/forged share makes aggregation fail closed
 * (throwing, identifying the offending signer).
 * @param {Buffer} message
 * @param {{ id, identifier, hidingCommitment, bindingCommitment }[]} commitments
 * @param {{ id, identifier, share }[]} shares
 * @param {object} group - the group package from dealerKeygen()
 * @returns {Buffer} 64-byte signature
 */
function aggregate (message, commitments, shares, group) {
  if (!group || !group.commitments) throw new Error('group package required (from dealerKeygen)')
  const list = toCommitmentList(commitments)
  const sigShares = {}
  for (const s of shares) sigShares[s.identifier] = asBytes(s.share)
  const sig = FROST.aggregate(group, list, asBytes(message), sigShares)
  return b4a.from(sig)
}

/**
 * Verify a group signature against the single 32-byte group public key.
 * This is a plain ristretto255 Schnorr verify — NOT an Ed25519 verify.
 * @param {Buffer} signature - 64 bytes
 * @param {Buffer} message
 * @param {Buffer} publicKey - 32-byte group public key
 * @returns {boolean}
 */
function verify (signature, message, publicKey) {
  if (!b4a.isBuffer(signature) || signature.byteLength !== SIGNATURE_BYTES) {
    throw new Error('signature must be a 64-byte buffer')
  }
  if (!b4a.isBuffer(publicKey) || publicKey.byteLength !== PUBLICKEY_BYTES) {
    throw new Error('publicKey must be a 32-byte buffer')
  }
  try {
    // A tampered signature can carry a non-canonical R point that fails to
    // decode; that is an invalid signature, not a crash — return false.
    return FROST.verify(signature, asBytes(message), publicKey)
  } catch {
    return false
  }
}

/**
 * Create a hypercore whose appends are signed by the FROST group.
 *
 * HONEST STUB: not implemented. hypercore verifies RFC 8032 Ed25519, and the
 * signatures this module produces are ristretto255 Schnorr, which are NOT
 * byte-compatible. A hypercore-compatible group core needs the FROST-Ed25519
 * ciphersuite (RFC 9591) so the aggregate is a valid Ed25519 signature the
 * stock verifier accepts, plus a manifest signer hook that gathers the two
 * signing rounds. That is the required follow-up.
 */
function createCore (storage, opts = {}) {
  throw new Error('not implemented: FROST-Ed25519 needed for hypercore-compatible (RFC 8032) signatures')
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
    SIGNATURE_BYTES,
    PUBLICKEY_BYTES
  }
}
