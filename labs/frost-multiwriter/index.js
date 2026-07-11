// frost-multiwriter — real t-of-n threshold Schnorr multi-writer for fixed
// writer sets (e.g. a 2-of-3 org core). Any t of n writers cooperatively
// produce ONE canonical group signature over the hypercore root, so a group
// commit is a single signed object — no per-writer cores, no DAG, no reorg.
//
// CRYPTO: FROST (RFC 9591) via @noble/curves, in two ciphersuites:
//
// - ristretto255 (FROST(ristretto255, SHA-512)) — the original suite here,
//   exported at the top level unchanged.
// - ed25519 (FROST(Ed25519, SHA-512)) — exported as `ed25519`. Its aggregate
//   is a standard RFC 8032 Ed25519 signature: sodium's stock verifier (and so
//   hypercore's stock Verifier) accepts it with no knowledge that the key was
//   ever sharded. This is what makes createCore() real: a live hypercore
//   whose manifest key is the FROST group key, appends signed by any t of n
//   writers, replicating to completely stock peers.
//
// Remaining honest limits: keygen is still a trusted dealer (RFC 9591
// Appendix C — swap for the DKG rounds to drop the dealer), and the two
// signing rounds here run in-process; a networked deployment brings its own
// transport for the commit/share messages (they are plain buffers).

const b4a = require('b4a')
const { ristretto255_FROST, ed25519_FROST } = require('@noble/curves/ed25519.js')

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

// Everything below is ciphersuite-generic: both suites share the exact same
// noble API, only the group (and therefore the signature format) differs.
function createSuite (FROST) {
  /**
   * Trusted-dealer FROST keygen: verifiably secret-share one group secret into
   * n shares, of which any t reconstruct a signing quorum. (RFC 9591
   * Appendix C; swap for the DKG rounds to drop the dealer.)
   * @returns {{ publicKey: Buffer, group: object, shares: { id, identifier, secret, verificationShare }[] }}
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
     * signature share. Throws if fewer than `threshold` commitments are
     * present (the protocol fails closed below quorum).
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
   * Aggregate >= threshold signature shares into ONE 64-byte Schnorr
   * signature verifiable against the single group public key. Each share is
   * verified; a bad/forged share makes aggregation fail closed (throwing,
   * identifying the offending signer).
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
   * Run one complete two-round signing over `message` with the given
   * in-process sessions (>= threshold of them) and aggregate to the single
   * group signature. In a networked deployment the two rounds are two
   * broadcast messages; this helper is the local composition of them.
   */
  function thresholdSign (message, sessions) {
    if (!Array.isArray(sessions) || sessions.length === 0) throw new Error('sessions required')
    if (sessions.length < sessions[0].threshold) {
      throw new Error('need at least threshold sessions to sign (below quorum)')
    }
    const commitments = sessions.map((s) => s.commit())
    const shares = sessions.map((s) => s.sign(message, commitments))
    return aggregate(message, commitments, shares, sessions[0].group)
  }

  return { dealerKeygen, SignSession, aggregate, verify, thresholdSign }
}

const ristretto255 = createSuite(ristretto255_FROST)
const ed25519 = createSuite(ed25519_FROST)

/**
 * A live hypercore whose appends are signed by the FROST-Ed25519 group.
 *
 * The manifest pins ONE ed25519 signer — the group public key — with
 * quorum 1 and no patching, which stock hypercore verifies with a plain
 * RFC 8032 check (`crypto.verify`). Replicas need no FROST code, no special
 * verifier, not even knowledge that the writer is a committee.
 *
 * append(blocks, sessions) computes the exact tree signable hypercore will
 * verify (tree hash + length + fork, bound to the manifest hash), runs the
 * two FROST rounds across the given sessions (any t of n), aggregates to one
 * 64-byte Ed25519 signature and appends with it.
 *
 * @param {object} storage - anything `new Hypercore(storage)` accepts
 * @param {Buffer} groupPublicKey - from ed25519.dealerKeygen()
 * @param {object} [opts] - { Hypercore, coreOpts } injection points
 */
async function createCore (storage, groupPublicKey, opts = {}) {
  const Hypercore = opts.Hypercore || require('hypercore')
  const Verifier = opts.Verifier || require('hypercore/lib/verifier')

  if (!groupPublicKey || asBytes(groupPublicKey).byteLength !== PUBLICKEY_BYTES) {
    throw new Error('groupPublicKey (32 bytes, from ed25519.dealerKeygen) is required')
  }

  const manifest = {
    version: 1,
    quorum: 1,
    allowPatch: false,
    signers: [{ signature: 'ed25519', publicKey: b4a.from(asBytes(groupPublicKey)) }]
  }

  const core = new Hypercore(storage, { manifest, ...opts.coreOpts })
  await core.ready()

  // the context every signer signs against: version-1 manifests bind the
  // signable to the manifest hash (Signer._ctx in hypercore/lib/verifier)
  const verifier = Verifier.fromManifest(core.manifest)
  const ctx = verifier.manifestHash

  // The tree signable for appending `bufs` at the current length. Exposed so
  // out-of-process signers can be shown exactly what they are signing.
  function signableFor (blocks) {
    const bufs = (Array.isArray(blocks) ? blocks : [blocks]).map(asBytes)
    const batch = core.state.createTreeBatch()
    for (const b of bufs) batch.append(b)
    return { bufs, signable: batch.signable(ctx), length: batch.length }
  }

  // Threshold-signed append. Single-writer-group discipline applies: the
  // signable is computed against the current tree, so appends must not race.
  // The raw 64-byte aggregate goes into the same multisig envelope hypercore's
  // own Verifier.sign wraps single-signer v1 signatures in — that envelope is
  // what replicas expect on the wire.
  async function append (blocks, sessions) {
    const { bufs, signable } = signableFor(blocks)
    const raw = ed25519.thresholdSign(signable, sessions)
    const signature = verifier.assemble([{ signer: 0, signature: raw, patch: 0, nodes: null }])
    return core.append(bufs, { signature })
  }

  return { core, manifest, publicKey: b4a.from(asBytes(groupPublicKey)), signableFor, append }
}

module.exports = {
  // ristretto255 suite — original top-level API, unchanged
  dealerKeygen: ristretto255.dealerKeygen,
  SignSession: ristretto255.SignSession,
  aggregate: ristretto255.aggregate,
  verify: ristretto255.verify,
  thresholdSign: ristretto255.thresholdSign,
  ristretto255,
  // ed25519 suite — RFC 8032-compatible output, hypercore drop-in
  ed25519,
  createCore,
  validateConfig,
  constants: {
    MIN_THRESHOLD,
    SIGNATURE_BYTES,
    PUBLICKEY_BYTES
  }
}
