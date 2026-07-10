// hyperbeam-pake — CPace PAKE rendezvous for hyperbeam, so a low-entropy
// human passphrase resists offline dictionary attacks and first-come-
// first-served MITM. (BEAM-1, research BEAM-E1)
//
// What is real today: the CPace exchange itself — now on ristretto255 (a
// prime-order group; @noble/curves' ristretto255.Point + RFC-9380
// hashToCurve), following the CFRG CPace draft shape — and the rendezvous
// topic derivation. What throws: the wire integration that runs the exchange
// over the DHT and upgrades the beam to a SecretStream keyed by the CPace
// output (createPakeBeam).
//
// SECURITY NOTE: ristretto255 is a PRIME-ORDER group, so there is no
// cofactor / small-subgroup element to launder — the only degenerate element
// is the identity, which we reject explicitly. This removes the cofactor
// caveat the earlier ed25519/Elligator prototype carried. Still not audited
// for side channels; @noble/curves aims for constant-time field ops but this
// module's own control flow is not hardened. Do not ship as-is.

const sodium = require('sodium-universal')
const b4a = require('b4a')
const { ristretto255, ristretto255_hasher } = require('@noble/curves/ed25519.js')

const Point = ristretto255.Point

const DSI_GENERATOR = b4a.from('hyperbeam-pake/cpace/generator/v1-ristretto255')
const DSI_ISK = b4a.from('hyperbeam-pake/cpace/isk/v1-ristretto255')
const NS_TOPIC = b4a.from('hyperbeam-pake/topic/v0')

const MSGBYTES = 32 // one ristretto255 group element each way (canonical encoding)
const KEYBYTES = 32 // intermediate session key (ISK) length
const SEEDBYTES = 64 // randomness fed to hashToScalar to sample a group scalar

// 4-byte big-endian length prefix, for unambiguous (prefix-free) transcript
// hashing — so that H(a || b) can never collide with H(a' || b') for a
// different split of the same bytes.
function u32be (n) {
  const b = b4a.alloc(4)
  b[0] = (n >>> 24) & 0xff
  b[1] = (n >>> 16) & 0xff
  b[2] = (n >>> 8) & 0xff
  b[3] = n & 0xff
  return b
}

function lv (buf) {
  return b4a.concat([u32be(buf.byteLength), buf])
}

/**
 * Derive the swarm rendezvous topic from the passphrase. Deliberately in a
 * separate namespace from anything key-bearing: the topic only lets peers
 * find each other, it contributes nothing toward the session key. Production
 * wants a slow hash / OPRF here to tax online enumeration.
 *
 * @param {Buffer|string} passphrase
 * @returns {Buffer} 32-byte topic
 */
function topicFromPassphrase (passphrase) {
  if (typeof passphrase === 'string') passphrase = b4a.from(passphrase)
  if (!b4a.isBuffer(passphrase) || passphrase.byteLength === 0) {
    throw new Error('passphrase must be a non-empty string or buffer')
  }
  const topic = b4a.alloc(32)
  sodium.crypto_generichash_batch(topic, [NS_TOPIC, passphrase])
  return topic
}

/**
 * Hash the passphrase (and session id) onto a ristretto255 generator:
 * g = hashToCurve(DSI || lv(sid) || lv(passphrase)). RFC 9380 hash-to-curve
 * onto a prime-order group — every output is a full-order generator, none is
 * a small-subgroup element, and nobody knows its discrete log. Both sides
 * derive the same g iff they share the passphrase.
 *
 * @param {Buffer} passphrase
 * @param {Buffer} sid - session id both sides agree on
 * @returns {import('@noble/curves/abstract/edwards.js').Point} generator point
 */
function deriveGeneratorPoint (passphrase, sid) {
  const msg = b4a.concat([DSI_GENERATOR, lv(sid), lv(passphrase)])
  return ristretto255_hasher.hashToCurve(msg)
}

/**
 * Public helper: the 32-byte canonical encoding of the passphrase-derived
 * generator. Kept for API stability and to let callers confirm the topic and
 * generator live in separate namespaces.
 *
 * @param {Buffer|string} passphrase
 * @param {Buffer} sid
 * @returns {Buffer} 32-byte group element
 */
function deriveGenerator (passphrase, sid) {
  if (typeof passphrase === 'string') passphrase = b4a.from(passphrase)
  return b4a.from(deriveGeneratorPoint(passphrase, sid).toBytes())
}

/**
 * One side of a CPace exchange. Usage:
 *
 *   const a = new CPace(passphrase, { isInitiator: true, sid })
 *   const msgA = a.start() // send to peer
 *   const isk = a.finish(msgB) // 32-byte shared key, equal on both sides
 *
 * A wrong passphrase (or a MITM who doesn't know it) yields a different key
 * — and the transcript (the two Y points) gives an offline attacker nothing
 * to grind against: each Y is a fresh scalar times a passphrase-derived
 * generator, statistically uniform over the group regardless of which
 * passphrase produced g.
 */
class CPace {
  /**
   * @param {Buffer|string} passphrase - the low-entropy shared secret
   * @param {{ isInitiator: boolean, sid?: Buffer, rng?: (buf: Buffer) => void }} opts
   *   sid must match on both sides. rng fills a buffer with randomness
   *   (defaults to sodium.randombytes_buf); inject a deterministic rng for
   *   known-answer tests.
   */
  constructor (passphrase, opts = {}) {
    if (typeof passphrase === 'string') passphrase = b4a.from(passphrase)
    if (!b4a.isBuffer(passphrase) || passphrase.byteLength === 0) {
      throw new Error('passphrase must be a non-empty string or buffer')
    }
    if (typeof opts.isInitiator !== 'boolean') throw new Error('opts.isInitiator must be a boolean')

    this.isInitiator = opts.isInitiator
    this.sid = opts.sid || b4a.alloc(16) // both sides must use the same sid
    this._rng = opts.rng || ((buf) => sodium.randombytes_buf(buf))
    this.generatorPoint = deriveGeneratorPoint(passphrase, this.sid)
    this.scalar = null // bigint in [1, order)
    this.msg = null
    this.key = null
  }

  /**
   * Round 1: sample a random scalar y, return Y = y * g to send to the peer.
   * @returns {Buffer} 32-byte public message (canonical ristretto255 encoding)
   */
  start () {
    if (this.msg) throw new Error('start() already called')
    const seed = b4a.alloc(SEEDBYTES)
    this._rng(seed)
    // hashToScalar maps arbitrary bytes to a uniform nonzero scalar in [1, L)
    this.scalar = ristretto255_hasher.hashToScalar(seed)
    sodium.sodium_memzero(seed)
    const Y = this.generatorPoint.multiply(this.scalar)
    this.msg = b4a.from(Y.toBytes())
    return this.msg
  }

  /**
   * Round 2: combine the peer's message into the intermediate session key
   * ISK = H(DSI_ISK || lv(sid) || lv(K) || lv(first) || lv(second)) where
   * K = y * Ypeer and (first, second) is the role-ordered transcript so both
   * sides hash identical bytes. Rejects the identity element (the only
   * degenerate point in this prime-order group).
   *
   * @param {Buffer} remoteMsg - the peer's 32-byte start() output
   * @returns {Buffer} 32-byte shared key
   */
  finish (remoteMsg) {
    if (!this.msg) throw new Error('call start() before finish()')
    if (this.key) throw new Error('finish() already called')
    if (!b4a.isBuffer(remoteMsg) || remoteMsg.byteLength !== MSGBYTES) {
      throw new Error('remote message must be a 32-byte buffer')
    }

    let Ypeer
    try {
      Ypeer = Point.fromBytes(remoteMsg)
    } catch {
      throw new Error('invalid remote CPace message (non-canonical encoding)')
    }
    // Reject the identity: in a prime-order group it is the single degenerate
    // element, and a peer element of small order would collapse K to a known
    // value. ristretto255 has no other low-order points to worry about.
    if (Ypeer.is0()) {
      throw new Error('invalid remote CPace message (identity/low-order element)')
    }

    const K = Ypeer.multiply(this.scalar)
    // Defensive: with a nonzero scalar and a nonzero Ypeer in a prime-order
    // group, K is never the identity — but check anyway.
    if (K.is0()) {
      throw new Error('invalid remote CPace message (degenerate shared point)')
    }
    const kBytes = b4a.from(K.toBytes())

    // transcript ordering by role so both sides hash identical bytes
    const first = this.isInitiator ? this.msg : remoteMsg
    const second = this.isInitiator ? remoteMsg : this.msg

    const isk = b4a.alloc(KEYBYTES)
    sodium.crypto_generichash_batch(isk, [
      DSI_ISK,
      lv(this.sid),
      lv(kBytes),
      lv(first),
      lv(second)
    ])

    sodium.sodium_memzero(kBytes)
    // NOTE: this.scalar is a bigint (hashToScalar's return type), so it cannot
    // be memzeroed the way a sodium scalar buffer could; we can only drop the
    // reference and let GC reclaim it. A hardening pass would keep the scalar
    // as a wiped byte buffer.
    this.scalar = null
    this.key = isk
    return isk
  }
}

/**
 * Drop-in hyperbeam replacement: rendezvous on topicFromPassphrase(pass),
 * run CPace over the connection instead of deriving the Noise keypair from
 * the passphrase, then rekey the stream with the ISK. A MITM racing to the
 * topic gets exactly one online passphrase guess, and a transcript recording
 * gives an offline attacker nothing.
 *
 * Still a stub: the DHT rendezvous + CPace-keyed SecretStream upgrade over a
 * live hyperbeam connection is out of scope for this module.
 *
 * @param {string|Buffer} passphrase
 * @param {{ dht?: object, announce?: boolean }} [opts]
 * @returns {import('hyperbeam')}
 */
function createPakeBeam (passphrase, opts = {}) {
  topicFromPassphrase(passphrase) // validates the passphrase
  throw new Error('not implemented: DHT rendezvous + CPace-keyed SecretStream upgrade over hyperbeam')
}

module.exports = {
  CPace,
  createPakeBeam,
  topicFromPassphrase,
  deriveGenerator,
  constants: {
    MSGBYTES,
    KEYBYTES
  }
}
