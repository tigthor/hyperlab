// hyperbeam-pake — CPace PAKE rendezvous for hyperbeam, so a low-entropy
// human passphrase resists offline dictionary attacks and first-come-
// first-served MITM. (BEAM-1, research BEAM-E1)
//
// What is real today: the CPace exchange itself (prototyped on the ed25519
// group via libsodium's Elligator map — the RFC draft uses ristretto255,
// which sodium-universal does not expose) and the rendezvous topic
// derivation. What throws: the wire integration that runs the exchange over
// the DHT and upgrades the beam to a SecretStream keyed by the CPace output.
//
// SECURITY NOTE: prototype-grade. The group is ed25519 (cofactor cleared by
// crypto_core_ed25519_from_uniform), not ristretto255; not audited for
// side channels. Do not ship as-is.

const sodium = require('sodium-universal')
const b4a = require('b4a')

const DSI_GENERATOR = b4a.from('hyperbeam-pake/cpace/generator/v0')
const DSI_ISK = b4a.from('hyperbeam-pake/cpace/isk/v0')
const NS_TOPIC = b4a.from('hyperbeam-pake/topic/v0')

const MSGBYTES = 32 // one group element each way
const KEYBYTES = 32 // intermediate session key (ISK) length

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
 * Hash the passphrase (and session id) onto a group generator via
 * Elligator: g = map(H(dsi || passphrase || sid)). Both sides derive the
 * same g; nobody knows its discrete log.
 *
 * @param {Buffer} passphrase
 * @param {Buffer} sid - session id both sides agree on
 * @returns {Buffer} 32-byte group element
 */
function deriveGenerator (passphrase, sid) {
  const seed = b4a.alloc(sodium.crypto_core_ed25519_UNIFORMBYTES)
  sodium.crypto_generichash_batch(seed, [DSI_GENERATOR, passphrase, sid])
  const g = b4a.alloc(sodium.crypto_core_ed25519_BYTES)
  sodium.crypto_core_ed25519_from_uniform(g, seed)
  return g
}

/**
 * One side of a CPace exchange. Usage:
 *
 *   const a = new CPace(passphrase, { isInitiator: true, sid })
 *   const msgA = a.start() // send to peer
 *   const isk = a.finish(msgB) // 32-byte shared key, equal on both sides
 *
 * A wrong passphrase (or a MITM who doesn't know it) yields a different key
 * — and the transcript gives an offline attacker nothing to grind against.
 */
class CPace {
  /**
   * @param {Buffer|string} passphrase - the low-entropy shared secret
   * @param {{ isInitiator: boolean, sid?: Buffer }} opts - sid must match on both sides
   */
  constructor (passphrase, opts = {}) {
    if (typeof passphrase === 'string') passphrase = b4a.from(passphrase)
    if (!b4a.isBuffer(passphrase) || passphrase.byteLength === 0) {
      throw new Error('passphrase must be a non-empty string or buffer')
    }
    if (typeof opts.isInitiator !== 'boolean') throw new Error('opts.isInitiator must be a boolean')

    this.isInitiator = opts.isInitiator
    this.sid = opts.sid || b4a.alloc(16) // both sides must use the same sid
    this.generator = deriveGenerator(passphrase, this.sid)
    this.scalar = null
    this.msg = null
    this.key = null
  }

  /**
   * Round 1: pick a random scalar a, return Ya = a * g to send to the peer.
   * @returns {Buffer} 32-byte public message
   */
  start () {
    if (this.msg) throw new Error('start() already called')
    this.scalar = b4a.alloc(sodium.crypto_core_ed25519_SCALARBYTES)
    sodium.crypto_core_ed25519_scalar_random(this.scalar)
    this.msg = b4a.alloc(MSGBYTES)
    sodium.crypto_scalarmult_ed25519_noclamp(this.msg, this.scalar, this.generator)
    return this.msg
  }

  /**
   * Round 2: combine the peer's message into the intermediate session key
   * ISK = H(dsi || sid || a*Yb || transcript). Wipes the scalar.
   * @param {Buffer} remoteMsg - the peer's 32-byte start() output
   * @returns {Buffer} 32-byte shared key
   */
  finish (remoteMsg) {
    if (!this.msg) throw new Error('call start() before finish()')
    if (this.key) throw new Error('finish() already called')
    if (!b4a.isBuffer(remoteMsg) || remoteMsg.byteLength !== MSGBYTES) {
      throw new Error('remote message must be a 32-byte buffer')
    }

    const k = b4a.alloc(32)
    try {
      sodium.crypto_scalarmult_ed25519_noclamp(k, this.scalar, remoteMsg)
    } catch {
      throw new Error('invalid remote CPace message (bad or low-order point)')
    }

    // transcript ordering by role so both sides hash identical bytes
    const first = this.isInitiator ? this.msg : remoteMsg
    const second = this.isInitiator ? remoteMsg : this.msg

    const isk = b4a.alloc(KEYBYTES)
    sodium.crypto_generichash_batch(isk, [DSI_ISK, this.sid, k, first, second])

    sodium.sodium_memzero(this.scalar)
    sodium.sodium_memzero(k)
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
