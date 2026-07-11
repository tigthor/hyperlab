// filedrop wire protocol — the transport- and storage-agnostic core.
//
// Everything here runs identically under Node, Bare and the browser (via
// @hyperswarm/dht-relay): framing, the CPace authentication gate, manifest
// encoding and passphrase generation. No fs, no hyperdht — index.js (Node)
// and browser.js layer storage and transport on top.

const b4a = require('b4a')
const crypto = require('hypercore-crypto')
const { CPace, topicFromPassphrase } = require('hyperbeam-pake')

const DEFAULT_CHUNK_SIZE = 64 * 1024

const TYPE = {
  PAKE: 1,
  CONFIRM: 2,
  MANIFEST: 3,
  RESUME: 4,
  CHUNK: 5,
  DONE: 6,
  RECEIPT: 7,
  ENC: 8
}

// ---------------------------------------------------------------------------
// framing: [u32be len][type byte][payload], len = 1 + payload.length
// ---------------------------------------------------------------------------

function u32be (n) {
  const b = b4a.alloc(4)
  b[0] = (n >>> 24) & 0xff
  b[1] = (n >>> 16) & 0xff
  b[2] = (n >>> 8) & 0xff
  b[3] = n & 0xff
  return b
}

function readU32 (buf, off) {
  return (buf[off] * 0x1000000) + ((buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3])
}

function writeMsg (sock, type, payload) {
  if (!payload) payload = b4a.alloc(0)
  const frame = b4a.concat([u32be(1 + payload.byteLength), b4a.from([type]), payload])
  const ok = sock.write(frame)
  if (ok) return Promise.resolve()
  return new Promise((resolve, reject) => {
    const onDrain = () => { cleanup(); resolve() }
    const onClose = () => { cleanup(); reject(new Error('stream closed during write')) }
    const cleanup = () => {
      sock.removeListener('drain', onDrain)
      sock.removeListener('close', onClose)
    }
    sock.once('drain', onDrain)
    sock.once('close', onClose)
  })
}

// A buffered, message-boundary-preserving reader over a NoiseSecretStream.
// 'data' events do NOT respect our frame boundaries, so we accumulate and pull
// complete frames off the front.
class MessageReader {
  constructor (sock) {
    this.sock = sock
    this.buffered = b4a.alloc(0)
    this.queue = []
    this.waiters = []
    this.ended = false
    this.error = null

    this._onData = (d) => this._push(d)
    this._onEnd = () => this._finish(null)
    this._onError = (err) => this._finish(err)

    sock.on('data', this._onData)
    sock.on('end', this._onEnd)
    sock.on('close', this._onEnd)
    sock.on('error', this._onError)
  }

  _push (d) {
    this.buffered = this.buffered.byteLength ? b4a.concat([this.buffered, d]) : d
    while (this.buffered.byteLength >= 4) {
      const len = readU32(this.buffered, 0)
      if (this.buffered.byteLength < 4 + len) break
      const type = this.buffered[4]
      const payload = b4a.from(this.buffered.subarray(5, 4 + len))
      this.buffered = b4a.from(this.buffered.subarray(4 + len))
      const msg = { type, payload }
      if (this.waiters.length) this.waiters.shift().resolve(msg)
      else this.queue.push(msg)
    }
  }

  _finish (err) {
    if (this.ended) return
    this.ended = true
    this.error = err || new Error('stream ended')
    while (this.waiters.length) this.waiters.shift().reject(this.error)
  }

  read () {
    if (this.queue.length) return Promise.resolve(this.queue.shift())
    if (this.ended) return Promise.reject(this.error)
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }))
  }

  async expect (type) {
    const msg = await this.read()
    if (msg.type !== type) throw new Error('protocol error: expected type ' + type + ' got ' + msg.type)
    return msg
  }

  destroy () {
    this.sock.removeListener('data', this._onData)
    this.sock.removeListener('end', this._onEnd)
    this.sock.removeListener('close', this._onEnd)
    this.sock.removeListener('error', this._onError)
  }
}

// ---------------------------------------------------------------------------
// CPace over the connection — the authentication gate
// ---------------------------------------------------------------------------

// Runs the full CPace exchange (start/finish + key confirmation) over an open
// socket. Resolves the 32-byte ISK on success; REJECTS if the peer's
// confirmation tag does not verify (wrong passphrase / MITM) — the caller must
// destroy the socket on rejection so no file bytes ever move.
async function runCPace (sock, reader, passphrase, sid, isInitiator) {
  const cp = new CPace(passphrase, { isInitiator, sid })
  const myMsg = cp.start()
  await writeMsg(sock, TYPE.PAKE, myMsg)
  const peer = await reader.expect(TYPE.PAKE)
  cp.finish(peer.payload)
  const myTag = cp.confirm()
  await writeMsg(sock, TYPE.CONFIRM, myTag)
  const peerTag = await reader.expect(TYPE.CONFIRM)
  if (!cp.verifyConfirm(peerTag.payload)) {
    throw new Error('CPace key confirmation failed — wrong passphrase or MITM')
  }
  return cp.key
}

// ---------------------------------------------------------------------------
// SecretChannel — application-layer AEAD over the socket, keyed by the CPace
// ISK. The transport underneath (NoiseSecretStream) already encrypts between
// its OWN endpoints, but when the transport is proxied — a custodial
// dht-relay gateway terminates the noise session for the browser — the proxy
// would see plaintext. Sealing every post-CPace frame with the
// passphrase-bound ISK keeps the file bytes end-to-end: a gateway (or any
// intermediary) without the passphrase relays only ciphertext, and its
// compromise degrades to denial of service. Nonces are per-direction
// (1 = initiator->responder, 2 = responder->initiator) with a 64-bit counter,
// and the ISK is fresh per session, so nonces never repeat under one key.
// ---------------------------------------------------------------------------

class SecretChannel {
  constructor (sock, reader, key, isInitiator) {
    // @noble/ciphers rather than sodium: pure JS, so the exact same AEAD runs
    // under Node, Bare and the browser (sodium-javascript, the browser shim
    // for sodium-universal, does not implement xchacha20poly1305)
    this._aead = require('@noble/ciphers/chacha.js').xchacha20poly1305
    this.sock = sock
    this.reader = reader
    this.key = b4a.from(key)
    this.txNonce = b4a.alloc(24)
    this.rxNonce = b4a.alloc(24)
    this.txNonce[0] = isInitiator ? 1 : 2
    this.rxNonce[0] = isInitiator ? 2 : 1
  }

  _bump (nonce) {
    for (let i = 16; i < nonce.byteLength; i++) {
      if (++nonce[i] !== 0) break
    }
  }

  send (type, payload) {
    if (!payload) payload = b4a.alloc(0)
    const pt = b4a.concat([b4a.from([type]), payload])
    const ct = this._aead(this.key, this.txNonce).encrypt(pt)
    this._bump(this.txNonce)
    return writeMsg(this.sock, TYPE.ENC, b4a.from(ct))
  }

  async recv () {
    const msg = await this.reader.expect(TYPE.ENC)
    const ct = msg.payload
    if (ct.byteLength < 17) throw new Error('secret channel: frame too short')
    let pt
    try {
      pt = this._aead(this.key, this.rxNonce).decrypt(ct)
    } catch {
      throw new Error('secret channel: frame failed to authenticate')
    }
    this._bump(this.rxNonce)
    return { type: pt[0], payload: b4a.from(pt.subarray(1)) }
  }

  async expect (type) {
    const m = await this.recv()
    if (m.type !== type) throw new Error('protocol error: expected type ' + type + ' got ' + m.type)
    return m
  }
}

// CPace then an ISK-keyed SecretChannel: the standard way both entries open
// the authenticated, end-to-end-encrypted session.
async function secureChannel (sock, reader, passphrase, sid, isInitiator) {
  const isk = await runCPace(sock, reader, passphrase, sid, isInitiator)
  return new SecretChannel(sock, reader, isk, isInitiator)
}

// ---------------------------------------------------------------------------
// manifest encoding (JSON header; per-chunk leaves are small vs the payload)
// ---------------------------------------------------------------------------

function encodeManifest (m) {
  return b4a.from(JSON.stringify({
    name: m.name,
    size: m.size,
    chunkSize: m.chunkSize,
    totalChunks: m.totalChunks,
    merkleRoot: b4a.toString(m.merkleRoot, 'hex'),
    provider: b4a.toString(m.provider, 'hex'),
    leaves: m.leaves.map(l => b4a.toString(l, 'hex'))
  }))
}

function decodeManifest (payload) {
  const o = JSON.parse(b4a.toString(payload))
  return {
    name: o.name,
    size: o.size,
    chunkSize: o.chunkSize,
    totalChunks: o.totalChunks,
    merkleRoot: b4a.from(o.merkleRoot, 'hex'),
    provider: b4a.from(o.provider, 'hex'),
    leaves: o.leaves.map(h => b4a.from(h, 'hex'))
  }
}

function computeManifest (name, buf, chunkSize) {
  const totalChunks = Math.max(1, Math.ceil(buf.byteLength / chunkSize))
  const leaves = []
  for (let i = 0; i < totalChunks; i++) {
    const chunk = buf.subarray(i * chunkSize, Math.min(buf.byteLength, (i + 1) * chunkSize))
    leaves.push(crypto.data(chunk))
  }
  const merkleRoot = crypto.hash(b4a.concat(leaves))
  return { name, size: buf.byteLength, chunkSize, totalChunks, merkleRoot, leaves }
}

// The rendezvous keypair both sides derive from the passphrase. Byte-identical
// to hyperdht's DHT.keyPair(topic) (both are crypto_sign_seed_keypair), which
// lets the browser derive it without hyperdht.
function rendezvous (passphrase) {
  const topic = topicFromPassphrase(passphrase)
  const keyPair = crypto.keyPair(b4a.from(topic))
  const sid = b4a.from(topic.subarray(0, 16))
  return { topic, keyPair, sid }
}

// ---------------------------------------------------------------------------
// passphrase generation
// ---------------------------------------------------------------------------

const WORDS = [
  'amber', 'brave', 'cedar', 'delta', 'ember', 'flint', 'grove', 'harbor',
  'ivory', 'jade', 'koala', 'lunar', 'maple', 'nimbus', 'onyx', 'pixel',
  'quartz', 'raven', 'sable', 'topaz', 'umber', 'violet', 'willow', 'xenon',
  'yarrow', 'zephyr', 'copper', 'basalt', 'cobalt', 'dahlia', 'falcon', 'garnet'
]

function randomPassphrase () {
  const sodium = require('sodium-universal')
  const idx = b4a.alloc(4)
  const parts = []
  for (let i = 0; i < 4; i++) {
    sodium.randombytes_buf(idx)
    parts.push(WORDS[readU32(idx, 0) % WORDS.length])
  }
  return parts.join('-')
}

module.exports = {
  DEFAULT_CHUNK_SIZE,
  TYPE,
  u32be,
  readU32,
  writeMsg,
  MessageReader,
  runCPace,
  SecretChannel,
  secureChannel,
  encodeManifest,
  decodeManifest,
  computeManifest,
  rendezvous,
  randomPassphrase
}
