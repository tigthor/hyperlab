// filedrop — encrypted serverless file-drop over the DHT.
//
// A sender prints a human passphrase; a receiver on another node connects
// directly over the DHT (rendezvous keypair seeded from the passphrase). The
// connection is authenticated with CPace (hyperbeam-pake) so a wrong
// passphrase aborts before any file bytes move — the Noise keypair alone is
// low-entropy (passphrase-derived) and would be MITM-able; CPace's key
// confirmation is the real auth gate. The file is chunked, each chunk verified
// against the manifest's per-chunk BLAKE2b leaf, the transfer is resumable
// after a mid-stream kill (receiver persists a byte/chunk offset sidecar), and
// on completion the receiver signs a retrieval-market receipt binding the byte
// count and file hash, which the sender verifies as proof-of-receipt.

const fs = require('fs')
const path = require('path')
const b4a = require('b4a')
const DHT = require('hyperdht')
const crypto = require('hypercore-crypto')
const rm = require('retrieval-market')
const { CPace, topicFromPassphrase } = require('hyperbeam-pake')

const DEFAULT_CHUNK_SIZE = 64 * 1024

const TYPE = {
  PAKE: 1,
  CONFIRM: 2,
  MANIFEST: 3,
  RESUME: 4,
  CHUNK: 5,
  DONE: 6,
  RECEIPT: 7
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

// ---------------------------------------------------------------------------
// SENDER
// ---------------------------------------------------------------------------

// createSender(file, { node, passphrase?, chunkSize?, onProgress?, relayThrough?, onConnection? })
// Stands up a DHT server pinned to the passphrase-derived rendezvous keypair,
// authenticates each incoming connection with CPace, streams the file, and
// resolves `finished` with the verified signed receipt. Stays listening across
// reconnects so a killed transfer can resume on a fresh connection.
//
// relayThrough (32-byte key or array of keys) names blind-relay node(s): the
// connection races direct holepunch vs relay and upgrades to direct when the
// punch succeeds, so symmetric-NAT peers still connect instead of failing.
function createSender (file, opts = {}) {
  const node = opts.node
  if (!node) throw new Error('opts.node (a DHT node) is required')
  const chunkSize = opts.chunkSize || DEFAULT_CHUNK_SIZE
  const passphrase = opts.passphrase || randomPassphrase()
  const onProgress = opts.onProgress || (() => {})
  const onConnection = opts.onConnection || (() => {})

  const buf = b4a.from(fs.readFileSync(file))
  const name = path.basename(file)
  const manifest = computeManifest(name, buf, chunkSize)
  const provider = rm.keyPair()
  manifest.provider = provider.publicKey

  const topic = topicFromPassphrase(passphrase)
  const keyPair = DHT.keyPair(topic)
  const sid = b4a.from(topic.subarray(0, 16))

  let resolveFinished
  const finished = new Promise((resolve) => { resolveFinished = resolve })
  let settled = false

  const server = node.createServer({
    relayThrough: opts.relayThrough || null,
    // relay-only privacy mode: holepunch=false + shareLocalAddress=false means
    // the peer only ever sees the relay's address, never ours
    holepunch: opts.holepunch === false ? false : undefined,
    shareLocalAddress: opts.shareLocalAddress === false ? false : undefined,
    firewall (remotePublicKey) {
      // Only accept the peer connecting with our own rendezvous keypair.
      return !b4a.equals(remotePublicKey, keyPair.publicKey)
    }
  }, onconnection)

  async function onconnection (sock) {
    onConnection(sock)
    const reader = new MessageReader(sock)
    try {
      if ((await sock.opened) === false) throw new Error('sender socket failed to open')
      await runCPace(sock, reader, passphrase, sid, true)

      await writeMsg(sock, TYPE.MANIFEST, encodeManifest(manifest))
      const resume = await reader.expect(TYPE.RESUME)
      const fromChunk = JSON.parse(b4a.toString(resume.payload)).fromChunk | 0

      for (let i = fromChunk; i < manifest.totalChunks; i++) {
        const chunk = buf.subarray(i * chunkSize, Math.min(buf.byteLength, (i + 1) * chunkSize))
        await writeMsg(sock, TYPE.CHUNK, b4a.concat([u32be(i), chunk]))
        onProgress({ side: 'send', chunk: i + 1, totalChunks: manifest.totalChunks })
      }
      await writeMsg(sock, TYPE.DONE)

      const receiptMsg = await reader.expect(TYPE.RECEIPT)
      const signed = rm.decodeReceipt(receiptMsg.payload)
      const ok = rm.verifyReceipt(signed) &&
        b4a.equals(signed.channel, manifest.merkleRoot) &&
        signed.bytes === manifest.size &&
        b4a.equals(signed.provider, provider.publicKey)
      if (!ok) throw new Error('invalid proof-of-receipt from receiver')

      settled = true
      resolveFinished({ receipt: signed, bytes: signed.bytes, fileHash: manifest.merkleRoot, consumer: signed.consumer })
      reader.destroy()
      sock.end()
    } catch (err) {
      // A mid-transfer socket failure is not fatal: keep the server up so the
      // receiver can reconnect and resume. Only surface errors once settled
      // never happens (the caller can time out).
      reader.destroy()
      if (!sock.destroyed) sock.destroy()
    }
  }

  return {
    passphrase,
    topic,
    publicKey: keyPair.publicKey,
    provider: provider.publicKey,
    merkleRoot: manifest.merkleRoot,
    size: manifest.size,
    totalChunks: manifest.totalChunks,
    finished,
    async listen () {
      await server.listen(keyPair)
      return keyPair.publicKey
    },
    async close () {
      await server.close()
    }
  }
}

// ---------------------------------------------------------------------------
// RECEIVER
// ---------------------------------------------------------------------------

// receive(passphrase, outdir, { node, onProgress?, relayThrough?, onConnection? })
// Connects to the passphrase-derived rendezvous keypair, authenticates with
// CPace (rejects on a wrong passphrase before any file byte is read), then
// pulls chunks — each verified against the manifest leaf — into `<name>.part`,
// persisting a `<name>.filedrop.json` sidecar (byte/chunk offset + a stable
// consumer identity) so a kill can resume. On DONE it re-verifies the whole
// file hash, renames into place, signs a retrieval-market receipt, and sends
// it back. Resolves { path, bytes, fileHash, receipt }.
//
// onProgress({ side, chunk, totalChunks, bytes, socket }) is called after each
// verified chunk; a test can destroy `socket` from it to simulate a kill.
async function receive (passphrase, outdir, opts = {}) {
  const node = opts.node
  if (!node) throw new Error('opts.node (a DHT node) is required')
  const onProgress = opts.onProgress || (() => {})

  const topic = topicFromPassphrase(passphrase)
  const keyPair = DHT.keyPair(topic)
  const sid = b4a.from(topic.subarray(0, 16))

  const sock = node.connect(keyPair.publicKey, {
    keyPair,
    relayThrough: opts.relayThrough || null,
    holepunch: opts.holepunch === false ? () => false : undefined,
    localConnection: opts.localConnection === false ? false : undefined
  })
  if (opts.onConnection) opts.onConnection(sock)
  const reader = new MessageReader(sock)
  let fd = null

  try {
    if ((await sock.opened) === false) throw new Error('receiver socket failed to open')
    await runCPace(sock, reader, passphrase, sid, false)

    const manifest = decodeManifest((await reader.expect(TYPE.MANIFEST)).payload)
    fs.mkdirSync(outdir, { recursive: true })
    const partPath = path.join(outdir, manifest.name + '.part')
    const sidecarPath = path.join(outdir, manifest.name + '.filedrop.json')
    const finalPath = path.join(outdir, manifest.name)

    // Load or initialise the resume sidecar (verified chunk count, byte offset,
    // and a persisted consumer identity so a resumed receipt keeps one signer).
    let state = loadSidecar(sidecarPath, manifest)
    // Self-heal: truncate the .part to the durably-recorded byte offset so a
    // sidecar that outran the file (or vice versa) cannot corrupt the resume.
    if (fs.existsSync(partPath)) fs.truncateSync(partPath, state.bytes)
    else { fs.writeFileSync(partPath, b4a.alloc(0)); state.bytes = 0; state.verified = 0 }

    const consumer = rm.keyPair(b4a.from(state.consumerSeed, 'hex'))
    fd = fs.openSync(partPath, 'r+')

    await writeMsg(sock, TYPE.RESUME, b4a.from(JSON.stringify({ fromChunk: state.verified })))

    while (true) {
      const msg = await reader.read()
      if (msg.type === TYPE.DONE) break
      if (msg.type !== TYPE.CHUNK) throw new Error('protocol error: expected CHUNK/DONE got ' + msg.type)

      const index = readU32(msg.payload, 0)
      const chunk = msg.payload.subarray(4)
      if (index !== state.verified) throw new Error('out-of-order chunk ' + index + ' expected ' + state.verified)
      if (!b4a.equals(crypto.data(chunk), manifest.leaves[index])) {
        throw new Error('chunk ' + index + ' failed leaf verification')
      }

      fs.writeSync(fd, chunk, 0, chunk.byteLength, state.bytes)
      fs.fsyncSync(fd)
      state.bytes += chunk.byteLength
      state.verified += 1
      saveSidecar(sidecarPath, state)
      onProgress({ side: 'receive', chunk: state.verified, totalChunks: manifest.totalChunks, bytes: state.bytes, socket: sock })
    }

    fs.closeSync(fd); fd = null

    if (state.verified !== manifest.totalChunks) throw new Error('DONE before all chunks received')
    if (state.bytes !== manifest.size) throw new Error('size mismatch: got ' + state.bytes + ' want ' + manifest.size)

    // Full re-verification of the assembled file against the manifest root.
    const full = b4a.from(fs.readFileSync(partPath))
    const check = computeManifest(manifest.name, full, manifest.chunkSize)
    if (!b4a.equals(check.merkleRoot, manifest.merkleRoot)) throw new Error('assembled file failed merkle-root verification')

    fs.renameSync(partPath, finalPath)
    fs.unlinkSync(sidecarPath)

    // Proof-of-receipt: sign "received <size> bytes of file-hash <root>".
    const receipt = rm.createReceipt({
      provider: manifest.provider,
      consumer: consumer.publicKey,
      channel: manifest.merkleRoot,
      bytes: manifest.size,
      sequence: 1
    })
    const signed = rm.signReceipt(receipt, consumer.secretKey)
    await writeMsg(sock, TYPE.RECEIPT, rm.encodeReceipt(signed))

    reader.destroy()
    sock.end()
    return { path: finalPath, bytes: manifest.size, fileHash: manifest.merkleRoot, receipt: signed }
  } catch (err) {
    if (fd !== null) { try { fs.closeSync(fd) } catch {} }
    reader.destroy()
    if (!sock.destroyed) sock.destroy()
    throw err
  }
}

function loadSidecar (sidecarPath, manifest) {
  if (fs.existsSync(sidecarPath)) {
    const o = JSON.parse(fs.readFileSync(sidecarPath, 'utf8'))
    // Guard against a sidecar for a different file at the same name.
    if (o.merkleRoot === b4a.toString(manifest.merkleRoot, 'hex')) return o
  }
  const seed = b4a.alloc(32)
  require('sodium-universal').randombytes_buf(seed)
  return {
    name: manifest.name,
    merkleRoot: b4a.toString(manifest.merkleRoot, 'hex'),
    verified: 0,
    bytes: 0,
    consumerSeed: b4a.toString(seed, 'hex')
  }
}

function saveSidecar (sidecarPath, state) {
  const tmp = sidecarPath + '.tmp'
  fs.writeFileSync(tmp, JSON.stringify(state))
  fs.renameSync(tmp, sidecarPath)
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

// send(file, opts): convenience — listen then resolve with the verified
// receipt (server closes afterward).
async function send (file, opts = {}) {
  const sender = createSender(file, opts)
  await sender.listen()
  const result = await sender.finished
  await sender.close()
  return result
}

module.exports = {
  createSender,
  send,
  receive,
  randomPassphrase,
  computeManifest,
  // protocol primitives, exported so an adversary/MITM can be simulated in tests
  MessageReader,
  writeMsg,
  runCPace,
  u32be,
  readU32,
  DEFAULT_CHUNK_SIZE,
  TYPE
}
