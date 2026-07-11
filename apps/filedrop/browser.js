// filedrop/browser — the same wire protocol, storage in memory, transport via
// any hyperdht-compatible node (in practice @hyperswarm/dht-relay through a
// websocket gateway; also works over a real hyperdht node under Node, which
// is how the integration tests exercise it).
//
// Two deliberate differences from the Node entry:
// - no resume sidecar: the payload lives in memory, a dropped transfer
//   restarts from chunk 0 (the protocol's RESUME message is sent with 0)
// - no server-side firewall: dht-relay does not forward custom firewall
//   functions; CPace key confirmation remains the actual auth gate — a wrong
//   passphrase still aborts before any file byte moves

const b4a = require('b4a')
const crypto = require('hypercore-crypto')
const rm = require('retrieval-market')
const {
  DEFAULT_CHUNK_SIZE,
  TYPE,
  u32be,
  readU32,
  MessageReader,
  secureChannel,
  encodeManifest,
  decodeManifest,
  computeManifest,
  rendezvous,
  randomPassphrase
} = require('./protocol')

// createSender(node, { name, data, passphrase?, chunkSize?, onProgress?, onConnection? })
// -> { passphrase, publicKey, size, totalChunks, merkleRoot, finished, listen(), close() }
function createSender (node, opts = {}) {
  if (!node) throw new Error('a DHT-compatible node is required')
  const name = opts.name || 'file.bin'
  const data = b4a.from(opts.data)
  const chunkSize = opts.chunkSize || DEFAULT_CHUNK_SIZE
  const passphrase = opts.passphrase || randomPassphrase()
  const onProgress = opts.onProgress || (() => {})

  const manifest = computeManifest(name, data, chunkSize)
  const provider = rm.keyPair()
  manifest.provider = provider.publicKey

  const { keyPair, sid } = rendezvous(passphrase)

  let resolveFinished
  const finished = new Promise((resolve) => { resolveFinished = resolve })

  const server = node.createServer(onconnection)

  async function onconnection (sock) {
    if (opts.onConnection) opts.onConnection(sock)
    const reader = new MessageReader(sock)
    try {
      if ((await sock.opened) === false) throw new Error('sender socket failed to open')
      const ch = await secureChannel(sock, reader, passphrase, sid, true)

      await ch.send(TYPE.MANIFEST, encodeManifest(manifest))
      const resume = await ch.expect(TYPE.RESUME)
      const fromChunk = JSON.parse(b4a.toString(resume.payload)).fromChunk | 0

      for (let i = fromChunk; i < manifest.totalChunks; i++) {
        const chunk = data.subarray(i * chunkSize, Math.min(data.byteLength, (i + 1) * chunkSize))
        await ch.send(TYPE.CHUNK, b4a.concat([u32be(i), chunk]))
        onProgress({ side: 'send', chunk: i + 1, totalChunks: manifest.totalChunks })
      }
      await ch.send(TYPE.DONE)

      const receiptMsg = await ch.expect(TYPE.RECEIPT)
      const signed = rm.decodeReceipt(receiptMsg.payload)
      const ok = rm.verifyReceipt(signed) &&
        b4a.equals(signed.channel, manifest.merkleRoot) &&
        signed.bytes === manifest.size &&
        b4a.equals(signed.provider, provider.publicKey)
      if (!ok) throw new Error('invalid proof-of-receipt from receiver')

      resolveFinished({ receipt: signed, bytes: signed.bytes, fileHash: manifest.merkleRoot, consumer: signed.consumer })
      reader.destroy()
      sock.end()
    } catch (err) {
      // keep listening so the receiver can retry on a fresh connection
      reader.destroy()
      if (!sock.destroyed) sock.destroy()
    }
  }

  return {
    passphrase,
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

// receive(node, passphrase, { onProgress?, onConnection? })
// -> { name, data (Uint8Array), bytes, fileHash, receipt }
async function receive (node, passphrase, opts = {}) {
  if (!node) throw new Error('a DHT-compatible node is required')
  const onProgress = opts.onProgress || (() => {})

  const { keyPair, sid } = rendezvous(passphrase)

  const sock = node.connect(keyPair.publicKey, { keyPair })
  if (opts.onConnection) opts.onConnection(sock)
  const reader = new MessageReader(sock)

  try {
    if ((await sock.opened) === false) throw new Error('receiver socket failed to open')
    const ch = await secureChannel(sock, reader, passphrase, sid, false)

    const manifest = decodeManifest((await ch.expect(TYPE.MANIFEST)).payload)
    const consumer = rm.keyPair()
    const chunks = new Array(manifest.totalChunks)
    let bytes = 0
    let verified = 0

    await ch.send(TYPE.RESUME, b4a.from(JSON.stringify({ fromChunk: 0 })))

    while (true) {
      const msg = await ch.recv()
      if (msg.type === TYPE.DONE) break
      if (msg.type !== TYPE.CHUNK) throw new Error('protocol error: expected CHUNK/DONE got ' + msg.type)

      const index = readU32(msg.payload, 0)
      const chunk = msg.payload.subarray(4)
      if (index !== verified) throw new Error('out-of-order chunk ' + index + ' expected ' + verified)
      if (!b4a.equals(crypto.data(chunk), manifest.leaves[index])) {
        throw new Error('chunk ' + index + ' failed leaf verification')
      }

      chunks[index] = b4a.from(chunk)
      bytes += chunk.byteLength
      verified += 1
      onProgress({ side: 'receive', chunk: verified, totalChunks: manifest.totalChunks, bytes, size: manifest.size, name: manifest.name, socket: sock })
    }

    if (verified !== manifest.totalChunks) throw new Error('DONE before all chunks received')
    if (bytes !== manifest.size) throw new Error('size mismatch: got ' + bytes + ' want ' + manifest.size)

    const data = b4a.concat(chunks)
    const check = computeManifest(manifest.name, data, manifest.chunkSize)
    if (!b4a.equals(check.merkleRoot, manifest.merkleRoot)) throw new Error('assembled file failed merkle-root verification')

    const receipt = rm.createReceipt({
      provider: manifest.provider,
      consumer: consumer.publicKey,
      channel: manifest.merkleRoot,
      bytes: manifest.size,
      sequence: 1
    })
    const signed = rm.signReceipt(receipt, consumer.secretKey)
    await ch.send(TYPE.RECEIPT, rm.encodeReceipt(signed))

    reader.destroy()
    sock.end()
    return { name: manifest.name, data, bytes: manifest.size, fileHash: manifest.merkleRoot, receipt: signed }
  } catch (err) {
    reader.destroy()
    if (!sock.destroyed) sock.destroy()
    throw err
  }
}

module.exports = { createSender, receive, randomPassphrase, DEFAULT_CHUNK_SIZE }
