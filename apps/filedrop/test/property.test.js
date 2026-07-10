// Cheap (no-network) property + fuzz tests for filedrop's building blocks:
//   - the merkle manifest binds every byte (any flip changes a leaf + the root)
//   - the framing / MessageReader recovers exact message boundaries regardless
//     of how the byte stream is chopped into 'data' events
//   - a signed receipt binds the byte count + file hash, and a tamper to ANY
//     field (bytes, channel, provider, consumer, signature) fails verification
//
// Everything is driven by a SEEDED prng so a failure reproduces exactly.
// Hundreds of iterations each, since none of these touch the network.

const test = require('brittle')
const b4a = require('b4a')
const { EventEmitter } = require('events')
const crypto = require('hypercore-crypto')
const rm = require('retrieval-market')

const {
  computeManifest,
  MessageReader,
  u32be,
  TYPE
} = require('..')

// ---------------------------------------------------------------------------
// seeded PRNG (xorshift32) — deterministic bytes + ints for reproducibility
// ---------------------------------------------------------------------------
const SEED = (process.env.FILEDROP_SEED ? (parseInt(process.env.FILEDROP_SEED, 10) >>> 0) : 0x9e3779b1) || 1

function makePRNG (seed) {
  let s = seed >>> 0 || 1
  const next = () => {
    s ^= s << 13; s >>>= 0
    s ^= s >>> 17; s >>>= 0
    s ^= s << 5; s >>>= 0
    return s >>> 0
  }
  return {
    u32: next,
    int: (n) => next() % n,
    fill: (buf) => { for (let i = 0; i < buf.byteLength; i++) buf[i] = next() & 0xff; return buf }
  }
}

function frameOf (type, payload) {
  if (!payload) payload = b4a.alloc(0)
  return b4a.concat([u32be(1 + payload.byteLength), b4a.from([type & 0xff]), payload])
}

// ---------------------------------------------------------------------------
test('property: manifest binds every byte — leaves + root reconstruct, any flip is detected', function (t) {
  t.comment('seed=' + SEED)
  const rng = makePRNG(SEED)
  const chunkSizes = [1, 2, 7, 64, 4096, 64 * 1024]
  const edgeSizes = [0, 1, 2, 63, 64, 65, 4095, 4096, 4097]

  let checked = 0
  for (let iter = 0; iter < 300; iter++) {
    const chunkSize = chunkSizes[rng.int(chunkSizes.length)]
    const size = iter < edgeSizes.length * chunkSizes.length
      ? edgeSizes[iter % edgeSizes.length]
      : rng.int(20000)
    const buf = rng.fill(b4a.alloc(size))

    const m = computeManifest('f' + iter, buf, chunkSize)

    // structural invariants
    if (m.size !== size) t.fail('size mismatch ' + m.size + '!=' + size)
    const wantChunks = Math.max(1, Math.ceil(size / chunkSize))
    if (m.totalChunks !== wantChunks) t.fail('totalChunks ' + m.totalChunks + '!=' + wantChunks)
    if (m.leaves.length !== wantChunks) t.fail('leaves length mismatch')

    // every leaf independently recomputes, and the root is hash(concat(leaves))
    for (let i = 0; i < m.totalChunks; i++) {
      const chunk = buf.subarray(i * chunkSize, Math.min(size, (i + 1) * chunkSize))
      if (!b4a.equals(crypto.data(chunk), m.leaves[i])) t.fail('leaf ' + i + ' does not recompute')
    }
    if (!b4a.equals(crypto.hash(b4a.concat(m.leaves)), m.merkleRoot)) t.fail('root != hash(leaves)')

    // tamper: flipping any single byte must change the merkle root
    if (size > 0) {
      const pos = rng.int(size)
      const tampered = b4a.from(buf)
      tampered[pos] ^= (1 << rng.int(8))
      const m2 = computeManifest('f' + iter, tampered, chunkSize)
      if (b4a.equals(m2.merkleRoot, m.merkleRoot)) t.fail('flip at ' + pos + ' left root unchanged')
    }
    checked++
  }
  t.is(checked, 300, 'ran 300 manifest property iterations')
  t.pass('all manifest invariants held')
})

// ---------------------------------------------------------------------------
test('fuzz: MessageReader recovers exact frame boundaries under arbitrary stream splits', async function (t) {
  t.comment('seed=' + SEED)
  const rng = makePRNG(SEED ^ 0x55555555)

  for (let iter = 0; iter < 300; iter++) {
    const n = 1 + rng.int(12)
    const msgs = []
    const frames = []
    for (let k = 0; k < n; k++) {
      const type = 1 + rng.int(200)
      const plen = rng.int(320) // includes 0-length payloads (DONE-style)
      const payload = rng.fill(b4a.alloc(plen))
      msgs.push({ type, payload })
      frames.push(frameOf(type, payload))
    }
    const whole = b4a.concat(frames)

    const sock = new EventEmitter()
    const reader = new MessageReader(sock)

    // chop the byte stream into random-sized 'data' events — including splits
    // landing inside a 4-byte length prefix and 1-byte dribbles.
    let off = 0
    while (off < whole.byteLength) {
      const take = 1 + rng.int(rng.int(4) === 0 ? 2 : 40)
      sock.emit('data', b4a.from(whole.subarray(off, Math.min(whole.byteLength, off + take))))
      off += take
    }

    for (let k = 0; k < n; k++) {
      const got = await reader.read()
      if (got.type !== msgs[k].type) t.fail('iter ' + iter + ' msg ' + k + ' type ' + got.type + '!=' + msgs[k].type)
      if (!b4a.equals(got.payload, msgs[k].payload)) t.fail('iter ' + iter + ' msg ' + k + ' payload mismatch')
    }
    reader.destroy()
  }
  t.pass('300 framing fuzz iterations recovered every message exactly')
})

// ---------------------------------------------------------------------------
test('property: receipt binds bytes+hash; tampering ANY field fails verification', function (t) {
  t.comment('seed=' + SEED)
  const rng = makePRNG(SEED ^ 0x0f0f0f0f)

  for (let iter = 0; iter < 300; iter++) {
    const provider = rng.fill(b4a.alloc(32))
    const channel = rng.fill(b4a.alloc(32)) // stands in for the file merkle root
    const bytes = rng.int(1 << 30)
    const consumer = rm.keyPair(rng.fill(b4a.alloc(32)))

    const receipt = rm.createReceipt({ provider, consumer: consumer.publicKey, channel, bytes, sequence: 1 })
    const signed = rm.signReceipt(receipt, consumer.secretKey)

    if (!rm.verifyReceipt(signed)) t.fail('honest receipt failed to verify (iter ' + iter + ')')

    // the receipt actually binds these values
    if (signed.bytes !== bytes) t.fail('bytes not bound')
    if (!b4a.equals(signed.channel, channel)) t.fail('channel(hash) not bound')

    // encode/decode roundtrip still verifies + preserves fields
    const dec = rm.decodeReceipt(rm.encodeReceipt(signed))
    if (!rm.verifyReceipt(dec)) t.fail('decoded receipt failed to verify')
    if (dec.bytes !== bytes || !b4a.equals(dec.channel, channel)) t.fail('roundtrip lost binding')

    // tamper each field independently -> must fail
    if (rm.verifyReceipt({ ...signed, bytes: signed.bytes + 1 + rng.int(1000) })) t.fail('bytes tamper verified')
    if (rm.verifyReceipt({ ...signed, channel: flip(channel, rng) })) t.fail('channel tamper verified')
    if (rm.verifyReceipt({ ...signed, provider: flip(provider, rng) })) t.fail('provider tamper verified')
    if (rm.verifyReceipt({ ...signed, consumer: flip(signed.consumer, rng) })) t.fail('consumer tamper verified')
    if (rm.verifyReceipt({ ...signed, signature: flip(signed.signature, rng) })) t.fail('signature tamper verified')
    if (rm.verifyReceipt({ ...signed, sequence: signed.sequence + 1 })) t.fail('sequence tamper verified')
  }
  t.pass('300 receipt property iterations: honest verifies, every tamper rejected')
})

function flip (buf, rng) {
  const out = b4a.from(buf)
  out[rng.int(out.byteLength)] ^= (1 << rng.int(8))
  return out
}
