const test = require('brittle')
const b4a = require('b4a')
const c = require('compact-encoding')

const rm = require('..')

// ---------------------------------------------------------------------------
// Seeded PRNG (mulberry32) so every failure below is reproducible: bump SEED
// or read it off the failing assertion message to replay an exact iteration.
// ---------------------------------------------------------------------------
const SEED = 0x9e3779b9

function prng (seed) {
  let s = seed >>> 0
  return function () {
    s = (s + 0x6d2b79f5) | 0
    let t = Math.imul(s ^ (s >>> 15), 1 | s)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function randBytes (rand, n) {
  const b = b4a.alloc(n)
  for (let i = 0; i < n; i++) b[i] = (rand() * 256) | 0
  return b
}

function randInt (rand, max) {
  return Math.floor(rand() * max)
}

// A different non-negative safe integer than `orig` in [0, max).
function otherInt (rand, orig, max) {
  let v = randInt(rand, max)
  if (v === orig) v = orig === 0 ? 1 : orig - 1
  return v
}

// A 32-byte buffer guaranteed distinct from `orig`.
function otherBytes (rand, orig) {
  let b = randBytes(rand, 32)
  while (b4a.equals(b, orig)) b = randBytes(rand, 32)
  return b
}

// Fisher-Yates shuffle in place using the seeded prng.
function shuffle (rand, arr) {
  const a = arr.slice()
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1))
    const t = a[i]; a[i] = a[j]; a[j] = t
  }
  return a
}

// A fully random honest signed receipt plus the keypairs behind it.
function randomSigned (rand) {
  const consumer = rm.keyPair(randBytes(rand, 32))
  const provider = rm.keyPair(randBytes(rand, 32))
  const channel = randBytes(rand, 32)
  const receipt = rm.createReceipt({
    provider: provider.publicKey,
    consumer: consumer.publicKey,
    channel,
    bytes: randInt(rand, 2 ** 40),
    sequence: randInt(rand, 1e6),
    timestamp: randInt(rand, 2 ** 41),
    nonce: randBytes(rand, 32)
  })
  const signed = rm.signReceipt(receipt, consumer.secretKey)
  return { signed, consumer, provider, channel }
}

// ---------------------------------------------------------------------------
// PROPERTY: honest receipts verify TRUE; every single-field tamper verifies
// FALSE. Each tampered value is itself well-formed, so the ONLY reason the
// tamper is rejected is the cryptographic binding of that field — not an
// incidental encode error.
// ---------------------------------------------------------------------------
test('fuzz: honest receipts verify, every single-field tamper is rejected', function (t) {
  const rand = prng(SEED)
  const N = 300
  let honestOk = 0

  for (let i = 0; i < N; i++) {
    const { signed, provider } = randomSigned(rand)

    if (!rm.verifyReceipt(signed)) {
      t.fail('honest receipt failed to verify at iteration ' + i)
      continue
    }
    honestOk++

    // Each entry: a well-formed alternative value for exactly one signed field.
    const tampers = {
      version: { ...signed, version: signed.version + 1 },
      provider: { ...signed, provider: otherBytes(rand, signed.provider) },
      // consumer swapped to a random key: verify checks against the embedded
      // consumer, so the real signer's signature no longer matches.
      consumer: { ...signed, consumer: otherBytes(rand, signed.consumer) },
      channel: { ...signed, channel: otherBytes(rand, signed.channel) },
      bytes: { ...signed, bytes: otherInt(rand, signed.bytes, 2 ** 40) },
      sequence: { ...signed, sequence: otherInt(rand, signed.sequence, 1e6) },
      timestamp: { ...signed, timestamp: otherInt(rand, signed.timestamp, 2 ** 41) },
      nonce: { ...signed, nonce: otherBytes(rand, signed.nonce) }
    }

    for (const [field, bad] of Object.entries(tampers)) {
      if (rm.verifyReceipt(bad)) {
        t.fail('tampered ' + field + ' verified TRUE at iteration ' + i + ' (seed ' + SEED + ')')
      }
    }

    // Provider signing instead of consumer: a real signature by the wrong key.
    const wrongSigner = rm.signReceipt(signed, provider.secretKey)
    if (rm.verifyReceipt(wrongSigner)) t.fail('wrong-signer receipt verified at iteration ' + i)
  }

  t.is(honestOk, N, 'all ' + N + ' honest receipts verified')
  t.pass('no single-field tamper survived across ' + N + ' random receipts')
})

// ---------------------------------------------------------------------------
// PROPERTY: a single flipped bit ANYWHERE in the receipt body or the 64-byte
// signature destroys verification. Body bit-flips are exercised through the
// real wire codec: if the flip corrupts a varint length the decode throws
// (still a rejection); otherwise the decoded receipt must verify FALSE.
// ---------------------------------------------------------------------------
test('fuzz: any single flipped bit (body or signature) is rejected', function (t) {
  const rand = prng(SEED ^ 0x1234)
  const N = 250
  let checked = 0

  for (let i = 0; i < N; i++) {
    const { signed } = randomSigned(rand)

    // Signature bit-flip: always decodable, must verify false.
    const sig = b4a.from(signed.signature)
    const sBit = randInt(rand, sig.byteLength * 8)
    sig[sBit >> 3] ^= 1 << (sBit & 7)
    if (rm.verifyReceipt({ ...signed, signature: sig })) {
      t.fail('signature bit-flip ' + sBit + ' verified TRUE at iteration ' + i)
    }
    checked++

    // Body bit-flip via the wire.
    const buf = rm.encodeReceipt(signed)
    const bit = randInt(rand, buf.byteLength * 8)
    buf[bit >> 3] ^= 1 << (bit & 7)
    let decoded = null
    try {
      decoded = rm.decodeReceipt(buf)
    } catch {
      // corrupted framing -> rejected, that is acceptable
    }
    if (decoded !== null && rm.verifyReceipt(decoded)) {
      t.fail('wire bit-flip ' + bit + ' still verified TRUE at iteration ' + i)
    }
  }

  t.is(checked, N)
  t.pass('every single-bit corruption was rejected across ' + N + ' receipts')
})

// ---------------------------------------------------------------------------
// PROPERTY: cross-core / cross-channel replay. A receipt signed for channel A
// never verifies for channel B, and aggregate credits only the genuine
// channel — an attacker cannot re-point a valid receipt at another core.
// ---------------------------------------------------------------------------
test('fuzz: cross-core replay is rejected and never credited', function (t) {
  const rand = prng(SEED ^ 0xabcd)
  const N = 200

  for (let i = 0; i < N; i++) {
    const { signed, channel } = randomSigned(rand)
    const other = otherBytes(rand, channel)

    const replay = { ...signed, channel: other }
    if (rm.verifyReceipt(replay)) t.fail('channel replay verified at iteration ' + i)

    const { claims, totalBytes } = rm.aggregate([signed, replay], { strict: false })
    if (claims.length !== 1) t.fail('replay produced ' + claims.length + ' claims at iteration ' + i)
    if (!b4a.equals(claims[0].channel, channel)) t.fail('credited the wrong channel at iteration ' + i)
    if (totalBytes !== BigInt(signed.bytes)) t.fail('replay inflated total at iteration ' + i)
  }

  t.pass('no cross-core replay verified or was credited across ' + N + ' receipts')
})

// ---------------------------------------------------------------------------
// PROPERTY: ed25519 malleability. For a valid signature (R || S) with the
// canonical S < L, the non-canonical variant (R || S+L) encodes the same
// group element but MUST be rejected — otherwise a valid receipt would have a
// second distinct signature, breaking the "one signature per body" identity
// that equivocation detection and deduplication rely on.
// ---------------------------------------------------------------------------
test('fuzz: ed25519 (S+L) malleability is rejected', function (t) {
  const rand = prng(SEED ^ 0x5a5a)
  const L = 2n ** 252n + 27742317777372353535851937790883648493n
  const N = 200

  const readLE = (buf, off) => {
    let v = 0n
    for (let i = 0; i < 32; i++) v += BigInt(buf[off + i]) << (8n * BigInt(i))
    return v
  }
  const writeLE = (buf, off, v) => {
    for (let i = 0; i < 32; i++) buf[off + i] = Number((v >> (8n * BigInt(i))) & 0xffn)
  }

  for (let i = 0; i < N; i++) {
    const { signed } = randomSigned(rand)
    if (!rm.verifyReceipt(signed)) { t.fail('honest failed at iteration ' + i); continue }

    const sig = b4a.from(signed.signature)
    const S = readLE(sig, 32)
    const mal = b4a.from(sig) // R unchanged in [0,32)
    writeLE(mal, 32, S + L) // S -> S + L, still 32 bytes since S < L

    if (b4a.equals(mal, sig)) { t.fail('malleated signature identical at iteration ' + i); continue }
    if (mal.byteLength !== 64) { t.fail('malleated signature wrong length at iteration ' + i); continue }
    if (!b4a.equals(mal.subarray(0, 32), sig.subarray(0, 32))) t.fail('R changed at iteration ' + i)

    if (rm.verifyReceipt({ ...signed, signature: mal })) {
      t.fail('non-canonical (S+L) signature verified TRUE at iteration ' + i + ' (seed ' + SEED + ')')
    }
  }

  t.pass('all ' + N + ' (S+L) malleated signatures rejected')
})

// ---------------------------------------------------------------------------
// PROPERTY: aggregate is order-independent for honest receipts. Over a random
// multiset of receipts (many channels, out-of-order sequences, dropped
// intermediates), the credited total and the per-channel winning claim are the
// same for every permutation. No equivocation is present, so nothing is
// excluded — only cumulative highest-sequence accounting decides the result.
// ---------------------------------------------------------------------------
test('fuzz: aggregate is order-independent for honest receipts', function (t) {
  const rand = prng(SEED ^ 0x0f0f)
  const ROUNDS = 40

  for (let round = 0; round < ROUNDS; round++) {
    // A small pool of channels, each with its own signer, so many receipts
    // share a channel and cumulative accounting actually matters.
    const pool = []
    const nChannels = 1 + randInt(rand, 5)
    for (let k = 0; k < nChannels; k++) {
      pool.push({
        consumer: rm.keyPair(randBytes(rand, 32)),
        provider: rm.keyPair(randBytes(rand, 32)),
        channel: randBytes(rand, 32),
        usedSeq: new Set()
      })
    }

    const receipts = []
    const nReceipts = 5 + randInt(rand, 40)
    for (let r = 0; r < nReceipts; r++) {
      const p = pool[randInt(rand, pool.length)]
      let seq = randInt(rand, 500)
      while (p.usedSeq.has(seq)) seq++ // keep (channel, sequence) unique -> honest
      p.usedSeq.add(seq)
      receipts.push(rm.signReceipt(rm.createReceipt({
        provider: p.provider.publicKey,
        consumer: p.consumer.publicKey,
        channel: p.channel,
        bytes: randInt(rand, 2 ** 40),
        sequence: seq
      }), p.consumer.secretKey))
    }

    // Independent expectation: per channel, the bytes of the highest sequence.
    const expected = new Map()
    for (const r of receipts) {
      const key = b4a.toString(r.provider, 'hex') + b4a.toString(r.consumer, 'hex') + b4a.toString(r.channel, 'hex')
      const cur = expected.get(key)
      if (!cur || r.sequence > cur.sequence) expected.set(key, { sequence: r.sequence, bytes: r.bytes })
    }
    let expectedTotal = 0n
    for (const v of expected.values()) expectedTotal += BigInt(v.bytes)

    let firstTotal = null
    let firstClaims = null
    for (let s = 0; s < 6; s++) {
      const { claims, totalBytes, equivocations, invalid } = rm.aggregate(shuffle(rand, receipts), { strict: false })
      if (invalid !== 0) t.fail('honest set flagged invalid in round ' + round)
      if (equivocations.length !== 0) t.fail('honest set flagged equivocation in round ' + round)
      if (totalBytes !== expectedTotal) t.fail('total ' + totalBytes + ' != expected ' + expectedTotal + ' round ' + round)
      if (claims.length !== expected.size) t.fail('claim count mismatch in round ' + round)

      // Canonical fingerprint of the claim set (channelKey -> bytes), sorted.
      const sig = claims
        .map(r => b4a.toString(r.provider, 'hex') + b4a.toString(r.consumer, 'hex') + b4a.toString(r.channel, 'hex') + ':' + r.bytes)
        .sort()
        .join('|')
      if (firstTotal === null) { firstTotal = totalBytes; firstClaims = sig }
      else {
        if (totalBytes !== firstTotal) t.fail('total varied by permutation in round ' + round)
        if (sig !== firstClaims) t.fail('claim set varied by permutation in round ' + round)
      }
    }
  }

  t.pass('aggregate produced identical results across all permutations in ' + ROUNDS + ' rounds')
})

// ---------------------------------------------------------------------------
// PROPERTY: same-sequence equivocation is detected order-independently and the
// offending channel is fully excluded from claims/total, regardless of where
// the conflicting receipts land in the input.
// ---------------------------------------------------------------------------
test('fuzz: same-sequence equivocation is detected and excluded (order-independent)', function (t) {
  const rand = prng(SEED ^ 0x7331)
  const ROUNDS = 60

  for (let round = 0; round < ROUNDS; round++) {
    // Honest background across a few clean channels.
    const honest = []
    let honestTotal = 0n
    const nClean = 1 + randInt(rand, 4)
    for (let k = 0; k < nClean; k++) {
      const consumer = rm.keyPair(randBytes(rand, 32))
      const provider = rm.keyPair(randBytes(rand, 32))
      const channel = randBytes(rand, 32)
      const bytes = randInt(rand, 2 ** 40)
      honest.push(rm.signReceipt(rm.createReceipt({
        provider: provider.publicKey, consumer: consumer.publicKey, channel, bytes, sequence: 1 + randInt(rand, 10)
      }), consumer.secretKey))
      honestTotal += BigInt(bytes)
    }

    // A dedicated equivocating channel: two DIFFERENT receipts at the same seq.
    const consumer = rm.keyPair(randBytes(rand, 32))
    const provider = rm.keyPair(randBytes(rand, 32))
    const channel = randBytes(rand, 32)
    const seq = randInt(rand, 100)
    const b1 = randInt(rand, 2 ** 40)
    const b2 = otherInt(rand, b1, 2 ** 40)
    const eqLow = rm.signReceipt(rm.createReceipt({ provider: provider.publicKey, consumer: consumer.publicKey, channel, bytes: b1, sequence: seq }), consumer.secretKey)
    const eqHigh = rm.signReceipt(rm.createReceipt({ provider: provider.publicKey, consumer: consumer.publicKey, channel, bytes: b2, sequence: seq }), consumer.secretKey)

    const all = [...honest, eqLow, eqHigh]

    let firstTotal = null
    for (let s = 0; s < 5; s++) {
      const { claims, totalBytes, equivocations } = rm.aggregate(shuffle(rand, all), { strict: false })

      if (equivocations.length !== 1) t.fail('expected exactly 1 equivocation, got ' + equivocations.length + ' round ' + round)
      else if (!b4a.equals(equivocations[0].channel, channel)) t.fail('wrong channel flagged in round ' + round)

      // The equivocating channel must never appear in the credited claims.
      for (const cl of claims) {
        if (b4a.equals(cl.channel, channel) && b4a.equals(cl.consumer, consumer.publicKey)) {
          t.fail('equivocating channel credited in round ' + round)
        }
      }
      if (totalBytes !== honestTotal) t.fail('equivocating bytes leaked into total: ' + totalBytes + ' != ' + honestTotal + ' round ' + round)

      if (firstTotal === null) firstTotal = totalBytes
      else if (totalBytes !== firstTotal) t.fail('equivocation outcome depended on order in round ' + round)
    }

    // Strict mode must refuse the whole batch.
    let threw = false
    try { rm.aggregate(all) } catch { threw = true }
    if (!threw) t.fail('strict aggregate accepted an equivocating batch in round ' + round)
  }

  t.pass('equivocation detected, excluded, and order-independent across ' + ROUNDS + ' rounds')
})

// ---------------------------------------------------------------------------
// PROPERTY: BigInt totals stay exact past 2^53. Summing many near-maximal
// byte counts as floats would silently lose precision; the aggregate total is
// a BigInt equal to an independently computed BigInt sum, bit for bit.
// ---------------------------------------------------------------------------
test('fuzz: BigInt totals never lose precision past 2^53', function (t) {
  const rand = prng(SEED ^ 0xdead)
  const ROUNDS = 60

  for (let round = 0; round < ROUNDS; round++) {
    const receipts = []
    let expected = 0n
    const k = 3 + randInt(rand, 8)
    for (let i = 0; i < k; i++) {
      const consumer = rm.keyPair(randBytes(rand, 32))
      const provider = rm.keyPair(randBytes(rand, 32))
      // bytes in [2^52, 2^53) so a handful already overruns the safe range.
      const bytes = 2 ** 52 + randInt(rand, 2 ** 52)
      receipts.push(rm.signReceipt(rm.createReceipt({
        provider: provider.publicKey, consumer: consumer.publicKey, channel: randBytes(rand, 32), bytes, sequence: 1
      }), consumer.secretKey))
      expected += BigInt(bytes)
    }

    const { totalBytes, claims } = rm.aggregate(receipts)
    if (typeof totalBytes !== 'bigint') t.fail('totalBytes is not a BigInt in round ' + round)
    if (totalBytes !== expected) t.fail('BigInt total wrong in round ' + round + ': ' + totalBytes + ' != ' + expected)
    if (claims.length !== k) t.fail('claim count wrong in round ' + round)
    if (!(totalBytes > BigInt(Number.MAX_SAFE_INTEGER))) t.fail('total did not exceed 2^53 in round ' + round)
  }

  t.pass('BigInt totals were exact and beyond 2^53 across ' + ROUNDS + ' rounds')
})

// ---------------------------------------------------------------------------
// PROPERTY: decodeReceipt is an exact-length parse. A clean encoding round-
// trips; any trailing bytes (even one) are rejected; truncation is rejected.
// ---------------------------------------------------------------------------
test('fuzz: decodeReceipt rejects trailing bytes and truncation', function (t) {
  const rand = prng(SEED ^ 0xbeef)
  const N = 250

  for (let i = 0; i < N; i++) {
    const { signed } = randomSigned(rand)
    const buf = rm.encodeReceipt(signed)

    t.alike(rm.decodeReceipt(buf), signed, i === 0 ? 'clean encoding round-trips' : undefined)

    // Trailing garbage of random length must throw.
    const extra = randBytes(rand, 1 + randInt(rand, 8))
    let threw = false
    try { rm.decodeReceipt(b4a.concat([buf, extra])) } catch { threw = true }
    if (!threw) t.fail('trailing bytes accepted at iteration ' + i)

    // Truncation must throw (never return a bogus receipt).
    const cut = 1 + randInt(rand, buf.byteLength)
    let threwCut = false
    try {
      const r = rm.decodeReceipt(buf.subarray(0, cut))
      // If it somehow decoded a shorter buffer, that is only OK when the cut is
      // exactly the full length (cut === buf.byteLength).
      if (cut !== buf.byteLength) t.fail('truncated buffer decoded at iteration ' + i + ' cut ' + cut)
      else t.alike(r, signed)
    } catch { threwCut = true }
    if (!threwCut && cut !== buf.byteLength) t.fail('truncated buffer did not throw at iteration ' + i)
  }

  t.pass('exact-length decode held across ' + N + ' receipts')
})

// ---------------------------------------------------------------------------
// PROPERTY: hostile / malformed inputs never crash verify, decode, or
// aggregate. verifyReceipt returns a boolean; decodeReceipt either returns an
// object or throws; aggregate(lax) drops junk and still totals the good ones.
// ---------------------------------------------------------------------------
test('fuzz: malformed and hostile inputs never crash', function (t) {
  const rand = prng(SEED ^ 0xc0de)
  const N = 400

  for (let i = 0; i < N; i++) {
    // Random garbage buffer through the decoder: must never crash the process.
    const junkBuf = randBytes(rand, randInt(rand, 200))
    try {
      const r = rm.decodeReceipt(junkBuf)
      // If it decoded, verify must still be a boolean and not throw.
      const v = rm.verifyReceipt(r)
      if (typeof v !== 'boolean') t.fail('verify returned non-boolean at iteration ' + i)
    } catch {
      // throwing on malformed bytes is fine
    }

    // Random hostile object through verify: always a boolean, never a throw.
    const hostile = pickHostile(rand, i)
    let v
    try { v = rm.verifyReceipt(hostile) } catch (e) { t.fail('verifyReceipt threw on hostile input at iteration ' + i + ': ' + e.message); v = false }
    if (typeof v !== 'boolean') t.fail('verifyReceipt returned non-boolean at iteration ' + i)
    if (v === true) t.fail('hostile object verified TRUE at iteration ' + i)
  }

  // A mixed array of good + junk must aggregate (lax) without crashing.
  const good = []
  let goodTotal = 0n
  for (let k = 0; k < 5; k++) {
    const { signed } = randomSigned(rand)
    good.push(signed)
    goodTotal += BigInt(signed.bytes)
  }
  const junk = []
  for (let k = 0; k < 30; k++) junk.push(pickHostile(rand, k))
  const mixed = shuffle(rand, [...good, ...junk])

  let res
  try { res = rm.aggregate(mixed, { strict: false }) } catch (e) { t.fail('aggregate crashed on mixed hostile input: ' + e.message) }
  if (res) {
    if (res.invalid !== junk.length) t.fail('expected ' + junk.length + ' invalid, got ' + res.invalid)
    if (res.claims.length !== good.length) t.fail('good receipts did not all survive: ' + res.claims.length)
    if (res.totalBytes !== goodTotal) t.fail('total wrong after hostile mix: ' + res.totalBytes + ' != ' + goodTotal)
  }

  // Non-array input is a clean throw, not a runtime crash.
  for (const bad of [null, undefined, 5, 'x', {}, { length: 2 }]) {
    let threw = false
    try { rm.aggregate(bad) } catch { threw = true }
    if (!threw) t.fail('aggregate accepted non-array: ' + String(bad))
  }

  t.pass('no hostile input crashed verify / decode / aggregate across ' + N + ' iterations')
})

// A grab-bag of hostile / malformed receipt-shaped values, including throwing
// getters and wrong-typed / wrong-sized fields.
function pickHostile (rand, i) {
  const pool = [
    null,
    undefined,
    i,
    'not-a-receipt',
    true,
    {},
    [],
    { signature: randBytes(rand, 64) },
    { signature: randBytes(rand, 64), consumer: randBytes(rand, 32) },
    { signature: randBytes(rand, 63), consumer: randBytes(rand, 32) },
    { signature: randBytes(rand, 32), consumer: randBytes(rand, 4) },
    { signature: randBytes(rand, 64), consumer: randBytes(rand, 32), version: 1, provider: randBytes(rand, 32), channel: randBytes(rand, 32), bytes: -1, sequence: 0, timestamp: 0, nonce: randBytes(rand, 32) },
    { signature: randBytes(rand, 64), consumer: randBytes(rand, 32), bytes: NaN, sequence: 1.5 },
    { signature: randBytes(rand, 64), get consumer () { throw new Error('boom-consumer') } },
    { signature: randBytes(rand, 64), consumer: randBytes(rand, 32), get sequence () { throw new Error('boom-seq') } },
    { signature: randBytes(rand, 64), consumer: randBytes(rand, 32), get bytes () { throw new Error('boom-bytes') } },
    Object.create(null),
    b4a.alloc(10)
  ]
  return pool[randInt(rand, pool.length)]
}
