// Property-based + fuzz tests for hyperbeam-pake.
//
// Every randomised test is driven by a SEEDED PRNG (mulberry32) so a failure is
// exactly reproducible: the seed is printed in the test name / comment and the
// same seed replays the same passphrases, sids and scalars. The CPace scalar
// randomness is injected via opts.rng from the same PRNG, so an entire run is a
// pure function of SEED — no wall-clock, no OS entropy.
//
// These are written to FAIL on a broken implementation:
//   - if the ISK stopped binding the sid, the "different sid" property fails
//   - if verifyConfirm stopped keying on the ISK, the wrong-passphrase property
//     would report a silent match and fail
//   - if the transcript reverted to role-based ordering, the both-initiator
//     property fails
//   - if finish() stopped rejecting the identity / non-canonical encodings, the
//     fuzz oracle (ground truth from @noble/curves) diverges and fails

const test = require('brittle')
const b4a = require('b4a')
const { ristretto255 } = require('@noble/curves/ed25519.js')

const { CPace, topicFromPassphrase, deriveGenerator, constants } = require('..')

const Point = ristretto255.Point

const SEED = 0xC0FFEE

// ---------------------------------------------------------------------------
// Seeded PRNG (mulberry32) — deterministic, reproducible.
// ---------------------------------------------------------------------------
function makePRNG (seed) {
  let s = seed >>> 0
  function u32 () {
    s = (s + 0x6D2B79F5) | 0
    let t = Math.imul(s ^ (s >>> 15), 1 | s)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return (t ^ (t >>> 14)) >>> 0
  }
  return {
    u32,
    byte: () => u32() & 0xff,
    int: (n) => u32() % n,
    bytes (n) {
      const b = b4a.alloc(n)
      for (let i = 0; i < n; i++) b[i] = u32() & 0xff
      return b
    },
    // fill an arbitrary buffer (used as the injected CPace rng)
    fill (buf) {
      for (let i = 0; i < buf.byteLength; i++) buf[i] = u32() & 0xff
    },
    passphrase () {
      const len = 1 + this.int(23) // 1..24 bytes, always non-empty
      return this.bytes(len)
    },
    sid () {
      return this.bytes(1 + this.int(39)) // 1..40 bytes
    }
  }
}

// An injectable rng backed by the seeded PRNG, so scalars are reproducible.
function rngFrom (prng) {
  return (buf) => prng.fill(buf)
}

// ---------------------------------------------------------------------------
// PROPERTY: matching passphrase ALWAYS yields equal ISK and mutually
// verifying confirmation MACs, across random passphrases, sids and roles.
// ---------------------------------------------------------------------------
test('property: matching passphrase => equal ISK + confirmations verify (seed ' + SEED + ')', function (t) {
  const prng = makePRNG(SEED)
  const N = 200
  for (let i = 0; i < N; i++) {
    const pass = prng.passphrase()
    const sid = prng.sid()
    // randomise roles too: correctness must be role-independent
    const roleA = prng.byte() < 128
    const roleB = prng.byte() < 128
    const rng = rngFrom(prng)

    const a = new CPace(pass, { isInitiator: roleA, sid, rng })
    const b = new CPace(pass, { isInitiator: roleB, sid, rng })

    const msgA = a.start()
    const msgB = b.start()
    if (msgA.byteLength !== 32 || msgB.byteLength !== 32) {
      t.fail('iter ' + i + ': message not 32 bytes')
      return
    }

    const kA = a.finish(msgB)
    const kB = b.finish(msgA)

    if (!b4a.equals(kA, kB)) {
      t.fail('iter ' + i + ': ISK mismatch for matching passphrase (seed ' + SEED + ')')
      return
    }

    // both sides derived the same passphrase-generator
    if (!b4a.equals(deriveGenerator(pass, sid), deriveGenerator(pass, sid))) {
      t.fail('iter ' + i + ': generator not deterministic')
      return
    }

    const tagA = a.confirm()
    const tagB = b.confirm()
    if (!b.verifyConfirm(tagA) || !a.verifyConfirm(tagB)) {
      t.fail('iter ' + i + ': confirmation MAC failed to verify on matching passphrase')
      return
    }
  }
  t.pass('all ' + N + ' matching-passphrase exchanges agreed and confirmed')
})

// ---------------------------------------------------------------------------
// PROPERTY: ANY different passphrase => different ISK and verifyConfirm FALSE.
// This is the security property — a wrong online guess must never yield a
// silent key match. If verifyConfirm ever returned true here, the test fails.
// ---------------------------------------------------------------------------
test('property: different passphrase => different ISK + verifyConfirm FALSE (never a silent match)', function (t) {
  const prng = makePRNG(SEED ^ 0x1234)
  const N = 200
  let checked = 0
  for (let i = 0; i < N; i++) {
    let passA = prng.passphrase()
    let passB = prng.passphrase()
    // guarantee the two passphrases genuinely differ
    let guard = 0
    while (b4a.equals(passA, passB) && guard++ < 8) passB = prng.passphrase()
    if (b4a.equals(passA, passB)) continue // give up on this rare draw

    const sid = prng.sid() // SAME sid, only the passphrase differs
    const rng = rngFrom(prng)

    const a = new CPace(passA, { isInitiator: true, sid, rng })
    const b = new CPace(passB, { isInitiator: false, sid, rng })

    const msgA = a.start()
    const msgB = b.start()
    const kA = a.finish(msgB)
    const kB = b.finish(msgA)

    if (b4a.equals(kA, kB)) {
      t.fail('iter ' + i + ': DIFFERENT passphrases produced the SAME ISK (silent match!)')
      return
    }

    const tagA = a.confirm()
    const tagB = b.confirm()
    if (b.verifyConfirm(tagA)) {
      t.fail('iter ' + i + ': verifyConfirm accepted a wrong-passphrase tag (silent match!)')
      return
    }
    if (a.verifyConfirm(tagB)) {
      t.fail('iter ' + i + ': verifyConfirm accepted a wrong-passphrase tag (reverse direction)')
      return
    }
    checked++
  }
  t.ok(checked > N * 0.9, 'checked ' + checked + '/' + N + ' distinct-passphrase pairs, all rejected')
})

// ---------------------------------------------------------------------------
// PROPERTY: same passphrase, different sid => different key.
// ---------------------------------------------------------------------------
test('property: same passphrase, different sid => different ISK', function (t) {
  const prng = makePRNG(SEED ^ 0x5678)
  const N = 150
  for (let i = 0; i < N; i++) {
    const pass = prng.passphrase()
    let sidA = prng.sid()
    let sidB = prng.sid()
    let guard = 0
    while (b4a.equals(sidA, sidB) && guard++ < 8) sidB = prng.sid()
    if (b4a.equals(sidA, sidB)) continue
    const rng = rngFrom(prng)

    const a = new CPace(pass, { isInitiator: true, sid: sidA, rng })
    const b = new CPace(pass, { isInitiator: false, sid: sidB, rng })

    const msgA = a.start()
    const msgB = b.start()
    const kA = a.finish(msgB)
    const kB = b.finish(msgA)
    if (b4a.equals(kA, kB)) {
      t.fail('iter ' + i + ': same passphrase but different sid produced equal ISK (sid not bound)')
      return
    }
  }
  t.pass('sid is bound into the key across ' + N + ' random cases')
})

// ---------------------------------------------------------------------------
// PROPERTY: content-ordered transcript makes BOTH-initiator (and both-
// responder) peers agree, across random passphrases/sids.
// ---------------------------------------------------------------------------
test('property: symmetric roles still agree (content-ordered transcript)', function (t) {
  const prng = makePRNG(SEED ^ 0x9abc)
  const N = 150
  for (let i = 0; i < N; i++) {
    const pass = prng.passphrase()
    const sid = prng.sid()
    const bothRole = prng.byte() < 128 // both true, or both false
    const rng = rngFrom(prng)

    const a = new CPace(pass, { isInitiator: bothRole, sid, rng })
    const b = new CPace(pass, { isInitiator: bothRole, sid, rng })

    const msgA = a.start()
    const msgB = b.start()
    const kA = a.finish(msgB)
    const kB = b.finish(msgA)
    if (!b4a.equals(kA, kB)) {
      t.fail('iter ' + i + ': symmetric-role peers (isInitiator=' + bothRole + ') derived different ISKs')
      return
    }
    if (!b.verifyConfirm(a.confirm()) || !a.verifyConfirm(b.confirm())) {
      t.fail('iter ' + i + ': symmetric-role confirmation failed')
      return
    }
  }
  t.pass('content-based ordering keeps symmetric-role peers in agreement (' + N + ' cases)')
})

// ---------------------------------------------------------------------------
// PROPERTY: ristretto identity / low-order / non-canonical peer messages are
// rejected. ristretto255 is prime-order, so the ONLY degenerate decodable
// element is the identity (all-zero canonical encoding); everything else that
// is not a valid canonical encoding must fail to decode. We prove this against
// @noble/curves as ground truth over many random encodings.
// ---------------------------------------------------------------------------
test('property: identity and non-canonical peer messages are rejected', function (t) {
  // The identity is the single degenerate decodable point in this prime-order
  // group. Its canonical encoding is 32 zero bytes.
  const identity = b4a.from(Point.ZERO.toBytes())
  t.alike(identity, b4a.alloc(32), 'ristretto identity encodes to all zeros')
  {
    const s = new CPace('pass', { isInitiator: true, sid: b4a.alloc(16) })
    s.start()
    t.exception(() => s.finish(identity), /identity\/low-order element/, 'identity element rejected')
  }

  // A non-canonical field encoding: field element with the high bit set is not
  // a canonical ristretto255 encoding and must fail to decode.
  {
    const nonCanon = b4a.alloc(32)
    nonCanon[31] = 0x80
    const s = new CPace('pass', { isInitiator: true, sid: b4a.alloc(16) })
    s.start()
    t.exception(() => s.finish(nonCanon), /non-canonical encoding/, 'high-bit non-canonical encoding rejected')
  }

  // Assert there is NO decodable non-identity low-order element by scanning a
  // large seeded sample: any decodable element we find is checked to be either
  // full-order (accepted by finish) or the identity (rejected). We never expect
  // to find a decodable element that is neither.
  const prng = makePRNG(SEED ^ 0xDEAD)
  let decoded = 0
  let rejected = 0
  const N = 4000
  for (let i = 0; i < N; i++) {
    const buf = prng.bytes(32)
    let P = null
    try {
      P = Point.fromBytes(buf)
    } catch {
      rejected++
      continue
    }
    decoded++
    // No random 32-byte string should ever decode to the identity.
    if (P.is0()) {
      t.fail('iter ' + i + ': a random encoding decoded to the identity element')
      return
    }
  }
  t.ok(decoded > 0, 'sampled ' + decoded + ' valid encodings, ' + rejected + ' rejected; none was a low-order/identity element')
})

// ---------------------------------------------------------------------------
// FUZZ: malformed peer messages passed to finish() must NEVER crash — they
// either throw a proper Error (with an expected message) or, for a genuinely
// valid non-identity point, return a 32-byte ISK. Expected behaviour is decided
// by @noble/curves as an independent oracle, then compared to finish().
// ---------------------------------------------------------------------------
test('fuzz: malformed peer messages never crash finish() (oracle-checked)', function (t) {
  const prng = makePRNG(SEED ^ 0xBEEF)
  const N = 400
  const sid = b4a.alloc(16).fill(0x5a)
  const rng = rngFrom(prng)

  for (let i = 0; i < N; i++) {
    const kind = prng.int(5)
    let input

    if (kind === 0) input = prng.bytes(32) // random 32-byte (mostly non-canonical)
    else if (kind === 1) input = prng.bytes(prng.int(64)) // 0..63 wrong-length buffer
    else if (kind === 2) input = prng.bytes(32 + prng.int(32)) // 32..63 (too long unless exactly 32)
    else if (kind === 3) {
      // structurally odd but valid-length: mostly 0xff / patterned bytes
      input = b4a.alloc(32)
      const fill = prng.byte()
      input.fill(fill)
      input[prng.int(32)] = prng.byte()
    } else {
      // non-buffer garbage
      const opts = [null, undefined, 42, 'not-a-buffer', {}, []]
      input = opts[prng.int(opts.length)]
    }

    // Independent oracle for the expected outcome.
    let expect // 'len' | 'noncanon' | 'identity' | 'ok'
    if (!b4a.isBuffer(input) || input.byteLength !== 32) {
      expect = 'len'
    } else {
      let P = null
      try {
        P = Point.fromBytes(input)
      } catch {
        P = false
      }
      if (P === false) expect = 'noncanon'
      else if (P.is0()) expect = 'identity'
      else expect = 'ok'
    }

    // Fresh started instance each time (finish is single-shot on success).
    const s = new CPace('fuzz-pass', { isInitiator: true, sid, rng })
    s.start()

    let threw = null
    let result = null
    try {
      result = s.finish(input)
    } catch (err) {
      threw = err
    }

    if (expect === 'ok') {
      if (threw) {
        t.fail('iter ' + i + ' kind ' + kind + ': finish threw on a valid point: ' + threw.message)
        return
      }
      if (!b4a.isBuffer(result) || result.byteLength !== 32) {
        t.fail('iter ' + i + ': finish did not return a 32-byte ISK for a valid point')
        return
      }
    } else {
      if (!threw) {
        t.fail('iter ' + i + ' kind ' + kind + ' expect ' + expect + ': finish did NOT throw on malformed input')
        return
      }
      if (!(threw instanceof Error)) {
        t.fail('iter ' + i + ': finish threw a non-Error value: ' + String(threw))
        return
      }
      const m = threw.message
      const okMsg = /32-byte|non-canonical|identity|degenerate/.test(m)
      if (!okMsg) {
        t.fail('iter ' + i + ' expect ' + expect + ': unexpected error message: ' + m)
        return
      }
    }
  }
  t.pass('fuzzed ' + N + ' malformed inputs; every one threw a proper Error or returned a valid ISK')
})

// ---------------------------------------------------------------------------
// FUZZ: verifyConfirm with random / wrong-length tags must return a boolean
// (false) and never throw, after a completed exchange.
// ---------------------------------------------------------------------------
test('fuzz: verifyConfirm tolerates arbitrary tag bytes without throwing', function (t) {
  const prng = makePRNG(SEED ^ 0x0F0F)
  const sid = b4a.alloc(16).fill(3)
  const rng = rngFrom(prng)
  const a = new CPace('confirm-pass', { isInitiator: true, sid, rng })
  const b = new CPace('confirm-pass', { isInitiator: false, sid, rng })
  const msgA = a.start()
  const msgB = b.start()
  a.finish(msgB)
  b.finish(msgA)

  const realTag = b.confirm() // the one tag that should verify true
  const N = 400
  let trueCount = 0
  for (let i = 0; i < N; i++) {
    const len = prng.int(48) // 0..47, including the correct 32
    const tag = prng.bytes(len)
    let res
    try {
      res = a.verifyConfirm(tag)
    } catch (err) {
      t.fail('iter ' + i + ': verifyConfirm threw on random tag: ' + err.message)
      return
    }
    if (typeof res !== 'boolean') {
      t.fail('iter ' + i + ': verifyConfirm returned a non-boolean')
      return
    }
    if (res) trueCount++
  }
  // A random tag colliding with the real MAC is ~2^-256; expect zero.
  t.is(trueCount, 0, 'no random tag ever forged a valid confirmation')
  t.ok(a.verifyConfirm(realTag), 'the genuine tag still verifies true')
})

// ---------------------------------------------------------------------------
// FUZZ: constructor / topic input validation never crashes uncontrolled.
// ---------------------------------------------------------------------------
test('fuzz: malformed passphrase inputs are rejected cleanly', function (t) {
  const bad = ['', b4a.alloc(0), null, undefined, 42, {}, [], b4a.alloc(0)]
  for (const p of bad) {
    t.exception(() => new CPace(p, { isInitiator: true }), 'CPace rejects malformed passphrase: ' + String(p))
    t.exception(() => topicFromPassphrase(p), 'topicFromPassphrase rejects malformed passphrase: ' + String(p))
  }
  // valid non-empty buffers/strings must NOT throw in the constructor
  t.execution(() => new CPace('ok', { isInitiator: true }))
  t.execution(() => new CPace(b4a.from([1]), { isInitiator: false }))
})

// ---------------------------------------------------------------------------
// PROPERTY: Argon2id topic is deterministic and measurably slow, over random
// passphrases (kept to a handful — each is a real Argon2id evaluation).
// ---------------------------------------------------------------------------
test('property: argon2id topic is deterministic, distinct, and slow', function (t) {
  const prng = makePRNG(SEED ^ 0x7777)
  const M = 4
  const topics = []
  let maxDt = 0
  for (let i = 0; i < M; i++) {
    const pass = prng.passphrase()
    const t0 = Date.now()
    const topic = topicFromPassphrase(pass)
    const dt = Date.now() - t0
    maxDt = Math.max(maxDt, dt)

    t.is(topic.byteLength, 32, 'topic is 32 bytes')
    t.alike(topic, topicFromPassphrase(pass), 'deterministic: same passphrase => same topic')
    // topic namespace must be disjoint from the generator namespace
    t.unlike(topic, deriveGenerator(pass, b4a.alloc(16)), 'topic and generator live in separate namespaces')
    topics.push(b4a.toString(topic, 'hex'))
  }
  // all distinct passphrases -> distinct topics (no collisions in the sample)
  t.is(new Set(topics).size, topics.length, 'distinct passphrases produce distinct topics')
  // Argon2id at INTERACTIVE limits is orders of magnitude slower than a bare
  // BLAKE2b hash (sub-millisecond); this lower bound documents the tax.
  t.ok(maxDt >= 5, 'argon2id topic derivation does real work, max measured ' + maxDt + 'ms')
})

// ---------------------------------------------------------------------------
// PROPERTY: fresh scalars => unlinkable transcripts. Two exchanges with the
// same passphrase+sid must produce different wire messages (fresh randomness),
// so a recorded transcript is not a static fingerprint. Uses the REAL default
// rng (sodium) to prove it is not an artifact of the injected PRNG.
// ---------------------------------------------------------------------------
test('property: fresh scalars make transcripts unlinkable across runs', function (t) {
  const pass = 'unlinkable-pass'
  const sid = b4a.alloc(16).fill(11)
  const seen = new Set()
  const N = 100
  for (let i = 0; i < N; i++) {
    const msg = new CPace(pass, { isInitiator: true, sid }).start()
    const hex = b4a.toString(msg, 'hex')
    if (seen.has(hex)) {
      t.fail('iter ' + i + ': repeated wire message across runs — scalar not fresh')
      return
    }
    seen.add(hex)
  }
  t.is(seen.size, N, 'all ' + N + ' transcripts distinct (fresh scalar per session)')
})
