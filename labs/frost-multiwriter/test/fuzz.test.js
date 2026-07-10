// Seeded property + fuzz tests for frost-multiwriter.
//
// Every random draw comes from a single seeded PRNG so any failure is
// reproducible: the seed is printed once at the top of the run. Override it
// with FROST_FUZZ_SEED=<uint32> to replay a specific failing run.
//
// These tests are written to FAIL if the threshold property were violated:
//  - any t of n sign  -> ONE valid Schnorr sig under the single group key
//  - any t-1          -> CANNOT produce a valid signature (fails closed)
//  - wrong msg / tampered sig / wrong group key -> verify() is false
//  - forged / cross-group share -> caught at aggregation (throws)
//  - nonce reuse -> rejected (a nonce is one-time-use)
//  - invalid (t,n) configs -> throw cleanly (real Error, no crash/garbage)

const test = require('brittle')
const b4a = require('b4a')

const frost = require('..')
const { ristretto255_FROST: RAW } = require('@noble/curves/ed25519.js')

const MAX_N = 7

// ---- seeded PRNG (mulberry32) ------------------------------------------
const SEED = (process.env.FROST_FUZZ_SEED
  ? (parseInt(process.env.FROST_FUZZ_SEED, 10) >>> 0)
  : (Math.random() * 0x100000000) >>> 0)

function mulberry32 (seed) {
  let a = seed >>> 0
  return function () {
    a |= 0
    a = (a + 0x6D2B79F5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const rng = mulberry32(SEED)
function randInt (lo, hi) { return lo + Math.floor(rng() * (hi - lo + 1)) } // inclusive
function randBytes (n) {
  const b = b4a.alloc(n)
  for (let i = 0; i < n; i++) b[i] = randInt(0, 255)
  return b
}
function shuffle (arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randInt(0, i)
    const tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp
  }
  return arr
}
// a random k-subset of writer ids [1..n]
function pickSubset (n, k) { return shuffle([...Array(n)].map((_, i) => i + 1)).slice(0, k).sort((a, b) => a - b) }

// ---- signing helpers ---------------------------------------------------
function makeSessions (dealt, threshold, signers, ids) {
  return ids.map((id) => new frost.SignSession({
    id, secret: dealt.shares[id - 1].secret, group: dealt.group, threshold, signers
  }))
}
function roundSign (dealt, sessions, message) {
  const commitments = sessions.map((s) => s.commit())
  const shares = sessions.map((s) => s.sign(message, commitments))
  return { commitments, shares, signature: frost.aggregate(message, commitments, shares, dealt.group) }
}

test('SEED banner (set FROST_FUZZ_SEED to reproduce)', function (t) {
  t.comment('FROST_FUZZ_SEED=' + SEED)
  t.pass('seed=' + SEED)
})

// PROPERTY 1 -------------------------------------------------------------
// Over random (t,n) with 2<=t<=n<=7 and a random t-subset of signers, the
// quorum produces exactly one 64-byte signature that verifies under the
// single group key. Aggregation is canonical (idempotent) regardless of the
// order commitments/shares are presented in.
test('property: any random t-of-n quorum yields ONE valid signature under the group key', function (t) {
  const ITERS = 80
  for (let it = 0; it < ITERS; it++) {
    const n = randInt(2, MAX_N)
    const threshold = randInt(2, n)
    const dealt = frost.dealerKeygen(threshold, n)
    t.is(dealt.publicKey.byteLength, 32, 'group key 32 bytes (n=' + n + ')')
    t.is(dealt.shares.length, n, 'n shares dealt')

    const message = randBytes(randInt(1, 48))
    const ids = pickSubset(n, threshold)
    const sessions = makeSessions(dealt, threshold, n, ids)
    const { commitments, shares, signature } = roundSign(dealt, sessions, message)

    t.is(signature.byteLength, 64, 't=' + threshold + '/n=' + n + ' subset=' + ids + ' -> 64-byte sig')
    t.ok(frost.verify(signature, message, dealt.publicKey), 'quorum ' + ids + ' verifies under group key')

    // canonical: re-aggregating the SAME shares in a shuffled order gives the
    // byte-identical signature (no reorg, one canonical group commit).
    const permC = shuffle(commitments.slice())
    const permS = shuffle(shares.slice())
    const again = frost.aggregate(message, permC, permS, dealt.group)
    t.alike(again, signature, 'aggregation is order-independent / canonical')
  }
})

// PROPERTY 2 -------------------------------------------------------------
// Any t-1 signers cannot produce a valid signature. Three attack shapes:
//  (a) t-1 honest signers with only their own commitments cannot even run
//      round 2 (below quorum, fails closed).
//  (b) t-1 honest signers pad the set with a fabricated commitment they do
//      not own the share for; aggregating the t-1 real shares fails closed.
//  (c) t-1 honest signers + an attacker who guesses a t-th secret produce a
//      full-count share set, but the forged share is caught at aggregation.
test('property: any t-1 signers CANNOT forge a valid signature', function (t) {
  const ITERS = 50
  for (let it = 0; it < ITERS; it++) {
    const n = randInt(2, MAX_N)
    const threshold = randInt(2, n)
    const dealt = frost.dealerKeygen(threshold, n)
    const message = randBytes(randInt(1, 32))
    const short = pickSubset(n, threshold - 1)

    // (a) below quorum: cannot sign at all
    const sessA = makeSessions(dealt, threshold, n, short)
    const commsA = sessA.map((s) => s.commit())
    t.exception(() => sessA[0].sign(message, commsA), /below quorum/, 't-1=' + short.length + ' cannot sign (below quorum)')

    // (b) pad with a fabricated commitment for a non-participating id to hit
    // the threshold count, sign the padded set, then aggregate only the real
    // t-1 shares -> the missing valid t-th share is detected, aggregation fails.
    const outsider = [...Array(n)].map((_, i) => i + 1).find((id) => !short.includes(id))
    const fakeSecret = { identifier: RAW.Identifier.fromNumber(outsider), signingShare: RAW.utils.randomScalar() }
    const fakeGen = RAW.commit(fakeSecret)
    const cFake = {
      id: outsider,
      identifier: fakeSecret.identifier,
      hidingCommitment: b4a.from(fakeGen.commitments.hiding),
      bindingCommitment: b4a.from(fakeGen.commitments.binding)
    }
    const sessB = makeSessions(dealt, threshold, n, short)
    const commsB = sessB.map((s) => s.commit()).concat([cFake])
    const realShares = sessB.map((s) => s.sign(message, commsB))
    t.exception(() => frost.aggregate(message, commsB, realShares, dealt.group), /aggregation failed/, 't-1 real shares + fabricated commitment fails closed')

    // (c) attacker also fabricates the t-th share from a guessed secret.
    const list = commsB
      .map((c) => ({ identifier: c.identifier, hiding: c.hidingCommitment, binding: c.bindingCommitment }))
      .sort((a, b) => (a.identifier < b.identifier ? -1 : a.identifier > b.identifier ? 1 : 0))
    const forgedShare = {
      id: outsider,
      identifier: fakeSecret.identifier,
      share: b4a.from(RAW.signShare(fakeSecret, dealt.group, fakeGen.nonces, list, message))
    }
    t.exception(() => frost.aggregate(message, commsB, realShares.concat([forgedShare]), dealt.group), /aggregation failed/, 'forged t-th share caught at aggregation')
  }
})

// PROPERTY 3 -------------------------------------------------------------
// verify() rejects wrong message, any single-bit tamper, random garbage,
// and the wrong group key — never returning a false positive.
test('property: wrong message / tampered sig / wrong group key -> verify false', function (t) {
  const ITERS = 40
  for (let it = 0; it < ITERS; it++) {
    const n = randInt(2, MAX_N)
    const threshold = randInt(2, n)
    const dealt = frost.dealerKeygen(threshold, n)
    const other = frost.dealerKeygen(threshold, n)
    const message = randBytes(randInt(1, 40))
    const { signature } = roundSign(dealt, makeSessions(dealt, threshold, n, pickSubset(n, threshold)), message)

    t.ok(frost.verify(signature, message, dealt.publicKey), 'genuine sig verifies')

    // wrong message (guaranteed different bytes)
    const wrongMsg = b4a.from(message)
    wrongMsg[randInt(0, wrongMsg.length - 1)] ^= (1 << randInt(0, 7))
    t.absent(frost.verify(signature, wrongMsg, dealt.publicKey), 'wrong message rejected')

    // single random-bit tamper on the signature
    const tampered = b4a.from(signature)
    tampered[randInt(0, 63)] ^= (1 << randInt(0, 7))
    t.absent(frost.verify(tampered, message, dealt.publicKey), 'tampered signature rejected')

    // pure garbage signature bytes
    t.absent(frost.verify(randBytes(64), message, dealt.publicKey), 'garbage signature rejected')

    // wrong (independent) group key
    t.absent(frost.verify(signature, message, other.publicKey), 'wrong group key rejected')
    // wrong-but-valid group point of the right length (another group's key)
    t.is(other.publicKey.byteLength, 32, 'other key is a valid 32-byte point')
  }
})

// PROPERTY 4 -------------------------------------------------------------
// A share from a DIFFERENT group (same identifier, valid on its own group)
// substituted into this group's aggregation is caught — cross-group shares
// do not aggregate into a valid signature.
test('property: cross-group / forged share is caught at aggregation', function (t) {
  const ITERS = 30
  for (let it = 0; it < ITERS; it++) {
    const n = randInt(3, MAX_N)
    const threshold = randInt(2, n - 1) // leave room so threshold-1 honest ids exist
    const groupA = frost.dealerKeygen(threshold, n)
    const groupB = frost.dealerKeygen(threshold, n)
    const message = randBytes(randInt(1, 32))

    const ids = pickSubset(n, threshold)
    const swap = ids[randInt(0, ids.length - 1)] // this id will be sourced from group B
    const honestIds = ids.filter((id) => id !== swap)

    const honest = makeSessions(groupA, threshold, n, honestIds)
    const impostor = makeSessions(groupB, threshold, n, [swap])[0]

    const commitments = honest.map((s) => s.commit()).concat([impostor.commit()])
    const shares = honest.map((s) => s.sign(message, commitments))
    shares.push(impostor.sign(message, commitments)) // valid on group B, wrong here

    t.exception(() => frost.aggregate(message, commitments, shares, groupA.group), /aggregation failed/, 'cross-group share rejected (t=' + threshold + '/n=' + n + ')')
  }
})

// PROPERTY 5 -------------------------------------------------------------
// Nonces are one-time-use. A session that has signed cannot sign again
// (the nonce was consumed), and independent commits never repeat a nonce
// commitment — so accidental nonce reuse cannot slip through.
test('property: nonce reuse rejected; fresh commits never repeat a nonce', function (t) {
  const n = randInt(3, MAX_N)
  const threshold = randInt(2, n)
  const dealt = frost.dealerKeygen(threshold, n)
  const message = randBytes(16)

  // one-time use: signing consumes the nonce; a second sign() throws.
  const ids = pickSubset(n, threshold)
  const sessions = makeSessions(dealt, threshold, n, ids)
  const commitments = sessions.map((s) => s.commit())
  sessions.forEach((s) => s.sign(message, commitments))
  for (const s of sessions) {
    t.exception(() => s.sign(message, commitments), /commit\(\) before sign\(\)/, 'nonce reuse rejected (id ' + s.id + ')')
  }

  // fresh commits are distinct: gather many nonce commitments, none collide.
  const seen = new Set()
  const REPS = 200
  for (let i = 0; i < REPS; i++) {
    const sess = makeSessions(dealt, threshold, n, [randInt(1, n)])[0]
    const c = sess.commit()
    const keyH = b4a.toString(c.hidingCommitment, 'hex')
    const keyB = b4a.toString(c.bindingCommitment, 'hex')
    t.absent(seen.has(keyH), 'hiding nonce commitment not reused')
    t.absent(seen.has(keyB), 'binding nonce commitment not reused')
    seen.add(keyH); seen.add(keyB)
  }
})

// EXTRA -----------------------------------------------------------------
// A duplicated signer (same id counted twice to fake reaching threshold)
// must not aggregate into a valid signature.
test('property: duplicate-signer padding cannot reach quorum', function (t) {
  const ITERS = 20
  for (let it = 0; it < ITERS; it++) {
    const n = randInt(2, MAX_N)
    const threshold = 2
    const dealt = frost.dealerKeygen(threshold, n)
    const message = randBytes(16)
    const id = randInt(1, n)
    const a = makeSessions(dealt, threshold, n, [id])[0]
    const b = makeSessions(dealt, threshold, n, [id])[0]
    const ca = a.commit(); const cb = b.commit()
    // one signer masquerading as the whole 2-of-n quorum -> fails closed,
    // whether the failure lands in signShare or aggregate. Prove no valid
    // signature can be produced this way.
    let produced = null
    try {
      const sa = a.sign(message, [ca, cb])
      const sb = b.sign(message, [ca, cb])
      produced = frost.aggregate(message, [ca, cb], [sa, sb], dealt.group)
    } catch (_) { produced = null }
    if (produced) t.absent(frost.verify(produced, message, dealt.publicKey), 'duplicate-signer sig does not verify')
    else t.pass('duplicate-signer attack fails closed')
  }
})

// FUZZ ------------------------------------------------------------------
// Invalid (t,n) configurations throw a clean Error (never crash or silently
// accept), via validateConfig, dealerKeygen, and the SignSession constructor.
test('fuzz: invalid t-of-n configs throw cleanly', function (t) {
  const ITERS = 300
  let checked = 0
  for (let it = 0; it < ITERS; it++) {
    const kind = randInt(0, 4)
    let threshold, signers, why
    if (kind === 0) { threshold = randInt(-3, 1); signers = randInt(threshold, MAX_N); why = />= 2|integers/ } // t < 2
    else if (kind === 1) { signers = randInt(2, MAX_N); threshold = signers + randInt(1, 4); why = /signers must be >= threshold/ } // t > n
    else if (kind === 2) { threshold = randInt(2, 5) + 0.5; signers = randInt(2, MAX_N); why = /integers/ } // non-integer t
    else if (kind === 3) { threshold = randInt(2, 5); signers = randInt(2, 5) + 0.5; why = /integers/ } // non-integer n
    else { threshold = [NaN, Infinity][randInt(0, 1)]; signers = randInt(2, MAX_N); why = /integers/ } // NaN/Inf

    // validateConfig throws with a matching message and a real Error.
    let err = null
    try { frost.validateConfig(threshold, signers) } catch (e) { err = e }
    t.ok(err instanceof Error, 'validateConfig(' + threshold + ',' + signers + ') threw an Error')
    t.exception(() => frost.validateConfig(threshold, signers), why, 'clean message')

    // dealerKeygen must reject the same config (fails closed before dealing).
    t.exception(() => frost.dealerKeygen(threshold, signers), why, 'dealerKeygen rejects bad config')
    checked++
  }
  // valid configs never throw (positive control across the whole grid).
  for (let n = 2; n <= MAX_N; n++) {
    for (let th = 2; th <= n; th++) {
      t.execution(() => frost.validateConfig(th, n), 'valid ' + th + '-of-' + n + ' accepted')
    }
  }
  t.is(checked, ITERS, 'fuzzed ' + ITERS + ' invalid configs')
})

// FUZZ ------------------------------------------------------------------
// SignSession id bounds: any id outside [1, signers] throws cleanly.
test('fuzz: SignSession rejects out-of-range / non-integer ids', function (t) {
  const ITERS = 150
  for (let it = 0; it < ITERS; it++) {
    const n = randInt(2, MAX_N)
    const threshold = randInt(2, n)
    const dealt = frost.dealerKeygen(threshold, n)
    const badId = randInt(0, 1) === 0 ? randInt(-4, 0) : n + randInt(1, 5)
    t.exception(() => new frost.SignSession({ id: badId, group: dealt.group, threshold, signers: n }), /id must be/, 'id ' + badId + ' out of [1,' + n + ']')
    // non-integer id
    t.exception(() => new frost.SignSession({ id: randInt(1, n) + 0.5, group: dealt.group, threshold, signers: n }), /id must be/, 'non-integer id')
  }
})
