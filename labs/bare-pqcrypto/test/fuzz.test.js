// Property-based + fuzz tests for bare-pqcrypto.
//
// Every random draw comes from a SEEDED, deterministic DRBG (SHA-256 in counter
// mode) so a failure is exactly reproducible: re-run with the same PQ_FUZZ_SEED
// and the identical byte stream is regenerated. Iteration counts are tuned so
// the whole file runs in a few seconds while still exercising hundreds of
// independent draws (ML-DSA sign ~14ms dominates, so keypairs are reused across
// many cheap verify probes).
//
// These are adversarial by construction: each assertion is written so that it
// would FAIL on a broken implementation (e.g. a hybrid verifier that OR'd its
// two halves, a KEM that leaked plaintext-equality via a throw, a verifier that
// ignored a flipped bit). Passing therefore carries signal.

const test = require('brittle')
const b4a = require('b4a')
const crypto = require('crypto')

const pq = require('..')

const KEM_LEVELS = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']
const DSA_LEVELS = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']

// --- seeded deterministic DRBG -------------------------------------------
// SHA-256(seed || counterLE) concatenated. Reproducible across runs/platforms.
function makeRng (seedLabel) {
  const seed = crypto.createHash('sha256').update(String(seedLabel)).digest()
  let counter = 0
  let pool = b4a.alloc(0)
  function refill () {
    const c = b4a.alloc(4)
    c.writeUInt32LE(counter++, 0)
    const block = crypto.createHash('sha256').update(seed).update(c).digest()
    pool = b4a.concat([pool, block])
  }
  return {
    bytes (n) {
      while (pool.byteLength < n) refill()
      const out = b4a.from(pool.subarray(0, n))
      pool = pool.subarray(n)
      return out
    },
    // uniform in [0, max)
    int (max) {
      if (max <= 0) return 0
      const b = this.bytes(6) // 48 bits of entropy, modulo bias negligible
      let v = 0
      for (let i = 0; i < 6; i++) v = (v * 256 + b[i]) % max
      return v
    }
  }
}

const MASTER_SEED = process.env.PQ_FUZZ_SEED || 'bare-pqcrypto/fuzz/v1'

// Flip exactly one bit at a uniformly random position of a fresh copy.
function flipOneBit (rng, buf) {
  const out = b4a.from(buf)
  const bit = rng.int(out.byteLength * 8)
  out[bit >> 3] ^= (1 << (bit & 7))
  return out
}

// -------------------------------------------------------------------------
// 1. ML-KEM: encap/decap MATCH for honest keys; DIFFER (implicit rejection,
//    no throw) for a wrong secret key or a tampered ciphertext.
// -------------------------------------------------------------------------
test('fuzz: ML-KEM honest encap/decap match; wrong-key & tampered-ct implicitly reject without throwing', function (t) {
  const rng = makeRng(MASTER_SEED + '/kem-core')
  const ITER = 24 // per level; each does 1 encap + 3 decaps
  let honest = 0
  let wrongKeyDiff = 0
  let tamperDiff = 0

  for (const alg of KEM_LEVELS) {
    const p = pq.constants[alg]
    for (let i = 0; i < ITER; i++) {
      // Deterministic honest keygen from seeded 64-byte material.
      const kp = pq.mlkem.keygen(alg, rng.bytes(64))
      const coins = rng.bytes(32)
      const { ciphertext, sharedSecret } = pq.mlkem.encapsulate(kp.publicKey, alg, coins)

      t.is(ciphertext.byteLength, p.ciphertextBytes, alg + ' ct size')
      t.is(sharedSecret.byteLength, 32, alg + ' ss size')

      // (a) honest counterpart recovers the SAME secret.
      const ss = pq.mlkem.decapsulate(ciphertext, kp.secretKey, alg)
      t.alike(ss, sharedSecret, alg + ' honest shared secret matches')
      honest++

      // (b) a DIFFERENT valid secret key: implicit rejection -> no throw, and
      // a shared secret that MUST differ from the honest one.
      const other = pq.mlkem.keygen(alg, rng.bytes(64))
      let ssWrong
      try {
        ssWrong = pq.mlkem.decapsulate(ciphertext, other.secretKey, alg)
      } catch (err) {
        t.fail(alg + ' wrong-key decapsulate must not throw (implicit rejection): ' + err.message)
        continue
      }
      t.is(ssWrong.byteLength, 32, alg + ' wrong-key ss still 32 bytes')
      t.absent(b4a.equals(ssWrong, sharedSecret), alg + ' wrong-key shared secret differs')
      wrongKeyDiff++

      // (c) tampered ciphertext (single flipped bit): implicit rejection ->
      // no throw, shared secret differs from honest.
      const badCt = flipOneBit(rng, ciphertext)
      let ssTamper
      try {
        ssTamper = pq.mlkem.decapsulate(badCt, kp.secretKey, alg)
      } catch (err) {
        t.fail(alg + ' tampered-ct decapsulate must not throw (implicit rejection): ' + err.message)
        continue
      }
      t.absent(b4a.equals(ssTamper, sharedSecret), alg + ' tampered-ct shared secret differs')
      tamperDiff++
    }
  }
  t.is(honest, KEM_LEVELS.length * ITER, 'all honest roundtrips exercised')
  t.is(wrongKeyDiff, KEM_LEVELS.length * ITER, 'all wrong-key rejections differed')
  t.is(tamperDiff, KEM_LEVELS.length * ITER, 'all tampered-ct rejections differed')
})

// -------------------------------------------------------------------------
// 2. ML-DSA: sign/verify roundtrip TRUE; verify FALSE for ANY single flipped
//    bit of signature, message, or public key. (Randomized bit positions.)
// -------------------------------------------------------------------------
test('fuzz: ML-DSA roundtrip true; a single flipped bit in sig/msg/pubkey is rejected (never throws, never accepts)', function (t) {
  const rng = makeRng(MASTER_SEED + '/dsa-flip')
  const KEYPAIRS = 4 // per level
  const FLIPS = 12 // per category (sig / msg / pubkey), per keypair

  for (const alg of DSA_LEVELS) {
    const p = pq.constants[alg]
    for (let k = 0; k < KEYPAIRS; k++) {
      const kp = pq.mldsa.keygen(alg, rng.bytes(32))
      const msg = rng.bytes(1 + rng.int(64))
      const sig = pq.mldsa.sign(msg, kp.secretKey, alg)

      t.is(sig.byteLength, p.signatureBytes, alg + ' signature size')
      t.is(pq.mldsa.verify(sig, msg, kp.publicKey, alg), true, alg + ' honest signature verifies')

      // flip a signature bit
      for (let f = 0; f < FLIPS; f++) {
        const bad = flipOneBit(rng, sig)
        const r = pq.mldsa.verify(bad, msg, kp.publicKey, alg)
        t.is(r, false, alg + ' flipped-sig bit rejected')
      }
      // flip a message bit (message length >= 1 guaranteed)
      for (let f = 0; f < FLIPS; f++) {
        const badMsg = flipOneBit(rng, msg)
        const r = pq.mldsa.verify(sig, badMsg, kp.publicKey, alg)
        t.is(r, false, alg + ' flipped-msg bit rejected')
      }
      // flip a public-key bit (must return false, not throw)
      for (let f = 0; f < FLIPS; f++) {
        const badPk = flipOneBit(rng, kp.publicKey)
        let r
        try {
          r = pq.mldsa.verify(sig, msg, badPk, alg)
        } catch (err) {
          t.fail(alg + ' flipped-pubkey verify threw instead of returning false: ' + err.message)
          continue
        }
        t.is(r, false, alg + ' flipped-pubkey bit rejected')
      }
    }
  }
})

// -------------------------------------------------------------------------
// 3. Cross-algorithm confusion: an ML-DSA signature from one level presented to
//    a verifier configured for a different level must be rejected (throw OR
//    false) — never a silent accept.
// -------------------------------------------------------------------------
test('fuzz: cross-algorithm ML-DSA confusion is always rejected (throw or false, never accept)', function (t) {
  const rng = makeRng(MASTER_SEED + '/dsa-cross')
  const msg = b4a.from('cross-algorithm confusion vector')
  const bundles = {}
  for (const alg of DSA_LEVELS) {
    const kp = pq.mldsa.keygen(alg, rng.bytes(32))
    bundles[alg] = { kp, sig: pq.mldsa.sign(msg, kp.secretKey, alg) }
  }
  for (const signAlg of DSA_LEVELS) {
    for (const verifyAlg of DSA_LEVELS) {
      if (signAlg === verifyAlg) continue
      const { sig, kp } = bundles[signAlg]
      // Verify signAlg's signature under verifyAlg (mismatched sig/pubkey level).
      let rejected = false
      try {
        const r = pq.mldsa.verify(sig, msg, bundles[verifyAlg].kp.publicKey, verifyAlg)
        rejected = (r === false)
      } catch {
        rejected = true // length/format guard throwing is a valid rejection
      }
      t.ok(rejected, signAlg + ' sig under ' + verifyAlg + ' verifier rejected')

      // Also the pathological case: signAlg sig + signAlg's OWN pubkey but the
      // WRONG verifyAlg label. Must still reject.
      let rejected2 = false
      try {
        const r = pq.mldsa.verify(sig, msg, kp.publicKey, verifyAlg)
        rejected2 = (r === false)
      } catch {
        rejected2 = true
      }
      t.ok(rejected2, signAlg + ' sig+pk under ' + verifyAlg + ' label rejected')
    }
  }
})

// -------------------------------------------------------------------------
// 4. Hybrid signer: fail-closed. verify FALSE if EITHER half is tampered,
//    cross-keyed, or spliced from a foreign signature.
// -------------------------------------------------------------------------
test('fuzz: hybrid signer is fail-closed under tamper / cross-key / splice', function (t) {
  const rng = makeRng(MASTER_SEED + '/hybrid')
  const ED = pq.constants.HYBRID_ED25519_BYTES // 64
  const SIG = pq.constants.HYBRID_SIG_BYTES // 3373
  const ITER = 10

  for (let i = 0; i < ITER; i++) {
    const kpA = pq.hybridKeyPair()
    const kpB = pq.hybridKeyPair()
    const A = pq.hybridSigner(kpA)
    const B = pq.hybridSigner(kpB)
    const root = rng.bytes(32)
    const sigA = A.sign(root)
    t.is(sigA.byteLength, SIG, 'hybrid sig is exactly ' + SIG + ' bytes')

    // honest roundtrip
    t.is(A.verify(root, sigA), true, 'honest hybrid verify true')
    t.is(A.verify(root, sigA, { ed: kpA.ed.publicKey, mldsa: kpA.mldsa.publicKey }), true, 'explicit pubkeys verify true')

    // (a) flip a bit inside the Ed25519 half [0,64)
    {
      const bit = rng.int(ED * 8)
      const bad = b4a.from(sigA)
      bad[bit >> 3] ^= (1 << (bit & 7))
      t.is(A.verify(root, bad), false, 'flipped ed half -> false')
    }
    // (b) flip a bit inside the ML-DSA half [64,3373)
    {
      const bit = ED * 8 + rng.int((SIG - ED) * 8)
      const bad = b4a.from(sigA)
      bad[bit >> 3] ^= (1 << (bit & 7))
      t.is(A.verify(root, bad), false, 'flipped mldsa half -> false')
    }
    // (c) cross-key: correct half A + foreign pubkey B, both orientations
    t.is(A.verify(root, sigA, { ed: kpB.ed.publicKey, mldsa: kpA.mldsa.publicKey }), false, 'wrong ed pubkey -> false')
    t.is(A.verify(root, sigA, { ed: kpA.ed.publicKey, mldsa: kpB.mldsa.publicKey }), false, 'wrong mldsa pubkey -> false')

    // (d) splice: ed half from A's sig, mldsa half from B's sig over same root.
    const sigB = B.sign(root)
    const spliced = b4a.concat([sigA.subarray(0, ED), sigB.subarray(ED)])
    t.is(spliced.byteLength, SIG, 'spliced length preserved')
    // Against A's keys the mldsa half (B) fails; against B's keys the ed half (A) fails.
    t.is(A.verify(root, spliced), false, 'spliced sig rejected under A keys')
    t.is(B.verify(root, spliced, { ed: kpB.ed.publicKey, mldsa: kpB.mldsa.publicKey }), false, 'spliced sig rejected under B keys')

    // (e) reverse splice: ed half from B, mldsa half from A.
    const spliced2 = b4a.concat([sigB.subarray(0, ED), sigA.subarray(ED)])
    t.is(A.verify(root, spliced2), false, 'reverse-spliced rejected under A keys')

    // (f) wrong message: valid full sig over a different root.
    const otherRoot = flipOneBit(rng, root)
    t.is(A.verify(otherRoot, sigA), false, 'valid sig over wrong root -> false')

    // (g) classical-only forgery: zero the PQ half, keep the real ed half.
    const clsOnly = b4a.from(sigA)
    b4a.fill(clsOnly, 0x00, ED)
    t.is(A.verify(root, clsOnly), false, 'zeroed PQ half rejected')
  }
})

// -------------------------------------------------------------------------
// 5. Exact FIPS 203/204 byte sizes hold for every level across fresh keygens.
// -------------------------------------------------------------------------
test('property: exact FIPS byte sizes hold for all levels over many fresh keygens', function (t) {
  const rng = makeRng(MASTER_SEED + '/sizes')
  const N = 8

  for (const alg of KEM_LEVELS) {
    const p = pq.constants[alg]
    for (let i = 0; i < N; i++) {
      const kp = pq.mlkem.keygen(alg, rng.bytes(64))
      t.is(kp.publicKey.byteLength, p.publicKeyBytes, alg + ' pk bytes')
      t.is(kp.secretKey.byteLength, p.secretKeyBytes, alg + ' sk bytes')
      const enc = pq.mlkem.encapsulate(kp.publicKey, alg, rng.bytes(32))
      t.is(enc.ciphertext.byteLength, p.ciphertextBytes, alg + ' ct bytes')
      t.is(enc.sharedSecret.byteLength, p.sharedSecretBytes, alg + ' ss bytes')
    }
  }
  for (const alg of DSA_LEVELS) {
    const p = pq.constants[alg]
    for (let i = 0; i < N; i++) {
      const kp = pq.mldsa.keygen(alg, rng.bytes(32))
      t.is(kp.publicKey.byteLength, p.publicKeyBytes, alg + ' pk bytes')
      t.is(kp.secretKey.byteLength, p.secretKeyBytes, alg + ' sk bytes')
      const sig = pq.mldsa.sign(rng.bytes(1 + rng.int(32)), kp.secretKey, alg)
      t.is(sig.byteLength, p.signatureBytes, alg + ' sig bytes')
    }
  }
})

// -------------------------------------------------------------------------
// 6. Malformed-input fuzz: wrong lengths and non-buffers must NEVER crash the
//    process. Top-level ML-KEM/ML-DSA either throw a JS Error or return a
//    boolean false — never a silent accept. Hybrid.verify is total: it must
//    ALWAYS return a boolean (fail-closed), never throw.
// -------------------------------------------------------------------------
test('fuzz: malformed inputs never crash; primitives throw-or-false, hybrid.verify is total and returns false', function (t) {
  const rng = makeRng(MASTER_SEED + '/malformed')
  const NON_BUFFERS = [null, undefined, 0, 42, -1, 1.5, NaN, '', 'not-a-buffer', {}, [], true, false, () => {}, Symbol.iterator]

  // Helper: run fn, classify result. Must not return `true` for garbage.
  function safe (label, fn) {
    let threw = false
    let value
    try {
      value = fn()
    } catch (err) {
      threw = true
      t.ok(err instanceof Error, label + ' threw a real Error (not a raw value)')
    }
    if (!threw) {
      t.absent(value === true, label + ' garbage input did not falsely verify true')
    }
  }

  // --- non-buffer arguments at every top-level entry point ---
  for (const junk of NON_BUFFERS) {
    safe('mlkem.encapsulate(junk)', () => pq.mlkem.encapsulate(junk, 'ML-KEM-768', rng.bytes(32)))
    safe('mlkem.decapsulate(junk,sk)', () => pq.mlkem.decapsulate(junk, junk, 'ML-KEM-768'))
    safe('mldsa.sign(msg,junk)', () => pq.mldsa.sign(b4a.from('m'), junk, 'ML-DSA-65'))
    safe('mldsa.verify(junk...)', () => pq.mldsa.verify(junk, b4a.from('m'), junk, 'ML-DSA-65'))
    safe('mlkem.keygen(bad-alg)', () => pq.mlkem.keygen(junk))
    safe('mldsa.keygen(bad-alg)', () => pq.mldsa.keygen(junk))
  }

  // --- random wrong-length buffers at every entry point ---
  for (let i = 0; i < 150; i++) {
    const alg = KEM_LEVELS[rng.int(KEM_LEVELS.length)]
    const dalg = DSA_LEVELS[rng.int(DSA_LEVELS.length)]
    const len = rng.int(4100) // spans below/around/above all real sizes
    const buf = rng.bytes(len)
    const buf2 = rng.bytes(rng.int(4100))

    safe('mlkem.encapsulate rand-len', () => pq.mlkem.encapsulate(buf, alg, rng.bytes(32)))
    safe('mlkem.decapsulate rand-len', () => pq.mlkem.decapsulate(buf, buf2, alg))
    safe('mldsa.sign rand-len', () => pq.mldsa.sign(buf, buf2, dalg))
    safe('mldsa.verify rand-len', () => pq.mldsa.verify(buf, buf2, rng.bytes(rng.int(3000)), dalg))
    safe('mlkem.keygen bad seed', () => pq.mlkem.keygen(alg, buf))
    safe('mldsa.keygen bad seed', () => pq.mldsa.keygen(dalg, buf))
  }

  // --- hybrid.verify must be TOTAL: always a boolean, always false for junk ---
  const signer = pq.hybridSigner()
  const goodRoot = b4a.alloc(32, 0x5a)
  const goodSig = signer.sign(goodRoot)
  t.is(signer.verify(goodRoot, goodSig), true, 'hybrid honest sig still true')

  const rootJunk = [...NON_BUFFERS, goodRoot, b4a.alloc(0), b4a.alloc(31), b4a.alloc(64)]
  const sigJunk = [...NON_BUFFERS, b4a.alloc(0), b4a.alloc(3372), b4a.alloc(3374), rng.bytes(3373), goodSig.subarray(0, 100)]
  const pubJunk = [null, undefined, {}, { ed: null, mldsa: null }, { ed: b4a.alloc(32), mldsa: b4a.alloc(1952) }, { ed: 5, mldsa: 'x' }, []]

  let totalCalls = 0
  for (const r of rootJunk) {
    for (const s of sigJunk) {
      // vary the publics too, indexed off the running counter for coverage
      const p = pubJunk[totalCalls % pubJunk.length]
      let out
      let threw = false
      try {
        out = signer.verify(r, s, p)
      } catch (err) {
        threw = true
      }
      t.absent(threw, 'hybrid.verify never throws (fail-closed)')
      t.is(typeof out, 'boolean', 'hybrid.verify always returns a boolean')
      // The only true case in this grid would be (goodRoot, goodSig, valid own keys);
      // our pubJunk never supplies the signer's real keys, so every result is false.
      t.is(out, false, 'hybrid.verify returns false for junk root/sig/publics')
      totalCalls++
    }
  }
  t.ok(totalCalls > 40, 'exercised a broad malformed hybrid grid')
})
