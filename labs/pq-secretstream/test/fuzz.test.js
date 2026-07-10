// Property + fuzz tests for pq-secretstream.
//
// Everything under test here is pure in-process crypto (the networked
// PQSecretStream throws "not implemented"), so there is NO testnet / DHT to
// stand up and nothing to tear down — no streams, stores, swarms or tmp dirs.
//
// Reproducibility: all fuzzing *decisions* (mode-list shapes, tamper byte
// positions and values, random 32-byte secrets) are drawn from a seeded
// splitmix64 PRNG, so a failing iteration is reproducible by re-running with
// the same SEED (printed at load). The ML-KEM keygen/encaps entropy lives
// inside @noble/post-quantum, whose ml_kem768 object is frozen and cannot be
// seed-injected; the handshake invariants asserted here must hold for EVERY
// keypair regardless, and each failing handshake prints its exact wire bytes.

const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')

const pq = require('..')

const MODES = pq.constants.MODES // ['classical', 'hybrid']
const MODE_HYBRID = pq.constants.MODE_HYBRID
const MODE_CLASSICAL = pq.constants.MODE_CLASSICAL

// --- seeded splitmix64 PRNG ------------------------------------------------

const SEED = process.env.FUZZ_SEED ? Number(process.env.FUZZ_SEED) : 0x1234beef
process.stderr.write('[fuzz] SEED=' + SEED + ' (set FUZZ_SEED to reproduce)\n')

const MASK64 = (1n << 64n) - 1n

function makePrng (seedNum) {
  let s = BigInt(seedNum) & MASK64
  function next () {
    s = (s + 0x9e3779b97f4a7c15n) & MASK64
    let z = s
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64
    z = (z ^ (z >> 31n)) & MASK64
    return z
  }
  return {
    u32 () { return Number(next() & 0xffffffffn) },
    // uniform int in [0, n)
    int (n) { return n <= 0 ? 0 : this.u32() % n },
    bytes (len) {
      const out = b4a.alloc(len)
      let i = 0
      while (i < len) {
        let z = next()
        for (let b = 0; b < 8 && i < len; b++) {
          out[i++] = Number(z & 0xffn)
          z >>= 8n
        }
      }
      return out
    },
    pick (arr) { return arr[this.int(arr.length)] },
    shuffle (arr) {
      const a = arr.slice()
      for (let i = a.length - 1; i > 0; i--) {
        const j = this.int(i + 1)
        const t = a[i]; a[i] = a[j]; a[j] = t
      }
      return a
    }
  }
}

// Flip one bit of a 32-byte X25519 public key, but never bit 255 (the top bit
// of byte 31). RFC 7748 masks that bit in decodeUCoordinate, so flipping it is
// a documented no-op: the DH output — and thus the session key — is unchanged
// and both peers still agree. That is expected malleability, not a tamper the
// key schedule can (or needs to) detect.
function flipMeaningfulX25519Bit (rng, pk) {
  const out = b4a.from(pk)
  const idx = rng.int(out.byteLength)
  const bit = idx === 31 ? rng.int(7) : rng.int(8) // skip bit 7 of byte 31
  out[idx] ^= (1 << bit)
  return out
}

// popcount of the byte-wise difference between two equal-length buffers
function bitDiff (a, b) {
  let n = 0
  for (let i = 0; i < a.byteLength; i++) {
    let x = a[i] ^ b[i]
    while (x) { n += x & 1; x >>= 1 }
  }
  return n
}

// independent restatement of selectMode's spec, used as an oracle
function selectOracle (local, remote, requireHybrid) {
  for (const m of local.concat(remote)) {
    if (!MODES.includes(m)) return { throws: /unknown mode/ }
  }
  const common = local.filter((m) => remote.includes(m))
  if (common.length === 0) return { throws: /no common handshake mode/ }
  const mode = common.includes(MODE_HYBRID) ? MODE_HYBRID : MODE_CLASSICAL
  if (requireHybrid && mode !== MODE_HYBRID) return { throws: /downgrade rejected/ }
  return { mode }
}

const TOKEN_POOL = [MODE_CLASSICAL, MODE_HYBRID, 'kyber', 'x25519', 'HYBRID', '']

// random (possibly invalid, possibly empty, possibly duplicated) mode list
function randModeList (rng) {
  const len = rng.int(5) // 0..4
  const out = []
  for (let i = 0; i < len; i++) out.push(rng.pick(TOKEN_POOL))
  return out
}

// random VALID, non-empty mode list that is guaranteed to contain `must`
function randValidModes (rng, must) {
  const set = new Set([must])
  if (rng.int(2)) set.add(rng.pick(MODES))
  return rng.shuffle([...set])
}

const N_HANDSHAKE = 120 // each ~2.5ms of real ML-KEM
const N_CHEAP = 500

// ---------------------------------------------------------------------------
// 1. honest handshake => byte-identical hybrid session keys, over random keys
// ---------------------------------------------------------------------------

test('property: honest hybrid handshake derives byte-identical keys (fuzz)', function (t) {
  const rng = makePrng(SEED ^ 0xa11ce)
  for (let n = 0; n < N_HANDSHAKE; n++) {
    const iModes = randValidModes(rng, MODE_HYBRID)
    const rModes = randValidModes(rng, MODE_HYBRID)
    const requireHybrid = !!rng.int(2)

    const { state, offer } = pq.initiate({ modes: iModes, requireHybrid })
    const r = pq.respond(offer, { modes: rModes, requireHybrid })
    const i = pq.finalize(state, r.message)

    const ctx = 'iter ' + n + ' iModes=' + JSON.stringify(iModes) +
      ' rModes=' + JSON.stringify(rModes) +
      ' ct=' + b4a.toString(r.message.ciphertext, 'hex').slice(0, 24)

    if (i.mode !== MODE_HYBRID || r.mode !== MODE_HYBRID) {
      t.fail('expected hybrid mode; ' + ctx)
      return
    }
    if (i.sessionKey.byteLength !== 32) { t.fail('bad key length; ' + ctx); return }
    if (!b4a.equals(i.sessionKey, r.sessionKey)) {
      t.fail('initiator/responder keys diverged on honest run; ' + ctx)
      return
    }
  }
  t.pass(N_HANDSHAKE + ' honest hybrid handshakes all agreed byte-for-byte')
})

// ---------------------------------------------------------------------------
// 2. honest handshake agrees for EVERY negotiated mode (incl. classical),
//    and the negotiated mode matches the oracle
// ---------------------------------------------------------------------------

test('property: honest handshake agrees across all negotiated modes (fuzz)', function (t) {
  const rng = makePrng(SEED ^ 0xb0b)
  let sawHybrid = false
  let sawClassical = false
  for (let n = 0; n < N_HANDSHAKE; n++) {
    // guarantee a shared mode so the handshake completes
    const shared = rng.pick(MODES)
    const iModes = randValidModes(rng, shared)
    const rModes = randValidModes(rng, shared)

    const oracle = selectOracle(iModes, rModes, false)
    t.absent(oracle.throws, 'oracle: shared mode exists')

    const { state, offer } = pq.initiate({ modes: iModes })
    const r = pq.respond(offer, { modes: rModes })
    const i = pq.finalize(state, r.message)

    const ctx = 'iter ' + n + ' iModes=' + JSON.stringify(iModes) + ' rModes=' + JSON.stringify(rModes)
    if (r.mode !== oracle.mode || i.mode !== oracle.mode) {
      t.fail('negotiated mode != oracle (' + oracle.mode + '); got r=' + r.mode + ' i=' + i.mode + '; ' + ctx)
      return
    }
    if (!b4a.equals(i.sessionKey, r.sessionKey)) {
      t.fail('keys diverged for negotiated mode ' + r.mode + '; ' + ctx)
      return
    }
    if (r.mode === MODE_HYBRID) sawHybrid = true
    else sawClassical = true
  }
  t.ok(sawHybrid, 'fuzz exercised at least one hybrid negotiation')
  t.ok(sawClassical, 'fuzz exercised at least one classical negotiation')
})

// ---------------------------------------------------------------------------
// 3. tampered ML-KEM ciphertext => different key (post-quantum half)
// ---------------------------------------------------------------------------

test('fuzz: tampered ML-KEM ciphertext yields a different key', function (t) {
  const rng = makePrng(SEED ^ 0xc1)
  for (let n = 0; n < N_HANDSHAKE; n++) {
    const { state, offer } = pq.initiate({ modes: [MODE_HYBRID] })
    const r = pq.respond(offer, { modes: [MODE_HYBRID] })

    let tamperedCt
    if (rng.int(2)) {
      // a fresh, VALID encapsulation against the same pk: decapsulates cleanly
      // to a *different* shared secret than the responder derived.
      tamperedCt = pq.encapsulate(offer.mlkemPk).ciphertext
    } else {
      // flip random bits in the ciphertext: ML-KEM implicit rejection returns a
      // deterministic but different pseudo-random secret (it does not error).
      tamperedCt = b4a.from(r.message.ciphertext)
      const flips = 1 + rng.int(4)
      for (let f = 0; f < flips; f++) {
        const idx = rng.int(tamperedCt.byteLength)
        tamperedCt[idx] ^= (1 << rng.int(8))
      }
    }

    const ctx = 'iter ' + n + ' orig=' + b4a.toString(r.message.ciphertext, 'hex').slice(0, 24) +
      ' tampered=' + b4a.toString(tamperedCt, 'hex').slice(0, 24)

    if (b4a.equals(tamperedCt, r.message.ciphertext)) continue // no-op flip, skip

    const i = pq.finalize(state, { ...r.message, ciphertext: tamperedCt })
    if (b4a.equals(i.sessionKey, r.sessionKey)) {
      t.fail('tampered ML-KEM ciphertext produced the SAME session key; ' + ctx)
      return
    }
  }
  t.pass('every tampered ML-KEM ciphertext broke key agreement')
})

// ---------------------------------------------------------------------------
// 4. tampered X25519 share => different key (classical half)
// ---------------------------------------------------------------------------

test('fuzz: tampered X25519 share yields a different key (or is rejected)', function (t) {
  const rng = makePrng(SEED ^ 0xd2)
  for (let n = 0; n < N_HANDSHAKE; n++) {
    const { state, offer } = pq.initiate({ modes: [MODE_HYBRID] })
    const r = pq.respond(offer, { modes: [MODE_HYBRID] })

    let tamperedPk
    if (rng.int(2)) {
      // a foreign but well-formed X25519 public key (fresh keypair)
      const { offer: o2 } = pq.initiate({ modes: [MODE_HYBRID] })
      tamperedPk = o2.x25519pk
    } else {
      tamperedPk = flipMeaningfulX25519Bit(rng, r.message.x25519pk)
    }
    if (b4a.equals(tamperedPk, r.message.x25519pk)) continue

    const ctx = 'iter ' + n + ' orig=' + b4a.toString(r.message.x25519pk, 'hex').slice(0, 16) +
      ' tampered=' + b4a.toString(tamperedPk, 'hex').slice(0, 16)

    // A tampered share either changes the DH (=> different key) or, for a rare
    // low-order point, makes scalarmult throw. Both mean the tamper is detected.
    let i
    try {
      i = pq.finalize(state, { ...r.message, x25519pk: tamperedPk })
    } catch (err) {
      continue // rejected outright — tamper caught
    }
    if (b4a.equals(i.sessionKey, r.sessionKey)) {
      t.fail('tampered X25519 share produced the SAME session key; ' + ctx)
      return
    }
  }
  t.pass('every tampered X25519 share broke key agreement (or was rejected)')
})

// ---------------------------------------------------------------------------
// 5. any single-byte flip anywhere in the responder message breaks the key
// ---------------------------------------------------------------------------

test('fuzz: any single-byte flip in the response breaks agreement', function (t) {
  const rng = makePrng(SEED ^ 0xe3)
  for (let n = 0; n < 60; n++) {
    const { state, offer } = pq.initiate({ modes: [MODE_HYBRID] })
    const r = pq.respond(offer, { modes: [MODE_HYBRID] })

    // flip one meaningful bit in either mutable key-material field
    const field = rng.int(2) // 0 -> x25519pk, 1 -> ciphertext
    let target, idx
    if (field === 0) {
      target = flipMeaningfulX25519Bit(rng, r.message.x25519pk) // avoids masked bit 255
      idx = 'meaningful'
    } else {
      target = b4a.from(r.message.ciphertext)
      idx = rng.int(target.byteLength)
      target[idx] ^= (1 << rng.int(8))
    }

    const msg = field === 0
      ? { ...r.message, x25519pk: target }
      : { ...r.message, ciphertext: target }

    const ctx = 'iter ' + n + ' field=' + (field === 0 ? 'x25519pk' : 'ciphertext') + ' idx=' + idx

    let i
    try { i = pq.finalize(state, msg) } catch (err) { continue }
    if (b4a.equals(i.sessionKey, r.sessionKey)) {
      t.fail('single-byte flip left the session key unchanged; ' + ctx)
      return
    }
  }
  t.pass('every single-byte flip broke key agreement (or was rejected)')
})

// ---------------------------------------------------------------------------
// 6. downgrade — transcript binding: tampering EITHER offered-mode list
//    (without touching policy) makes the two sides derive different keys
// ---------------------------------------------------------------------------

test('fuzz: downgrade via offered-mode tampering diverges keys (both directions)', function (t) {
  const rng = makePrng(SEED ^ 0xf4)
  for (let n = 0; n < N_HANDSHAKE; n++) {
    // requireHybrid OFF so the policy check never short-circuits; we prove the
    // cryptographic transcript binding alone breaks the shared key.
    const { state, offer } = pq.initiate({ modes: [MODE_CLASSICAL, MODE_HYBRID] })

    if (rng.int(2)) {
      // MITM strips 'hybrid' from the offer the responder authenticates, but the
      // initiator still binds its GENUINE offered modes on finalize.
      const tampered = { ...offer, modes: [MODE_CLASSICAL] }
      const r = pq.respond(tampered, { modes: [MODE_CLASSICAL, MODE_HYBRID] })
      const i = pq.finalize(state, r.message)
      if (b4a.equals(i.sessionKey, r.sessionKey)) {
        t.fail('iter ' + n + ': stripped OFFER did not diverge keys')
        return
      }
    } else {
      // MITM strips 'hybrid' from the responder's returned mode list, which the
      // initiator authenticates on finalize; the responder bound its genuine list.
      const r = pq.respond(offer, { modes: [MODE_CLASSICAL, MODE_HYBRID] })
      const tamperedMsg = { ...r.message, modes: [MODE_CLASSICAL] }
      const i = pq.finalize(state, tamperedMsg)
      if (b4a.equals(i.sessionKey, r.sessionKey)) {
        t.fail('iter ' + n + ': stripped RESPONSE modes did not diverge keys')
        return
      }
    }
  }

  // control: an untampered run must always agree (guards against a test that
  // would "pass" even if divergence were spurious)
  const clean = pq.initiate({ modes: [MODE_CLASSICAL, MODE_HYBRID] })
  const rc = pq.respond(clean.offer, { modes: [MODE_CLASSICAL, MODE_HYBRID] })
  const ic = pq.finalize(clean.state, rc.message)
  t.alike(ic.sessionKey, rc.sessionKey, 'control: untampered run agrees')
})

// ---------------------------------------------------------------------------
// 7. downgrade — policy: requireHybrid hard-fails exactly when no shared hybrid
// ---------------------------------------------------------------------------

test('fuzz: requireHybrid policy matches oracle on random mode lists', function (t) {
  const rng = makePrng(SEED ^ 0x1357)
  for (let n = 0; n < N_CHEAP; n++) {
    const local = randModeList(rng)
    const remote = randModeList(rng)
    const requireHybrid = !!rng.int(2)
    const oracle = selectOracle(local, remote, requireHybrid)
    const ctx = 'iter ' + n + ' local=' + JSON.stringify(local) + ' remote=' + JSON.stringify(remote) + ' req=' + requireHybrid

    if (oracle.throws) {
      try {
        const got = pq.selectMode(local, remote, { requireHybrid })
        t.fail('expected throw ' + oracle.throws + ' but got ' + got + '; ' + ctx)
        return
      } catch (err) {
        if (!oracle.throws.test(err.message)) {
          t.fail('wrong error "' + err.message + '" expected ' + oracle.throws + '; ' + ctx)
          return
        }
      }
    } else {
      let got
      try {
        got = pq.selectMode(local, remote, { requireHybrid })
      } catch (err) {
        t.fail('unexpected throw "' + err.message + '" expected ' + oracle.mode + '; ' + ctx)
        return
      }
      if (got !== oracle.mode) {
        t.fail('selectMode=' + got + ' oracle=' + oracle.mode + '; ' + ctx)
        return
      }
    }
  }
  t.pass(N_CHEAP + ' random negotiations matched the oracle')
})

test('fuzz: respond/finalize enforce requireHybrid consistently with selectMode', function (t) {
  const rng = makePrng(SEED ^ 0x2468)
  let sawReject = 0
  for (let n = 0; n < 80; n++) {
    // both peers valid & non-empty, but the intersection may lack hybrid
    const local = rng.shuffle([...new Set(MODES.filter(() => rng.int(2)))])
    const remote = rng.shuffle([...new Set(MODES.filter(() => rng.int(2)))])
    if (local.length === 0 || remote.length === 0) continue

    const requireHybrid = !!rng.int(2)
    const oracle = selectOracle(local, remote, requireHybrid)
    const ctx = 'iter ' + n + ' local=' + JSON.stringify(local) + ' remote=' + JSON.stringify(remote) + ' req=' + requireHybrid

    const { state, offer } = pq.initiate({ modes: local, requireHybrid })

    if (oracle.throws) {
      try {
        pq.respond(offer, { modes: remote, requireHybrid })
        t.fail('respond should have thrown ' + oracle.throws + '; ' + ctx)
        return
      } catch (err) {
        if (!oracle.throws.test(err.message)) {
          t.fail('respond wrong error "' + err.message + '"; ' + ctx)
          return
        }
        sawReject++
      }
    } else {
      const r = pq.respond(offer, { modes: remote, requireHybrid })
      const i = pq.finalize(state, r.message)
      if (r.mode !== oracle.mode || i.mode !== oracle.mode) {
        t.fail('mode mismatch r=' + r.mode + ' i=' + i.mode + ' oracle=' + oracle.mode + '; ' + ctx)
        return
      }
      if (!b4a.equals(i.sessionKey, r.sessionKey)) {
        t.fail('keys diverged on accepted negotiation; ' + ctx)
        return
      }
    }
  }
  t.ok(sawReject > 0, 'fuzz exercised at least one requireHybrid/no-common rejection')
})

// ---------------------------------------------------------------------------
// 8. combineSecrets: order-sensitive, domain-separated, avalanching
// ---------------------------------------------------------------------------

test('property: combineSecrets is order-sensitive and domain-separated (fuzz)', function (t) {
  const rng = makePrng(SEED ^ 0x9753)
  let minAvalanche = 256

  for (let n = 0; n < N_CHEAP; n++) {
    const a = rng.bytes(32)
    const b = rng.bytes(32)

    const ab = pq.combineSecrets(a, b)
    if (ab.byteLength !== 32) { t.fail('output not 32 bytes'); return }

    // deterministic
    if (!b4a.equals(ab, pq.combineSecrets(a, b))) { t.fail('non-deterministic'); return }

    // order-sensitive (a and b are random 32-byte => equal with negligible prob)
    if (b4a.equals(a, b)) continue
    const ba = pq.combineSecrets(b, a)
    if (b4a.equals(ab, ba)) {
      t.fail('combineSecrets not order-sensitive for a=' + b4a.toString(a, 'hex') + ' b=' + b4a.toString(b, 'hex'))
      return
    }

    // domain separation: must differ from an un-namespaced hash of the same
    // inputs (proves NS_COMBINE prefix is actually mixed in)
    const noNs = b4a.alloc(32)
    sodium.crypto_generichash_batch(noNs, [a, b])
    if (b4a.equals(ab, noNs)) { t.fail('combineSecrets missing domain separation'); return }

    // ...and differ from a hash whose namespace is a plausible sibling label
    const otherNs = b4a.alloc(32)
    sodium.crypto_generichash_batch(otherNs, [b4a.from('pq-secretstream/session/v0'), a, b])
    if (b4a.equals(ab, otherNs)) { t.fail('combineSecrets namespace collides with session ns'); return }

    // output must not simply echo an input
    if (b4a.equals(ab, a) || b4a.equals(ab, b)) { t.fail('output echoes an input'); return }

    // avalanche: flipping one bit of `a` should change ~half the output bits
    const a2 = b4a.from(a)
    a2[rng.int(32)] ^= (1 << rng.int(8))
    const ab2 = pq.combineSecrets(a2, b)
    const d = bitDiff(ab, ab2)
    if (d === 0) { t.fail('single-bit input change left output identical'); return }
    if (d < minAvalanche) minAvalanche = d
  }

  // BLAKE2b avalanche: a one-bit change should flip far more than a handful of
  // output bits; a weak/broken combiner (xor, truncation) would not.
  t.ok(minAvalanche >= 40, 'min avalanche over ' + N_CHEAP + ' trials = ' + minAvalanche + ' bits (>=40)')

  // explicit input validation still holds under fuzz
  t.exception(() => pq.combineSecrets(rng.bytes(16), rng.bytes(32)), /32-byte/)
  t.exception(() => pq.combineSecrets(rng.bytes(32), rng.bytes(31)), /32-byte/)
})

// ---------------------------------------------------------------------------
// 9. bindModes: order-independent, collision-free, domain-separated
// ---------------------------------------------------------------------------

test('property: bindModes is order-independent, distinct per set, domain-separated', function (t) {
  const rng = makePrng(SEED ^ 0x8642)
  const sets = [[MODE_CLASSICAL], [MODE_HYBRID], [MODE_CLASSICAL, MODE_HYBRID]]
  const digests = sets.map((s) => pq.bindModes(s))

  // 32-byte, distinct across the three distinct offered sets
  for (const d of digests) t.is(d.byteLength, 32)
  for (let i = 0; i < digests.length; i++) {
    for (let j = i + 1; j < digests.length; j++) {
      if (b4a.equals(digests[i], digests[j])) {
        t.fail('bindModes collision between ' + JSON.stringify(sets[i]) + ' and ' + JSON.stringify(sets[j]))
        return
      }
    }
  }

  // order-independent: any permutation of the same multiset => same digest
  for (let n = 0; n < N_CHEAP; n++) {
    const base = sets[rng.int(sets.length)]
    const perm = rng.shuffle(base)
    if (!b4a.equals(pq.bindModes(base), pq.bindModes(perm))) {
      t.fail('bindModes not order-independent for ' + JSON.stringify(perm))
      return
    }
  }

  // domain separation: differ from an un-namespaced hash of the joined label
  const noNs = b4a.alloc(32)
  sodium.crypto_generichash_batch(noNs, [b4a.from('classical,hybrid')])
  t.unlike(pq.bindModes([MODE_CLASSICAL, MODE_HYBRID]), noNs, 'bindModes is namespaced')

  t.exception(() => pq.bindModes([]), /non-empty/)
  t.exception(() => pq.bindModes(['kyber']), /unknown mode/)
  t.pass('bindModes order-independent + collision-free over ' + N_CHEAP + ' trials')
})
