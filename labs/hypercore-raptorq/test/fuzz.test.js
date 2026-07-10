// Property + fuzz tests for hypercore-raptorq. Every random draw comes from a
// SEEDED PRNG so any failure is reproducible from the printed seed. The tests
// are written so they would FAIL if the property under test were violated:
//   - GF(256) field axioms over random elements (comm/assoc/distrib, inverses,
//     addition === XOR) and the addScaled/scale kernels used by decode;
//   - systematic no-loss transfer is an EXACT passthrough;
//   - over random k and random loss patterns, once k independent symbols are
//     in, decode reconstructs EXACTLY (b4a.equals) — never approximately;
//   - a tampered repair symbol is caught by leaf-hash auth: decode either
//     throws or returns the true blocks, but is NEVER silently wrong;
//   - rank-deficiency (too few / only dependent symbols) fails cleanly and
//     never hangs or raises rank past the truth.

const test = require('brittle')
const b4a = require('b4a')
const { Encoder, Decoder, leafHash, coeffsFor, gf } = require('..')

// ---- seeded PRNG (mulberry32): deterministic, reproducible from a seed ------
function makeRng (seed) {
  let s = (seed >>> 0) || 0x1a2b3c4d
  const next = () => {
    s = (s + 0x6d2b79f5) >>> 0
    let t = s
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0)
  }
  return {
    u32: next,
    byte: () => next() & 0xff,
    // integer in [lo, hi]
    range: (lo, hi) => lo + (next() % (hi - lo + 1)),
    float: () => next() / 0x100000000
  }
}

function randBlocks (rng, k, size) {
  const out = new Array(k)
  for (let i = 0; i < k; i++) {
    const b = b4a.alloc(size)
    for (let j = 0; j < size; j++) b[j] = rng.byte()
    out[i] = b
  }
  return out
}

// naive GF multiply straight from the reducing polynomial — an INDEPENDENT
// reference implementation, so a bug in the log/exp tables cannot hide behind
// itself. (Russian-peasant carry-less multiply mod x^8+x^4+x^3+x^2+1.)
function naiveMul (a, b) {
  let p = 0
  a &= 0xff; b &= 0xff
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a
    const hi = a & 0x80
    a = (a << 1) & 0xff
    if (hi) a ^= 0x1d
    b >>= 1
  }
  return p & 0xff
}

// ---------------------------------------------------------------------------
// 1. GF(256) field axioms over random elements
// ---------------------------------------------------------------------------

test('fuzz: gf.mul agrees with an independent naive multiply for all pairs', function (t) {
  // exhaustive over the whole field — the reference is derived from the poly,
  // not the tables, so this catches a wrong table build.
  let bad = 0
  for (let a = 0; a < 256; a++) {
    for (let b = 0; b < 256; b++) {
      if (gf.mul(a, b) !== naiveMul(a, b)) bad++
    }
  }
  t.is(bad, 0, 'gf.mul === naiveMul over all 65536 pairs')
})

test('fuzz: GF(256) field axioms hold on random elements (seeded)', function (t) {
  const seed = 0xF00D01
  const rng = makeRng(seed)
  const N = 6000
  for (let i = 0; i < N; i++) {
    const a = rng.byte()
    const b = rng.byte()
    const cc = rng.byte()
    const ctx = 'seed=' + seed + ' i=' + i + ' a=' + a + ' b=' + b + ' c=' + cc

    // commutativity
    t.is(gf.mul(a, b), gf.mul(b, a), 'commutative ' + ctx)
    // associativity
    t.is(gf.mul(gf.mul(a, b), cc), gf.mul(a, gf.mul(b, cc)), 'associative ' + ctx)
    // distributivity over addition, where addition === XOR in GF(2^8)
    t.is(gf.mul(a, b ^ cc), gf.mul(a, b) ^ gf.mul(a, cc), 'distributive ' + ctx)
    // multiplicative identity
    t.is(gf.mul(a, 1), a, 'identity ' + ctx)
    // annihilator
    t.is(gf.mul(a, 0), 0, 'zero ' + ctx)
    // inverse: a*inv(a) === 1 for a != 0, and div inverts mul
    if (a !== 0) {
      t.is(gf.mul(a, gf.inv(a)), 1, 'a*inv(a)=1 ' + ctx)
      if (b !== 0) {
        t.is(gf.div(gf.mul(a, b), b), a, 'div undoes mul ' + ctx)
        t.is(gf.mul(gf.div(a, b), b), a, 'mul undoes div ' + ctx)
      }
    }
  }
})

test('fuzz: addition is XOR — a^a=0 and (a^b)^b=a for random elements', function (t) {
  const rng = makeRng(0xADD)
  for (let i = 0; i < 4000; i++) {
    const a = rng.byte()
    const b = rng.byte()
    t.is(a ^ a, 0, 'a^a=0')
    t.is((a ^ b) ^ b, a, '(a^b)^b=a')
    // characteristic 2: a + a = 0, so mul(a,b) ^ mul(a,b) = 0
    t.is(gf.mul(a, b) ^ gf.mul(a, b), 0, '2*(a*b)=0')
  }
})

test('fuzz: addScaled and scale kernels match a naive GF reference', function (t) {
  // These two kernels are the entire inner loop of decode; a bug here is a
  // silent-wrong-data bug. Verify them against naiveMul on random rows.
  const rng = makeRng(0x5CA1ED)
  for (let it = 0; it < 800; it++) {
    const len = rng.range(1, 40)
    const factor = rng.byte()
    const dst = new Uint8Array(len)
    const src = new Uint8Array(len)
    for (let j = 0; j < len; j++) { dst[j] = rng.byte(); src[j] = rng.byte() }

    // addScaled: dst[j] ^= factor*src[j]
    const expectAdd = new Uint8Array(len)
    for (let j = 0; j < len; j++) expectAdd[j] = dst[j] ^ naiveMul(factor, src[j])
    const gotAdd = new Uint8Array(dst)
    gf.addScaled(gotAdd, src, factor, len)
    t.ok(b4a.equals(gotAdd, expectAdd), 'addScaled matches (it=' + it + ' factor=' + factor + ')')

    // scale: dst[j] = factor*dst[j]
    const expectScale = new Uint8Array(len)
    for (let j = 0; j < len; j++) expectScale[j] = naiveMul(factor, dst[j])
    const gotScale = new Uint8Array(dst)
    gf.scale(gotScale, factor, len)
    t.ok(b4a.equals(gotScale, expectScale), 'scale matches (it=' + it + ' factor=' + factor + ')')
  }
})

// ---------------------------------------------------------------------------
// 2. Systematic no-loss transfer is an exact passthrough
// ---------------------------------------------------------------------------

test('fuzz: systematic symbols are source blocks verbatim; no-loss decode is exact', function (t) {
  const rng = makeRng(0x5157EA)
  for (let it = 0; it < 200; it++) {
    const k = rng.range(1, 40)
    const size = rng.range(1, 200)
    const blocks = randBlocks(rng, k, size)
    const enc = new Encoder(blocks)

    // passthrough: esi < k returns the source block byte-for-byte
    for (let esi = 0; esi < k; esi++) {
      t.ok(b4a.equals(enc.symbol(esi), blocks[esi]), 'passthrough esi=' + esi + ' it=' + it)
    }

    // decode from exactly the k systematic symbols reconstructs exactly
    const dec = new Decoder(k, { symbolSize: enc.symbolSize, lengths: enc.lengths })
    let ready = false
    for (const m of enc.systematicSymbols()) ready = dec.add(m)
    t.ok(ready, 'decodable from k systematic (it=' + it + ')')
    const out = dec.decode()
    let ok = out.length === k
    for (let i = 0; i < k && ok; i++) ok = b4a.equals(out[i], blocks[i])
    t.ok(ok, 'no-loss decode exact (it=' + it + ' k=' + k + ' size=' + size + ')')
  }
})

// ---------------------------------------------------------------------------
// 3. Random k + random loss: decode reconstructs EXACTLY from any k independent
// ---------------------------------------------------------------------------

test('fuzz: random k and random loss — once decodable, decode is EXACT (seeded)', function (t) {
  const seed = 0x105510
  const rng = makeRng(seed)
  let decodableCount = 0
  for (let it = 0; it < 300; it++) {
    const k = rng.range(1, 40)
    const size = rng.range(1, 160)
    const blocks = randBlocks(rng, k, size)
    const enc = new Encoder(blocks)

    // a fat stream: all k systematic + a generous pile of repair symbols
    const repairN = k + 12
    const stream = enc.systematicSymbols().concat(enc.repairSymbols(repairN))

    // drop each symbol independently with a random loss probability
    const loss = rng.float() * 0.6 // up to 60% loss
    const kept = stream.filter(() => rng.float() > loss)

    const dec = new Decoder(k, { symbolSize: enc.symbolSize, lengths: enc.lengths })
    let ready = false
    for (const m of kept) if (dec.add(m)) { ready = true; break }

    if (!ready) {
      // too much loss this round: must fail cleanly, never silently
      t.absent(dec.decodable, 'not decodable under loss=' + loss.toFixed(2) + ' it=' + it)
      t.exception(() => dec.decode(), /need k independent symbols/, 'clean fail it=' + it)
      continue
    }
    decodableCount++

    // rank must be exactly k when decodable (no over/under counting)
    t.is(dec.rank, k, 'rank===k when decodable it=' + it)

    const out = dec.decode()
    let ok = out.length === k
    let firstBad = -1
    for (let i = 0; i < k; i++) {
      if (!b4a.equals(out[i], blocks[i])) { ok = false; if (firstBad < 0) firstBad = i }
    }
    t.ok(ok, 'EXACT reconstruction it=' + it + ' k=' + k + ' size=' + size +
      ' loss=' + loss.toFixed(2) + (firstBad >= 0 ? ' firstBad=' + firstBad : ''))
  }
  t.ok(decodableCount > 200, 'most rounds were decodable (' + decodableCount + '/300)')
})

test('fuzz: decode from a RANDOM k-subset of repair-only symbols is exact when full-rank', function (t) {
  // Pure repair symbols (esi >= k) are random linear combinations. Feeding a
  // random selection reaches rank k with tiny overhead; result must be exact.
  const rng = makeRng(0x2EB0DE)
  for (let it = 0; it < 150; it++) {
    const k = rng.range(1, 36)
    const size = rng.range(1, 128)
    const blocks = randBlocks(rng, k, size)
    const enc = new Encoder(blocks)
    const dec = new Decoder(k, { symbolSize: enc.symbolSize, lengths: enc.lengths })

    let esi = k
    const cap = k + 400
    while (!dec.decodable && esi < k + cap) dec.add(enc.message(esi++))
    t.ok(dec.decodable, 'reached rank k from repair symbols it=' + it + ' k=' + k)

    const out = dec.decode()
    let ok = true
    for (let i = 0; i < k; i++) if (!b4a.equals(out[i], blocks[i])) ok = false
    t.ok(ok, 'repair-only reconstruction exact it=' + it + ' k=' + k + ' size=' + size)
  }
})

test('fuzz: variable-length blocks round-trip exactly through repair symbols', function (t) {
  const rng = makeRng(0x7A91EE)
  for (let it = 0; it < 120; it++) {
    const k = rng.range(1, 24)
    const blocks = new Array(k)
    for (let i = 0; i < k; i++) {
      const len = rng.range(1, 90)
      const b = b4a.alloc(len)
      for (let j = 0; j < len; j++) b[j] = rng.byte()
      blocks[i] = b
    }
    const enc = new Encoder(blocks)
    const dec = new Decoder(k, { symbolSize: enc.symbolSize, lengths: enc.lengths })
    for (const m of enc.repairSymbols(k + 8)) if (dec.add(m)) break
    t.ok(dec.decodable, 'decodable it=' + it)
    const out = dec.decode()
    let ok = true
    for (let i = 0; i < k; i++) {
      ok = ok && out[i].length === blocks[i].length && b4a.equals(out[i], blocks[i])
    }
    t.ok(ok, 'variable-length exact round-trip it=' + it + ' k=' + k)
  }
})

// ---------------------------------------------------------------------------
// 4. Tampered repair symbol is REJECTED — never silently wrong
// ---------------------------------------------------------------------------

test('fuzz: with hashes, decode is NEVER silently wrong under random tampering', function (t) {
  // Strong invariant: when leaf hashes are supplied, decode() either throws or
  // returns the TRUE blocks. It must never return blocks that differ from the
  // source. We tamper random symbols in the stream and force some rounds where
  // a tampered repair is the only source of a missing pivot.
  const seed = 0x7A3B77
  const rng = makeRng(seed)
  let rejected = 0
  let clean = 0
  for (let it = 0; it < 250; it++) {
    const k = rng.range(2, 32)
    const size = rng.range(2, 140)
    const blocks = randBlocks(rng, k, size)
    const hashes = blocks.map(leafHash)
    const enc = new Encoder(blocks)

    // Drop a random subset of systematic symbols so a repair symbol MUST become
    // a pivot for the missing blocks; then tamper some repair symbols.
    const drop = new Set()
    const nDrop = rng.range(1, k) // at least one systematic missing
    while (drop.size < nDrop) drop.add(rng.range(0, k - 1))

    const stream = []
    for (let esi = 0; esi < k; esi++) if (!drop.has(esi)) stream.push(enc.message(esi))
    for (const m of enc.repairSymbols(nDrop + 6)) stream.push(m)

    // tamper each repair symbol independently with some probability
    for (const m of stream) {
      if (m.esi >= k && rng.float() < 0.5) {
        m.symbol = b4a.from(m.symbol)
        m.symbol[rng.range(0, m.symbol.length - 1)] ^= (1 + rng.range(0, 254))
      }
    }

    const dec = new Decoder(k, { symbolSize: enc.symbolSize, lengths: enc.lengths, hashes })
    for (const m of stream) if (dec.add(m)) break

    if (!dec.decodable) {
      t.exception(() => dec.decode(), /need k independent symbols/, 'undecodable fails clean it=' + it)
      continue
    }

    let threw = false
    let out = null
    try {
      out = dec.decode()
    } catch (err) {
      threw = true
      t.ok(/failed authentication/.test(err.message), 'rejection is an auth failure it=' + it + ' seed=' + seed)
      rejected++
    }
    if (!threw) {
      // If it returned, it MUST be the true blocks — silent-wrong is a bug.
      let ok = true
      for (let i = 0; i < k; i++) if (!b4a.equals(out[i], blocks[i])) ok = false
      t.ok(ok, 'returned output is the TRUE blocks (not silently wrong) it=' + it + ' seed=' + seed)
      clean++
    }
  }
  t.comment('tamper fuzz: ' + rejected + ' rejected, ' + clean + ' clean-decoded')
  t.ok(rejected > 0, 'at least some rounds exercised the auth rejection path (' + rejected + ')')
})

test('fuzz: a single-byte flip in the pivot repair symbol is always caught', function (t) {
  // Construct the worst case every round: exactly k-1 honest systematic + one
  // tampered repair that supplies the last pivot. Authentication must reject.
  const rng = makeRng(0x1B17)
  for (let it = 0; it < 200; it++) {
    const k = rng.range(2, 30)
    const size = rng.range(2, 128)
    const blocks = randBlocks(rng, k, size)
    const hashes = blocks.map(leafHash)
    const enc = new Encoder(blocks)
    const dec = new Decoder(k, { symbolSize: enc.symbolSize, lengths: enc.lengths, hashes })

    const sys = enc.systematicSymbols()
    const missing = rng.range(0, k - 1)
    for (let i = 0; i < k; i++) if (i !== missing) dec.add(sys[i])
    t.absent(dec.decodable, 'still missing one block it=' + it)

    const tampered = enc.message(k + rng.range(0, 5))
    tampered.symbol = b4a.from(tampered.symbol)
    const pos = rng.range(0, tampered.symbol.length - 1)
    tampered.symbol[pos] ^= (1 + rng.range(0, 254)) // guaranteed non-zero flip

    const now = dec.add(tampered)
    if (!now) {
      // extremely unlikely: repair row's coeff at `missing` was 0 after
      // reduction, so it was dropped. Then group is still undecodable — clean.
      t.absent(dec.decodable, 'dropped dependent tamper leaves it undecodable it=' + it)
      continue
    }
    t.exception(() => dec.decode(), /failed authentication/, 'tamper rejected it=' + it + ' k=' + k)
  }
})

// ---------------------------------------------------------------------------
// 5. Rank-deficiency fails cleanly and never hangs
// ---------------------------------------------------------------------------

test('fuzz: too few symbols fails cleanly (throws, no hang, rank never exceeds k)', function (t) {
  const rng = makeRng(0xDEF1C17)
  for (let it = 0; it < 120; it++) {
    const k = rng.range(2, 40)
    const size = rng.range(1, 100)
    const blocks = randBlocks(rng, k, size)
    const enc = new Encoder(blocks)
    const dec = new Decoder(k, { symbolSize: enc.symbolSize, lengths: enc.lengths })

    // feed strictly fewer than k DISTINCT independent symbols
    const nFeed = rng.range(0, k - 1)
    const sys = enc.systematicSymbols()
    for (let i = 0; i < nFeed; i++) dec.add(sys[i])
    t.is(dec.rank, nFeed, 'rank equals distinct independent fed it=' + it)
    t.absent(dec.decodable, 'not decodable with ' + nFeed + '/' + k + ' it=' + it)
    t.exception(() => dec.decode(), /need k independent symbols/, 'clean throw it=' + it)
  }
})

test('fuzz: flooding with linearly DEPENDENT symbols never raises rank or hangs', function (t) {
  const rng = makeRng(0xC0FFEE)
  for (let it = 0; it < 60; it++) {
    const k = rng.range(2, 24)
    const size = rng.range(1, 80)
    const blocks = randBlocks(rng, k, size)
    const enc = new Encoder(blocks)
    const dec = new Decoder(k, { symbolSize: enc.symbolSize, lengths: enc.lengths })

    // give it k-1 independent systematic symbols
    const sys = enc.systematicSymbols()
    const present = []
    for (let i = 0; i < k - 1; i++) { dec.add(sys[i]); present.push(i) }
    const rankBefore = dec.rank
    t.is(rankBefore, k - 1, 'rank k-1 it=' + it)

    // now flood with symbols that live in the span of the present ones:
    // re-feed the same systematic symbols many times (all dependent now).
    for (let f = 0; f < 200; f++) {
      const pick = present[rng.range(0, present.length - 1)]
      const dependable = dec.add(sys[pick])
      t.absent(dependable, 'dependent add does not become decodable it=' + it + ' f=' + f)
    }
    t.is(dec.rank, k - 1, 'rank unchanged after 200 dependent adds it=' + it)
    t.absent(dec.decodable, 'still undecodable it=' + it)
    t.exception(() => dec.decode(), /need k independent symbols/, 'still fails clean it=' + it)

    // the one missing independent symbol finally makes it decodable & exact
    t.ok(dec.add(sys[k - 1]), 'last independent symbol completes it=' + it)
    const out = dec.decode()
    let ok = true
    for (let i = 0; i < k; i++) if (!b4a.equals(out[i], blocks[i])) ok = false
    t.ok(ok, 'exact after completion it=' + it)
  }
})

test('fuzz: coeffsFor is a unit vector for esi<k and a non-zero row for esi>=k', function (t) {
  const rng = makeRng(0xC0EF)
  for (let it = 0; it < 400; it++) {
    const k = rng.range(1, 48)
    const esi = rng.range(0, k - 1)
    const unit = coeffsFor(esi, k)
    t.is(unit.length, k, 'coeff length k')
    let ones = 0
    for (let i = 0; i < k; i++) { if (unit[i] === 1 && i === esi) ones++; else t.is(unit[i], 0, 'zero off-pivot') }
    t.is(ones, 1, 'systematic esi=' + esi + ' is unit vector e_esi')

    const repairEsi = k + rng.range(0, 500)
    const row = coeffsFor(repairEsi, k)
    let anyNonzero = false
    for (let i = 0; i < k; i++) if (row[i] !== 0) anyNonzero = true
    t.ok(anyNonzero, 'repair row esi=' + repairEsi + ' is non-zero (decodable pivot guaranteed)')
  }
})
