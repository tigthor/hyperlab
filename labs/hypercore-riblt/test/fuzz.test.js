const test = require('brittle')
const c = require('compact-encoding')

const {
  Encoder,
  reconcile,
  reconcileSets,
  hash64,
  codedSymbolEncoding
} = require('..')

const MASK64 = (1n << 64n) - 1n

// ---------------------------------------------------------------------------
// Seeded PRNG so every fuzz failure is reproducible: the seed of a failing
// iteration is printed, and re-running with it reproduces the exact inputs.
// Same 64-bit LCG the existing suite uses.
// ---------------------------------------------------------------------------
function rng (seed) {
  let s = (BigInt(seed) | 1n) & MASK64
  return () => {
    s = (s * 6364136223846793005n + 1442695040888963407n) & MASK64
    return (s >> 11n) & MASK64
  }
}

function eqSet (arr, set) {
  return arr.length === set.size && arr.every((x) => set.has(x))
}

// Build two peers whose sets share `shared` elements and differ by exactly
// da A-only + db B-only DISTINCT uint64 values, driven from `seed`. Returns the
// two sets plus the ground-truth symmetric difference.
function makeSets (shared, da, db, seed) {
  const r = rng(seed)
  const A = new Set()
  const B = new Set()
  const aOnly = new Set()
  const bOnly = new Set()
  for (let i = 0; i < shared; i++) { const v = r(); A.add(v); B.add(v) }
  while (aOnly.size < da) { const v = r(); if (!A.has(v)) { A.add(v); aOnly.add(v) } }
  while (bOnly.size < db) { const v = r(); if (!B.has(v) && !aOnly.has(v)) { B.add(v); bOnly.add(v) } }
  return { A: [...A], B: [...B], aOnly, bOnly }
}

// ---------------------------------------------------------------------------
// 1. PROPERTY: honest reconciliation recovers the EXACT symmetric difference
//    across the whole intended d range {0..5000}, in BOTH directions, and never
//    reports success with a wrong answer. A geometric d-sweep (many seeds each)
//    covers 0 and the extremes cheaply; the small-d fuzz below adds volume.
// ---------------------------------------------------------------------------

test('PROPERTY reconcile recovers exact symmetric difference across d in {0..5000}, both directions', function (t) {
  // Geometric ladder so we exercise d=0, tiny d, and d near 5000 without paying
  // for thousands of 5000-element reconciles.
  const ds = [0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181, 5000]
  const seedsPer = 5
  let wrongSuccess = 0
  let notDecoded = 0
  for (const d of ds) {
    for (let k = 0; k < seedsPer; k++) {
      const seed = 0x5EED0000 + d * 131 + k * 977
      // Randomize the A/B split of the difference (all on one side is a valid case).
      const split = rng(seed ^ 0xABCDEF)()
      const da = d === 0 ? 0 : Number(split % BigInt(d + 1))
      const db = d - da
      const shared = 50 + Number(split % 400n)
      const { A, B, aOnly, bOnly } = makeSets(shared, da, db, seed)

      const fwd = reconcileSets(A, B)
      if (!fwd.success) { notDecoded++; t.fail(`forward d=${d} seed=${seed.toString(16)} did not decode`); continue }
      if (!(eqSet(fwd.aOnly, aOnly) && eqSet(fwd.bOnly, bOnly))) {
        wrongSuccess++
        t.fail(`forward d=${d} seed=${seed.toString(16)} WRONG success (got a=${fwd.aOnly.length} b=${fwd.bOnly.length}, want a=${aOnly.size} b=${bOnly.size})`)
      }

      // Reverse direction: A\B and B\A swap.
      const rev = reconcileSets(B, A)
      if (!rev.success) { notDecoded++; t.fail(`reverse d=${d} seed=${seed.toString(16)} did not decode`); continue }
      if (!(eqSet(rev.aOnly, bOnly) && eqSet(rev.bOnly, aOnly))) {
        wrongSuccess++
        t.fail(`reverse d=${d} seed=${seed.toString(16)} WRONG success`)
      }
    }
  }
  t.is(notDecoded, 0, 'every honest full stream decoded (rateless)')
  t.is(wrongSuccess, 0, 'no honest trial ever reported success with a wrong difference')
})

// ---------------------------------------------------------------------------
// 2. FUZZ (high volume, cheap): random small/mid set sizes and random d, random
//    A/B split. Asserts exact recovery + the strong invariant "never a wrong
//    success:true" over hundreds of iterations. Also accumulates the overhead
//    statistic used by test 3.
// ---------------------------------------------------------------------------

const overheadSamples = [] // { d, cellsUsed }

test('FUZZ hundreds of random reconciliations are exact and never wrongly succeed', function (t) {
  const iters = 500
  const meta = rng(0xF0FEED)
  let wrongSuccess = 0
  let notDecoded = 0
  for (let it = 0; it < iters; it++) {
    const shared = Number(meta() % 700n)
    const d = Number(meta() % 800n) // cheap range, high volume
    const da = d === 0 ? 0 : Number(meta() % BigInt(d + 1))
    const db = d - da
    const seed = 0x1000000 + it * 2654435761
    const { A, B, aOnly, bOnly } = makeSets(shared, da, db, seed)
    const out = reconcileSets(A, B)
    if (!out.success) { notDecoded++; t.fail(`iter=${it} seed=${(seed >>> 0).toString(16)} d=${d} did not decode`); continue }
    if (!(eqSet(out.aOnly, aOnly) && eqSet(out.bOnly, bOnly))) {
      wrongSuccess++
      t.fail(`iter=${it} seed=${(seed >>> 0).toString(16)} d=${d} WRONG success`)
    }
    overheadSamples.push({ d: aOnly.size + bOnly.size, cellsUsed: out.cellsUsed })
  }
  t.is(notDecoded, 0, `all ${iters} random honest reconciliations decoded`)
  t.is(wrongSuccess, 0, 'zero wrong-success results over the whole fuzz run')
})

// ---------------------------------------------------------------------------
// 3. PROPERTY: cell overhead cellsUsed/d stays < ~2 across the range. The
//    asymptotic paper constant is ~1.35; a tiny d pays an additive constant, so
//    the strict per-trial <2 ratio is asserted for d>=50 (where it must hold),
//    a generous absolute cap guards the small-d tail, and the aggregate mean
//    over the larger differences must sit near 1.35.
// ---------------------------------------------------------------------------

test('PROPERTY cell overhead cellsUsed/d stays below ~2 across the range', function (t) {
  t.ok(overheadSamples.length > 100, 'have a population of overhead samples from the fuzz run')
  let ratioViolation = 0
  let capViolation = 0
  let bigSum = 0
  let bigN = 0
  let worst = 0
  let d0seen = 0
  for (const { d, cellsUsed } of overheadSamples) {
    if (d === 0) {
      d0seen++
      // No difference: reconciliation confirms equality in ~1 cell.
      if (cellsUsed > 1) capViolation++
      continue
    }
    const ratio = cellsUsed / d
    if (ratio > worst) worst = ratio
    // Strict overhead claim, where the constant term is negligible.
    if (d >= 50 && ratio >= 2) ratioViolation++
    // Generous absolute guard for every d (catches a real runaway even at tiny d,
    // where the additive constant legitimately inflates the ratio).
    if (cellsUsed > 4 * d + 40) capViolation++
    if (d >= 200) { bigSum += ratio; bigN++ }
  }
  const meanBig = bigN > 0 ? bigSum / bigN : 0
  t.comment(`overhead samples=${overheadSamples.length}, d=0 samples=${d0seen}, worst ratio=${worst.toFixed(3)}`)
  t.comment(`mean overhead for d>=200 = ${meanBig.toFixed(4)} (paper ~1.35), over ${bigN} samples`)
  t.is(ratioViolation, 0, 'every d>=50 trial used < 2*d cells')
  t.is(capViolation, 0, 'no trial exceeded the absolute cell cap (4d+40; d=0 => <=1)')
  t.ok(bigN > 10, 'enough large-d samples to trust the mean')
  t.ok(meanBig < 1.6, `aggregate overhead ${meanBig.toFixed(4)} < 1.6 for d>=200`)
})

// ---------------------------------------------------------------------------
// 4. FUZZ: the codedSymbolEncoding wire roundtrip is exact for random symbols,
//    and a full reconciliation driven THROUGH the wire codec still decodes
//    exactly. Would fail if the codec dropped a field, mishandled sign (zig-zag)
//    or the high bit of a uint64.
// ---------------------------------------------------------------------------

test('FUZZ codedSymbolEncoding roundtrips random coded symbols exactly', function (t) {
  const r = rng(0x0DDBA11)
  const iters = 3000
  let mism = 0
  for (let i = 0; i < iters; i++) {
    const index = Number(r() % 2000000n)
    // Signed count spanning negative/zero/positive, occasionally large magnitude.
    const mag = Number(r() % 200000n)
    const count = (r() & 1n) === 0n ? mag : -mag
    const sum = r() // full uint64, exercises the high bit
    const checksum = (r() << 40n | r()) & MASK64
    const s = { index, count, sum, checksum }
    const back = c.decode(codedSymbolEncoding, c.encode(codedSymbolEncoding, s))
    if (back.index !== index || back.count !== count || back.sum !== sum || back.checksum !== checksum) {
      mism++
      if (mism < 5) t.fail(`roundtrip mismatch i=${i}: ${JSON.stringify({ s, back }, (k, v) => typeof v === 'bigint' ? v.toString() : v)}`)
    }
  }
  t.is(mism, 0, `all ${iters} random coded symbols survived the wire roundtrip exactly`)
})

test('FUZZ full reconciliation through the wire codec is exact', function (t) {
  const trials = 40
  const meta = rng(0xC0DEC)
  let bad = 0
  for (let it = 0; it < trials; it++) {
    const shared = Number(meta() % 400n)
    const da = Number(meta() % 200n)
    const db = Number(meta() % 200n)
    const { A, B, aOnly, bOnly } = makeSets(shared, da, db, 0x700000 + it * 40507)
    const enc = new Encoder()
    for (const e of B) enc.add(e)
    // Every produced symbol is serialized and re-parsed before the Decoder sees it.
    const wire = () => c.decode(codedSymbolEncoding, c.encode(codedSymbolEncoding, enc.produceSymbol()))
    const out = reconcile(A, wire)
    if (!(out.success && eqSet(out.aOnly, aOnly) && eqSet(out.bOnly, bOnly))) {
      bad++
      t.fail(`wire reconcile trial=${it} failed (d=${aOnly.size + bOnly.size})`)
    }
  }
  t.is(bad, 0, `all ${trials} wire-driven reconciliations decoded exactly`)
})

// ---------------------------------------------------------------------------
// 5. FUZZ (the sharpest test): under a RANDOM corruption of the honest stream
//    (dup / drop / reorder / truncate / bit-flip / injected phantom pure cell)
//    at a random position, the decoder must NEVER report success with a wrong
//    difference, must stay within maxCells, and must not hang. When it does
//    succeed (corruption landed after the difference had already peeled), the
//    result must still be exactly correct.
// ---------------------------------------------------------------------------

test('FUZZ random stream corruptions never yield a wrong success and stay bounded', function (t) {
  const iters = 1500
  const meta = rng(0xBADBEEF)
  const maxCells = 4000
  let wrongSuccess = 0
  let overBudget = 0
  let slow = 0
  let successExact = 0
  let cleanFail = 0
  const t0 = Date.now()
  for (let it = 0; it < iters; it++) {
    const shared = 150 + Number(meta() % 350n)
    const da = Number(meta() % 100n)
    const db = Number(meta() % 100n)
    const { A, B, aOnly, bOnly } = makeSets(shared, da, db, 0x900000 + it * 2246822519)
    const enc = new Encoder()
    for (const e of B) enc.add(e)
    const corrupt = Number(meta() % 6n) // 0 dup 1 drop 2 reorder 3 truncate 4 bitflip 5 phantom
    const target = 1 + Number(meta() % 80n)
    const fr = rng(0xDEAD0000 + it)

    let pending = null
    let held = null
    let seen = 0
    let fired = false
    const src = () => {
      if (pending) { const p = pending; pending = null; return p }
      if (held && seen > target) { const h = held; held = null; return h }
      let s = enc.produceSymbol(); seen++
      if (!fired && s.index === target) {
        fired = true
        if (corrupt === 0) { pending = s; return s } // duplicate the cell
        if (corrupt === 1) { s = enc.produceSymbol(); seen++; return s } // drop the cell
        if (corrupt === 2) { held = s; return enc.produceSymbol() } // reorder: emit next first
        if (corrupt === 3) { return null } // truncate the stream
        if (corrupt === 4) { // flip a random bit of sum (index stays valid)
          return { index: s.index, count: s.count, sum: s.sum ^ (1n << (fr() % 64n)), checksum: s.checksum }
        }
        if (corrupt === 5) { // inject a fabricated pure cell for a phantom element
          const ph = (fr() | 1n) & MASK64
          return { index: s.index, count: 1, sum: ph, checksum: hash64(ph) }
        }
      }
      return s
    }

    const started = Date.now()
    const out = reconcile(A, src, { maxCells })
    if (Date.now() - started > 3000) slow++
    if (out.cellsUsed > maxCells) overBudget++
    if (out.success) {
      if (eqSet(out.aOnly, aOnly) && eqSet(out.bOnly, bOnly)) successExact++
      else { wrongSuccess++; t.fail(`iter=${it} corrupt=${corrupt} target=${target} WRONG success`) }
    } else cleanFail++
  }
  const ms = Date.now() - t0
  t.comment(`iters=${iters}: cleanFail=${cleanFail}, success(all exact)=${successExact}, in ${ms}ms`)
  t.is(wrongSuccess, 0, 'a corrupted stream NEVER produced a wrong success:true')
  t.is(overBudget, 0, 'every corrupted reconciliation stayed within maxCells')
  t.is(slow, 0, 'no corrupted reconciliation hung (all < 3s)')
  t.ok(cleanFail > 0, 'the corruptions did exercise the clean-failure path')
})

// ---------------------------------------------------------------------------
// 6. FUZZ: multiset inputs must be treated as SETS. Random duplication of
//    elements on either side must not XOR-cancel an element into a wrong
//    success — the recovered difference must equal the DISTINCT set difference.
// ---------------------------------------------------------------------------

test('FUZZ random multiset inputs reconcile to the exact set difference', function (t) {
  const iters = 300
  const meta = rng(0x0FF5E7)
  let wrong = 0
  for (let it = 0; it < iters; it++) {
    const { A, B, aOnly, bOnly } = makeSets(Number(meta() % 300n), Number(meta() % 60n), Number(meta() % 60n), 0xA00000 + it * 40503)
    // Sprinkle random duplicates (including even-count repeats that would
    // XOR-cancel if the boundary did not dedup).
    const dup = rng(0xD00D0000 + it)
    const Am = []
    for (const e of A) { const reps = 1 + Number(dup() % 4n); for (let k = 0; k < reps; k++) Am.push(e) }
    const Bm = []
    for (const e of B) { const reps = 1 + Number(dup() % 4n); for (let k = 0; k < reps; k++) Bm.push(e) }
    // Shuffle so duplicates are not adjacent.
    for (let i = Am.length - 1; i > 0; i--) { const j = Number(dup() % BigInt(i + 1)); const tmp = Am[i]; Am[i] = Am[j]; Am[j] = tmp }
    for (let i = Bm.length - 1; i > 0; i--) { const j = Number(dup() % BigInt(i + 1)); const tmp = Bm[i]; Bm[i] = Bm[j]; Bm[j] = tmp }
    const out = reconcileSets(Am, Bm)
    if (!(out.success && eqSet(out.aOnly, aOnly) && eqSet(out.bOnly, bOnly))) {
      wrong++
      t.fail(`multiset iter=${it} wrong (d=${aOnly.size + bOnly.size}, got a=${out.aOnly.length} b=${out.bOnly.length}, success=${out.success})`)
    }
  }
  t.is(wrong, 0, `all ${iters} multiset reconciliations matched the distinct set difference`)
})

// ---------------------------------------------------------------------------
// 7. FUZZ: a flooder streaming well-formed, correctly-indexed but BOGUS cells
//    with random shapes can never be made to succeed; it is bounded by maxCells
//    and returns quickly, for a spread of random ceilings.
// ---------------------------------------------------------------------------

test('FUZZ randomized bogus-cell flood is always bounded and never falsely succeeds', function (t) {
  const meta = rng(0xF100DED)
  let falseSuccess = 0
  let overBudget = 0
  let slow = 0
  for (let it = 0; it < 40; it++) {
    const localR = rng(0x10CA10 + it)
    const local = []
    const n = 200 + Number(meta() % 400n)
    for (let i = 0; i < n; i++) local.push(localR())
    const maxCells = 500 + Number(meta() % 3000n)
    const fr = rng(0xF00D0000 + it * 7)
    let idx = 0
    // Every cell: correct sequential index (passes the integrity check) but a
    // random count/sum/checksum, so nothing peels after local subtraction.
    const flood = () => ({ index: idx++, count: Number((fr() % 9n) - 4n) || 1, sum: fr(), checksum: fr() })
    const started = Date.now()
    const out = reconcile(local, flood, { maxCells })
    if (Date.now() - started > 3000) slow++
    if (out.success) falseSuccess++
    if (out.cellsUsed > maxCells) overBudget++
  }
  t.is(falseSuccess, 0, 'a bogus flood never reports success:true')
  t.is(overBudget, 0, 'every flood stayed within its maxCells ceiling')
  t.is(slow, 0, 'every flood returned promptly (< 3s)')
})
