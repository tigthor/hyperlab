const test = require('brittle')
const c = require('compact-encoding')

const riblt = require('..')
const { Encoder, reconcile, reconcileSets, hash64, makeMapping, mapNext, codedSymbolEncoding } = riblt

const MASK64 = (1n << 64n) - 1n

// Deterministic 64-bit LCG so every trial is reproducible.
function rng (seed) {
  let s = (BigInt(seed) | 1n) & MASK64
  return () => {
    s = (s * 6364136223846793005n + 1442695040888963407n) & MASK64
    return (s >> 11n) & MASK64
  }
}

// Build sets A, B sharing `shared` elements plus da A-only and db B-only.
function makeSets (shared, da, db, seed) {
  const r = rng(seed)
  const A = new Set()
  const B = new Set()
  const aOnly = new Set()
  const bOnly = new Set()
  for (let i = 0; i < shared; i++) { const v = r(); A.add(v); B.add(v) }
  for (let i = 0; i < da; i++) { const v = r(); A.add(v); aOnly.add(v) }
  for (let i = 0; i < db; i++) { const v = r(); B.add(v); bOnly.add(v) }
  return { A: [...A], B: [...B], aOnly, bOnly }
}

function sameSet (arr, set) {
  return arr.length === set.size && arr.every((x) => set.has(x))
}

test('module api surface', function (t) {
  t.is(typeof riblt.Encoder, 'function')
  t.is(typeof riblt.Decoder, 'function')
  t.is(typeof riblt.reconcile, 'function')
  t.is(typeof riblt.reconcileSets, 'function')
  t.is(typeof riblt.hash64, 'function')
  t.is(typeof riblt.codedSymbolEncoding.encode, 'function')
})

test('coded symbol roundtrips through compact-encoding', function (t) {
  const s = { count: -3, sum: 0xda942042e4dd58b5n, checksum: 0x0123456789abcdefn }
  const buf = c.encode(codedSymbolEncoding, s)
  const back = c.decode(codedSymbolEncoding, buf)
  t.is(back.count, s.count)
  t.is(back.sum, s.sum)
  t.is(back.checksum, s.checksum)
})

test('mapping is deterministic and thinning', function (t) {
  const seed = hash64(42n)
  const a = makeMapping(seed)
  const b = makeMapping(seed)
  const seqA = []
  const seqB = []
  for (let i = 0; i < 20; i++) { seqA.push(mapNext(a)); seqB.push(mapNext(b)) }
  t.alike(seqA, seqB, 'same seed -> identical index sequence')
  let strictlyIncreasing = true
  for (let i = 1; i < seqA.length; i++) if (seqA[i] <= seqA[i - 1]) strictlyIncreasing = false
  t.ok(strictlyIncreasing, 'mapped indices strictly increase')
  // different elements produce different sequences
  const other = makeMapping(hash64(43n))
  const seqO = []
  for (let i = 0; i < 20; i++) seqO.push(mapNext(other))
  t.absent(seqA.every((v, i) => v === seqO[i]), 'distinct elements map differently')
})

test('reconcile recovers exact symmetric difference for d in {1,10,100,1000}', function (t) {
  for (const d of [1, 10, 100, 1000]) {
    const da = Math.floor(d / 2)
    const db = d - da
    const { A, B, aOnly, bOnly } = makeSets(400, da, db, 7000 + d)
    const out = reconcileSets(A, B)
    t.ok(out.success, `d=${d} decoded`)
    t.ok(sameSet(out.aOnly, aOnly), `d=${d} A\\B exact`)
    t.ok(sameSet(out.bOnly, bOnly), `d=${d} B\\A exact`)
    t.is(out.aOnly.length + out.bOnly.length, d, `d=${d} difference size`)
  }
})

test('identical sets decode in ~0 cells', function (t) {
  const { A, B } = makeSets(1000, 0, 0, 99)
  const out = reconcileSets(A, B)
  t.ok(out.success)
  t.is(out.aOnly.length, 0)
  t.is(out.bOnly.length, 0)
  t.ok(out.cellsUsed <= 1, `cellsUsed=${out.cellsUsed} (expected ~0)`)
})

test('fully disjoint sets', function (t) {
  const A = [1n, 2n, 3n, 4n, 5n]
  const B = [6n, 7n, 8n, 9n, 10n]
  const out = reconcileSets(A, B)
  t.ok(out.success)
  t.ok(sameSet(out.aOnly, new Set(A)), 'all of A is A-only')
  t.ok(sameSet(out.bOnly, new Set(B)), 'all of B is B-only')
})

test('one empty set', function (t) {
  const A = [11n, 22n, 33n]
  const outB = reconcileSets(A, [])
  t.ok(outB.success)
  t.ok(sameSet(outB.aOnly, new Set(A)))
  t.is(outB.bOnly.length, 0)
  const outA = reconcileSets([], A)
  t.ok(outA.success)
  t.is(outA.aOnly.length, 0)
  t.ok(sameSet(outA.bOnly, new Set(A)))
})

test('reconcile drives an Encoder stream and is deterministic', function (t) {
  const { A, B } = makeSets(200, 25, 25, 555)
  const enc1 = new Encoder()
  for (const e of B) enc1.add(e)
  const out1 = reconcile(A, enc1)
  const out2 = reconcileSets(A, B)
  t.is(out1.cellsUsed, out2.cellsUsed, 'same cells consumed across runs')
  t.is(out1.aOnly.length + out1.bOnly.length, 50)
})

test('coded symbols survive a full encode/decode wire round trip', function (t) {
  const { A, B, aOnly, bOnly } = makeSets(300, 20, 20, 314)
  const enc = new Encoder()
  for (const e of B) enc.add(e)
  // Serialize every produced symbol and decode it before feeding the Decoder.
  const wire = () => c.decode(codedSymbolEncoding, c.encode(codedSymbolEncoding, enc.produceSymbol()))
  const out = reconcile(A, wire)
  t.ok(out.success)
  t.ok(sameSet(out.aOnly, aOnly))
  t.ok(sameSet(out.bOnly, bOnly))
})
