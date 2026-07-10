const test = require('brittle')

const { Encoder, reconcile, reconcileSets, hash64 } = require('..')

const MASK64 = (1n << 64n) - 1n

function rng (seed) {
  let s = (BigInt(seed) | 1n) & MASK64
  return () => {
    s = (s * 6364136223846793005n + 1442695040888963407n) & MASK64
    return (s >> 11n) & MASK64
  }
}

function sameSet (arr, set) {
  return arr.length === set.size && arr.every((x) => set.has(x))
}

// Two peers differing by ~d elements on a shared base, as plain arrays.
function makeSets (shared, da, db, seed) {
  const r = rng(seed)
  const A = []
  const B = []
  const aOnly = new Set()
  const bOnly = new Set()
  for (let i = 0; i < shared; i++) { const v = r(); A.push(v); B.push(v) }
  for (let i = 0; i < da; i++) { const v = r(); A.push(v); aOnly.add(v) }
  for (let i = 0; i < db; i++) { const v = r(); B.push(v); bOnly.add(v) }
  return { A, B, aOnly, bOnly }
}

// ---------------------------------------------------------------------------
// 1. MULTISET: duplicate elements must not silently XOR-cancel into a wrong
//    "success". Inputs are deduped to distinct sets at the boundary.
// ---------------------------------------------------------------------------

test('multiset inputs are deduped, not silently miscancelled', function (t) {
  // Before the fix the two 5n in A XOR-cancelled and 5n vanished from A\B,
  // returning success:true with the WRONG difference.
  const out = reconcileSets([5n, 5n, 6n], [6n, 7n])
  t.ok(out.success, 'still succeeds')
  t.ok(sameSet(out.aOnly, new Set([5n])), 'A\\B = {5} (the duplicate did not cancel it away)')
  t.ok(sameSet(out.bOnly, new Set([7n])), 'B\\A = {7}')
})

test('duplicates on both sides collapse to the correct set difference', function (t) {
  const A = [1n, 1n, 2n, 2n, 2n, 3n]
  const B = [2n, 3n, 3n, 4n, 4n]
  const out = reconcileSets(A, B)
  t.ok(out.success)
  t.ok(sameSet(out.aOnly, new Set([1n])), 'A\\B = {1}')
  t.ok(sameSet(out.bOnly, new Set([4n])), 'B\\A = {4}')
})

// ---------------------------------------------------------------------------
// 2. DESYNC / DoS: a duplicated, dropped, reordered, or injected-bogus coded
//    symbol must FAIL CLEANLY (success:false) within a bounded cell budget —
//    never an infinite loop, never a silent wrong answer.
// ---------------------------------------------------------------------------

// Build a live encoder stream for setB, wrapped so we can perturb it. `perturb`
// gets (nextSymbol, produce) where produce() pulls the next raw symbol.
function stream (setB, perturb) {
  const enc = new Encoder()
  for (const e of setB) enc.add(e)
  const produce = () => enc.produceSymbol()
  return () => perturb(produce)
}

// Each desync is introduced at cell index 10, long before a d=100 difference
// (~140 cells) could decode, so the corruption is always exercised.
const TARGET = 10

function assertFailsBounded (t, label, source, maxCells) {
  const { A } = makeSets(400, 50, 50, 4242)
  const started = Date.now()
  const out = reconcile(A, source, { maxCells })
  const elapsed = Date.now() - started
  t.absent(out.success, `${label}: success === false`)
  t.ok(out.cellsUsed <= maxCells, `${label}: cellsUsed ${out.cellsUsed} <= maxCells ${maxCells} (bounded)`)
  t.ok(elapsed < 5000, `${label}: returned in ${elapsed}ms (no hang)`)
  return out
}

test('duplicated coded symbol fails cleanly and fast', function (t) {
  const { B } = makeSets(400, 50, 50, 4242)
  let pending = null
  let done = false
  const src = stream(B, (produce) => {
    if (pending) { const p = pending; pending = null; return p }
    const s = produce()
    if (!done && s.index === TARGET) { done = true; pending = s } // emit s now, again next
    return s
  })
  assertFailsBounded(t, 'duplicate', src, 500)
})

test('dropped coded symbol fails cleanly and fast', function (t) {
  const { B } = makeSets(400, 50, 50, 4242)
  const src = stream(B, (produce) => {
    let s = produce()
    if (s.index === TARGET) s = produce() // skip cell TARGET
    return s
  })
  assertFailsBounded(t, 'drop', src, 500)
})

test('reordered coded symbol fails cleanly and fast', function (t) {
  const { B } = makeSets(400, 50, 50, 4242)
  let held = null
  const src = stream(B, (produce) => {
    if (held) { const h = held; held = null; return h }
    const s = produce()
    if (s.index === TARGET) { held = s; return produce() } // emit TARGET+1 before TARGET
    return s
  })
  assertFailsBounded(t, 'reorder', src, 500)
})

test('injected bogus pure cell (correct index) fails cleanly within a bounded budget', function (t) {
  const { B } = makeSets(400, 50, 50, 4242)
  const phantom = 0xdeadbeefcafef00dn // not in either set
  const src = stream(B, (produce) => {
    const s = produce()
    // Attacker keeps the index valid but swaps in a fabricated pure cell that
    // decodes to a phantom element. The phantom pollutes every cell it maps to,
    // so the difference never fully peels; we must bail at maxCells, not 16M.
    if (s.index === TARGET) return { index: TARGET, count: 1, sum: phantom, checksum: hash64(phantom) }
    return s
  })
  const out = assertFailsBounded(t, 'bogus-pure', src, 400)
  t.ok(out.cellsUsed >= TARGET, 'consumed cells up to the budget, then stopped')
})

// ---------------------------------------------------------------------------
// 3. TRUNCATION: the remote source returning null/undefined (peer disconnected
//    mid-stream) must be treated as end-of-stream, not crash.
// ---------------------------------------------------------------------------

test('truncated stream (source returns null) returns success:false without crashing', function (t) {
  const { A, B } = makeSets(400, 50, 50, 4242)
  const enc = new Encoder()
  for (const e of B) enc.add(e)
  let n = 0
  const src = () => {
    if (n++ >= 5) return null // peer vanished after 5 cells
    return enc.produceSymbol()
  }
  let out
  t.execution(() => { out = reconcile(A, src) }, 'does not throw on null from the source')
  t.absent(out.success, 'success === false on truncation')
  t.ok(out.cellsUsed <= 5, `stopped at the truncation point (cellsUsed=${out.cellsUsed})`)
})

test('undefined from the source is also treated as end-of-stream', function (t) {
  const { A } = makeSets(100, 20, 20, 99)
  let n = 0
  const src = () => { if (n++ >= 3) return undefined; return new Encoder().produceSymbol() }
  let out
  t.execution(() => { out = reconcile(A, src) })
  t.absent(out.success)
})

// ---------------------------------------------------------------------------
// Honest streams still reconcile correctly (regression guard for the fixes).
// ---------------------------------------------------------------------------

test('honest stream still decodes exactly after all the robustness guards', function (t) {
  const { A, B, aOnly, bOnly } = makeSets(500, 60, 40, 20260710)
  const out = reconcileSets(A, B)
  t.ok(out.success)
  t.ok(sameSet(out.aOnly, aOnly))
  t.ok(sameSet(out.bOnly, bOnly))
})
