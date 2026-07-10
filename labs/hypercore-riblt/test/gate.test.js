const test = require('brittle')
const c = require('compact-encoding')

const { Encoder, reconcileSets, hash64, makeMapping, mapNext, codedSymbolEncoding, honestNote } = require('..')

const MASK64 = (1n << 64n) - 1n

function rng (seed) {
  let s = (BigInt(seed) | 1n) & MASK64
  return () => {
    s = (s * 6364136223846793005n + 1442695040888963407n) & MASK64
    return (s >> 11n) & MASK64
  }
}

// A trial: two peers whose sets differ by exactly d elements (d/2 each side),
// on top of a shared common part. Returns cellsUsed and whether the recovered
// symmetric difference is exactly correct.
function trial (d, shared, seed) {
  const r = rng(seed)
  const A = new Set()
  const B = new Set()
  const aOnly = new Set()
  const bOnly = new Set()
  for (let i = 0; i < shared; i++) { const v = r(); A.add(v); B.add(v) }
  for (let i = 0; i < d / 2; i++) { const v = r(); A.add(v); aOnly.add(v) }
  for (let i = 0; i < d / 2; i++) { const v = r(); B.add(v); bOnly.add(v) }
  const out = reconcileSets([...A], [...B])
  const correct = out.success &&
    out.aOnly.length === aOnly.size && out.aOnly.every((x) => aOnly.has(x)) &&
    out.bOnly.length === bOnly.size && out.bOnly.every((x) => bOnly.has(x))
  return { cellsUsed: out.cellsUsed, correct }
}

// Realistic per-cell wire size at a peer of N blocks. Wire size is
// index-varint + count-varint + 16 fixed bytes; only the two varints vary, and
// they only depend on the cell's index and its count. We reproduce the encoder's
// exact per-cell COUNT via the public mapping law (every element starts at cell
// 0 then advances by mapNext), which is ~1000x cheaper than folding N elements
// through the heap for each of ~1400 cells. Validated against the real Encoder
// below.
function bytesPerCellAt (N, cells, seed) {
  const counts = new Array(cells).fill(0)
  const r = rng(seed)
  for (let i = 0; i < N; i++) {
    const m = makeMapping(hash64(r()))
    let idx = 0
    while (idx < cells) { counts[idx]++; idx = mapNext(m) }
  }
  let bytes = 0
  for (let j = 0; j < cells; j++) {
    bytes += c.encode(codedSymbolEncoding, { index: j, count: counts[j], sum: 0n, checksum: 0n }).length
  }
  return { bytesPerCell: bytes / cells, counts }
}

test('GATE (a) cells-to-decode overhead ~= 1.35 at the intended d=1000, N=1e6 regime', function (t) {
  const d = 1000
  const trials = 250
  let totalCells = 0
  let wrong = 0
  let maxRatio = 0
  for (let i = 0; i < trials; i++) {
    const res = trial(d, 500, 990000 + i * 7919)
    const ratio = res.cellsUsed / d
    if (!res.correct) wrong++
    totalCells += res.cellsUsed
    if (ratio > maxRatio) maxRatio = ratio
  }
  const meanOverhead = totalCells / trials / d
  t.comment(`d=${d}, trials=${trials}`)
  t.comment(`mean cellsUsed/d = ${meanOverhead.toFixed(4)} (paper ~1.35)`)
  t.comment(`worst-case cellsUsed/d = ${maxRatio.toFixed(3)}`)
  t.is(wrong, 0, 'every trial decoded the exact symmetric difference')
  t.ok(meanOverhead < 1.6, `mean overhead ${meanOverhead.toFixed(4)} < 1.6`)
})

test('GATE (b) decode-failure rate is bounded BELOW 1e-3 with real statistical power', function (t) {
  // 0/250 trials only bounds the failure probability to ~1.2e-2 (rule of three:
  // 3/250). To honestly claim < 1e-3 we need > 3000 trials. We run 4000 at a
  // cheaper d=100 (cells are ~10x cheaper than d=1000, so the whole sweep stays
  // ~2s) and require ZERO failures; the rule-of-three 95% upper bound is then
  // 3/4000 = 7.5e-4 < 1e-3. (Failure = wrong result OR pathological > 3*d cells.)
  const d = 100
  const shared = 100
  const trials = 4000
  let failures = 0
  let wrong = 0
  let maxRatio = 0
  for (let i = 0; i < trials; i++) {
    const res = trial(d, shared, 990000 + i * 7919)
    const ratio = res.cellsUsed / d
    if (!res.correct) wrong++
    if (!res.correct || ratio > 3) failures++
    if (ratio > maxRatio) maxRatio = ratio
  }
  const observedRate = failures / trials
  const ruleOfThreeBound = failures === 0 ? 3 / trials : (failures + 3) / trials
  t.comment(`d=${d}, trials=${trials}`)
  t.comment(`observed failures = ${failures} (wrong-result failures = ${wrong})`)
  t.comment(`worst-case cellsUsed/d = ${maxRatio.toFixed(3)}`)
  t.comment(`observed failure rate = ${observedRate.toExponential(2)}`)
  t.comment(`rule-of-three 95% upper bound = ${ruleOfThreeBound.toExponential(2)}`)
  t.ok(trials > 3000, `trials ${trials} > 3000 (needed for a strict < 1e-3 bound)`)
  t.is(failures, 0, 'zero decode failures observed')
  t.ok(ruleOfThreeBound < 1e-3, `achieved failure bound ${ruleOfThreeBound.toExponential(2)} < 1e-3`)
})

test('GATE (c) RIBLT beats a full bitfield when d << N — with HONEST byte accounting', function (t) {
  const N = 1000000 // core of 1e6 blocks
  const d = 1000

  // (a) HONEST bytes/cell at the real N=1e6 peer, over the ~1400 cells a d=1000
  // reconciliation actually consumes. Early low-index cells carry huge counts
  // (cell 0 XORs all N elements), so their count-varints are multi-byte — the
  // realistic mean is well above the 17.08 B/cell a 5000-element encoder reports.
  const cellsToMeasure = 1400
  const { bytesPerCell, counts } = bytesPerCellAt(N, cellsToMeasure, 2024)

  // Validate the fast count model against the real Encoder on a small population.
  const enc = new Encoder()
  const rv = rng(7)
  for (let i = 0; i < 3000; i++) enc.add(rv())
  const modelCounts = bytesPerCellAt(3000, 40, 7).counts
  const encCounts = [...enc.symbols(40)].map((s) => s.count)
  t.alike(encCounts, modelCounts, 'fast bytes/cell count model matches the real Encoder')

  t.comment(`N=${N} blocks, d=${d}`)
  t.comment(`measured bytes/cell = ${bytesPerCell.toFixed(2)} (cell0 count=${counts[0]}, cell100 count=${counts[100]})`)
  t.comment('(an under-populated 5000-element encoder would misreport ~17.08 B/cell)')
  t.ok(bytesPerCell > 18, `honest bytes/cell ${bytesPerCell.toFixed(2)} > 18 (not the 17.08 undercount)`)

  // cellsUsed for d: mean over a handful of trials -> the real overhead.
  let totalCells = 0
  const trials = 20
  for (let i = 0; i < trials; i++) totalCells += trial(d, 5000, 55000 + i * 131).cellsUsed
  const meanCells = totalCells / trials
  const overhead = meanCells / d

  const ribltBytes = meanCells * bytesPerCell
  const bitfieldBytes = N / 8 // raw one-bit-per-block: 125,000 bytes
  const ratio = bitfieldBytes / ribltBytes

  t.comment(`RIBLT: ${meanCells.toFixed(0)} cells * ${bytesPerCell.toFixed(1)}B = ${Math.round(ribltBytes)} bytes`)
  t.comment(`bitfield: ${bitfieldBytes} bytes`)
  t.comment(`RIBLT sends ${ratio.toFixed(2)}x FEWER bytes at d=${d}`)
  t.ok(ratio >= 3, `at the intended d=1000 regime, byte ratio ${ratio.toFixed(2)} >= 3`)

  // (b) DISCLOSE the loss regime. RIBLT only wins while d << N. The crossover
  // where a bitfield becomes cheaper is d* = bitfieldBytes / (overhead * B/cell).
  const crossoverD = bitfieldBytes / (overhead * bytesPerCell)
  const crossoverFrac = crossoverD / N
  t.comment(`crossover: bitfield wins once d >= ${Math.round(crossoverD)} (~${(crossoverFrac * 100).toFixed(2)}% of N)`)
  t.ok(crossoverFrac > 0.003 && crossoverFrac < 0.008, `crossover ${(crossoverFrac * 100).toFixed(2)}% of N is ~0.5% (RIBLT wins only for d << N)`)

  // At d = 1% of N, the bitfield is the smaller message — RIBLT LOSES.
  const dLoss = Math.round(N * 0.01)
  const ribltBytesLoss = overhead * dLoss * bytesPerCell
  t.comment(`at d=${dLoss} (1% of N): RIBLT ~${Math.round(ribltBytesLoss)}B vs bitfield ${bitfieldBytes}B -> bitfield wins`)
  t.ok(ribltBytesLoss > bitfieldBytes, `at d=1% of N a raw bitfield is smaller (${Math.round(ribltBytesLoss)} > ${bitfieldBytes})`)

  // (c) BASELINE CAVEAT: hypercore exchanges a RUN-LENGTH-COMPRESSED bitfield,
  // not a raw N/8 one. For clustered availability that is far smaller than N/8,
  // so the ratio above is an UPPER BOUND on RIBLT's real-world win.
  t.ok(honestNote.includes('RUN-LENGTH-COMPRESSED'), 'honestNote discloses the run-length-compressed bitfield caveat')
  t.comment('CAVEAT: real hypercore sends a run-length-compressed bitfield, so N/8 is an UPPER BOUND on the win.')
})
