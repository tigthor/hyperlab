// PQ append-throughput benchmark — Chapter 4 (HC-C1) + Chapter 56 gate.
//
// The book's decision gate: "if hybrid signing drops append throughput by
// more than fifteen percent in the benchmark, batched-append amortization
// ships FIRST." This bench measures the signing cadence hypercore pays on
// every append — one signature over the ~32-byte root — in three modes:
//
//   (a) classical Ed25519-only signing, one per append   (today's core)
//   (b) hybrid Ed25519 + ML-DSA-65 signing, one per append
//   (c) hybrid signing amortized over BATCHES of B appends
//       (sign the batch root ONCE, cost spread across B blocks)
//
// It reports appends/sec for each and the resulting drop / recovery
// percentages, plus the ML-DSA signing-latency tail (rejection sampling
// gives ML-DSA a ~50% CoV, fattening the tail — the book calls this out).
//
// Why the SIGNER object and not a live hypercore: hypercore's verifier.js
// hard-codes ed25519 ("Only Ed25519 signatures are supported"), so a live
// hybrid core needs a verifier fork (a separate deep-fork task). Signing is
// the ONLY per-append cost that differs between classical and hybrid — storage
// I/O is identical — so the signing-throughput drop measured here is an UPPER
// BOUND on the real append-throughput drop (real appends dilute the signature
// delta with fixed storage cost). Measuring the signer at hypercore's cadence
// is the sanctioned way to exercise the gate.

const b4a = require('b4a')
const { ed25519, hybridSigner, hybridKeyPair, constants } = require('../../labs/bare-pqcrypto')

const ROOT_BYTES = 32 // hypercore signs a ~32-byte root (signable(manifestHash))
const DEFAULT_ROOTS = 2000
const QUICK_ROOTS = 200
const DEFAULT_BATCH = 64 // matches append.js batchSize / baselines.full.json
const WARMUP = 16

module.exports = { run }

function makeRoots (n) {
  const roots = new Array(n)
  for (let i = 0; i < n; i++) {
    const r = b4a.alloc(ROOT_BYTES)
    // Vary the bytes so signing isn't trivially cached/identical.
    r.writeUInt32LE(i >>> 0, 0)
    r[4] = (i * 31) & 0xff
    roots[i] = r
  }
  return roots
}

function elapsedSeconds (start) {
  return Number(process.hrtime.bigint() - start) / 1e9
}

function percentile (sortedMs, p) {
  if (sortedMs.length === 0) return 0
  const idx = Math.min(sortedMs.length - 1, Math.floor((p / 100) * sortedMs.length))
  return sortedMs[idx]
}

// (a) classical Ed25519-only, one signature per append. Pure in-memory
// signing is JIT/GC-noisy, so take the median appends/sec over a few reps to
// give the gate a trustworthy denominator.
function benchClassical (roots, reps = 5) {
  const kp = ed25519.keyPair()
  for (let i = 0; i < WARMUP; i++) ed25519.sign(roots[i % roots.length], kp.secretKey)

  const rates = []
  for (let rep = 0; rep < reps; rep++) {
    const start = process.hrtime.bigint()
    for (let i = 0; i < roots.length; i++) ed25519.sign(roots[i], kp.secretKey)
    rates.push(roots.length / elapsedSeconds(start))
  }
  rates.sort(function (a, b) { return a - b })
  const appendsPerSec = rates[Math.floor(rates.length / 2)]
  return { appendsPerSec, signs: roots.length, repsPerSec: rates }
}

// (b) hybrid, one signature per append. Also captures per-sign latency to
//     characterize the ML-DSA rejection-sampling tail.
function benchHybridPerAppend (roots) {
  const signer = hybridSigner(hybridKeyPair())
  for (let i = 0; i < WARMUP; i++) signer.sign(roots[i % roots.length])

  const latMs = new Array(roots.length)
  const start = process.hrtime.bigint()
  for (let i = 0; i < roots.length; i++) {
    const t0 = process.hrtime.bigint()
    signer.sign(roots[i])
    latMs[i] = Number(process.hrtime.bigint() - t0) / 1e6
  }
  const seconds = elapsedSeconds(start)

  const sorted = latMs.slice().sort(function (a, b) { return a - b })
  const mean = latMs.reduce(function (s, x) { return s + x }, 0) / latMs.length
  const variance = latMs.reduce(function (s, x) { return s + (x - mean) * (x - mean) }, 0) / latMs.length
  const cov = mean > 0 ? Math.sqrt(variance) / mean : 0

  return {
    appendsPerSec: roots.length / seconds,
    seconds,
    signs: roots.length,
    signLatencyMs: {
      mean,
      p50: percentile(sorted, 50),
      p95: percentile(sorted, 95),
      p99: percentile(sorted, 99),
      max: sorted[sorted.length - 1],
      coefficientOfVariation: cov
    }
  }
}

// (c) hybrid, amortized: one hybrid signature per batch of B appends. The
//     batch root is a hash of the B roots (here: last root stands in as the
//     batch's Merkle root — hypercore signs one root per batched append call).
function benchHybridBatched (roots, batchSize) {
  const signer = hybridSigner(hybridKeyPair())
  const batchRoot = b4a.alloc(ROOT_BYTES)
  for (let i = 0; i < WARMUP; i++) signer.sign(batchRoot)

  let signs = 0
  const start = process.hrtime.bigint()
  for (let appended = 0; appended < roots.length; appended += batchSize) {
    const end = Math.min(appended + batchSize, roots.length)
    // One signature covers the whole batch — the fixed ML-DSA cost is spread
    // across (end - appended) appends. Use the last root of the batch as the
    // stand-in batch root (mirrors hypercore signing one root per append call).
    signer.sign(roots[end - 1])
    signs++
  }
  const seconds = elapsedSeconds(start)

  return { appendsPerSec: roots.length / seconds, seconds, signs, batchSize }
}

async function run (opts = {}) {
  const roots = makeRoots(opts.totalRoots || (opts.quick === true ? QUICK_ROOTS : DEFAULT_ROOTS))
  const batchSize = opts.batchSize || DEFAULT_BATCH

  const classical = benchClassical(roots)
  const hybrid = benchHybridPerAppend(roots)
  const batched = benchHybridBatched(roots, batchSize)

  // Gate arithmetic (relative to mode (a), the classical signing cadence).
  const dropPerAppendPct = (1 - hybrid.appendsPerSec / classical.appendsPerSec) * 100
  const batchedDropPct = (1 - batched.appendsPerSec / classical.appendsPerSec) * 100
  const recoveryFactor = batched.appendsPerSec / hybrid.appendsPerSec

  // Sweep batch sizes to trace the amortization curve. ML-DSA-65 signing is
  // inherently millisecond-scale (rejection sampling), so a SMALL batch
  // recovers a large multiple while a LARGER batch is needed to fully close
  // the 15% gap. Only sweep sizes that yield enough signatures (>= MIN_SIGNS)
  // to be a stable estimate — a huge batch over a small root set measures too
  // few signs to trust.
  const MIN_SIGNS = 8
  const sweepSizes = [1, 16, 64, 256].filter(function (b) {
    return b <= roots.length && Math.ceil(roots.length / b) >= MIN_SIGNS
  })
  const batchSweep = sweepSizes.map(function (b) {
    const r = benchHybridBatched(roots, b)
    const dropPct = (1 - r.appendsPerSec / classical.appendsPerSec) * 100
    return { batchSize: b, appendsPerSec: r.appendsPerSec, dropVsClassicalPct: dropPct, withinGate: dropPct <= 15 }
  })
  const empiricalCrossover = batchSweep.find(function (s) { return s.withinGate })

  // Analytic crossover: mode (c)'s only per-append cost is the amortized
  // hybrid signature, so appendsPerSec(B) ~= B / meanHybridSignSeconds. The
  // drop falls to <=15% of classical when B >= 0.85 * classicalAppendsPerSec *
  // meanHybridSignSeconds. (Reported as a projection; a batch this large over
  // a small root set is too few signs to measure empirically here.)
  const meanSignSeconds = hybrid.signLatencyMs.mean / 1000
  const analyticCrossoverBatchSize = Math.ceil(0.85 * classical.appendsPerSec * meanSignSeconds)
  const crossoverBatchSize = empiricalCrossover ? empiricalCrossover.batchSize : analyticCrossoverBatchSize

  const gateThresholdPct = 15
  const gateFires = dropPerAppendPct > gateThresholdPct // per-append hybrid trips the gate
  // "Recovers materially" = batched amortization buys back a large multiple of
  // the collapsed per-append throughput (>=10x here). Full closure to within
  // 15% needs the larger batch reported in `crossover`.
  const batchedRecoversMaterially = recoveryFactor >= 10
  const batchedFullyRecovers = batchedDropPct <= gateThresholdPct

  return {
    name: 'pq-append',
    scheme: constants.HYBRID_SCHEME,
    rootBytes: ROOT_BYTES,
    totalRoots: roots.length,
    batchSize,
    hybridSignatureBytes: constants.HYBRID_SIG_BYTES,
    classicalSignatureBytes: constants.HYBRID_ED25519_BYTES,
    modes: {
      a_classicalEd25519: { appendsPerSec: classical.appendsPerSec, signs: classical.signs },
      b_hybridPerAppend: {
        appendsPerSec: hybrid.appendsPerSec,
        signs: hybrid.signs,
        signLatencyMs: hybrid.signLatencyMs
      },
      c_hybridBatched: {
        appendsPerSec: batched.appendsPerSec,
        signs: batched.signs,
        batchSize
      }
    },
    batchSweep,
    gate: {
      claim: 'hybrid signing drops append throughput >15% => batched-append amortization ships FIRST (Ch.4 + Ch.56)',
      thresholdPct: gateThresholdPct,
      dropPerAppendPct,
      batchedDropPct,
      recoveryFactor,
      crossoverBatchSize,
      analyticCrossoverBatchSize,
      gateFires,
      batchedRecoversMaterially,
      batchedFullyRecovers,
      // The gate PASSES when it correctly fires for per-append hybrid AND
      // batched amortization materially recovers throughput — exactly the
      // "batched amortization ships first" decision the book prescribes.
      passes: gateFires && batchedRecoversMaterially
    },
    baselineNote: 'Recorded full-append baselines (baselines.full.json, incl. storage I/O): single Ed25519 ~9.7k appends/sec, batched(64) ~129k. This bench isolates the signing cadence, so its per-append drop is an UPPER BOUND on the real append-throughput drop.'
  }
}

if (require.main === module) {
  const quick = process.argv.includes('--quick')
  run({ quick })
    .then(function (metrics) {
      console.log(JSON.stringify(metrics, null, 2))
    })
    .catch(function (err) {
      console.error(err)
      process.exitCode = 1
    })
}
