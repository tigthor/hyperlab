#!/usr/bin/env node
// Benchmark orchestrator for the hyperlab harness.
//
// Usage: node bench/run.js [--quick] [--baseline] [--check]
//
// Runs the three benches SEQUENTIALLY (they are timing sensitive, never
// in parallel), prints a per-metric table with delta % vs the recorded
// baseline for this bench size when that file exists, and always writes
// the raw run to bench/results/<iso-timestamp>.json (gitignored).
//
// Baselines are kept per bench size so quick and full runs never clobber
// each other: bench/baselines.quick.json for --quick runs,
// bench/baselines.full.json for full-size runs. --baseline and --check
// both select the file matching this run's --quick flag.
//
//   --quick     smoke-sized run (< 5s per bench), passed to each bench
//   --baseline  record this run to the size-matching baselines file
//               (tracked in git, the plan requires recorded baselines)
//   --check     exit 1 if any gated throughput-like metric regressed
//               >15% vs baseline or any latency-like metric grew >15%
//               (the plan's decision-gate threshold)
//   --reps=N    repetitions per bench (default: 5 quick, 3 full)
//
// Noise handling: each bench is repeated N times and every numeric metric
// is aggregated in its gate direction - max over reps for
// higher-is-better (throughput has a hard ceiling, noise only ever slows
// a run down, so best-of-N converges on the machine's ceiling), min over
// reps for lower-is-better, median for ungated numerics. Baselines and
// checks aggregate identically, so the 15% gate compares like with like.
// When --check still sees a gate over threshold, only the failing benches
// are re-run (up to MAX_GATE_RETRIES more rep batches) and the samples
// merged before the verdict: scheduler jitter gets absorbed, while a real
// regression can never produce a near-baseline sample, so it still fails.

const fs = require('fs')
const path = require('path')

const RESULTS_DIR = path.join(__dirname, 'results')

// One baseline slot per bench size - a full-size `pnpm baseline` must not
// overwrite the quick baseline the smoke checks compare against.
function baselinesPath (quick) {
  return path.join(__dirname, quick ? 'baselines.quick.json' : 'baselines.full.json')
}

const THRESHOLD = 0.15 // the plan's 15% decision-gate threshold

const replicateBench = require('./replicate')

const BENCHES = [
  { name: 'append', mod: require('./append') },
  { name: 'handshake', mod: require('./handshake') },
  { name: 'replicate', mod: replicateBench },
  // The want/have side of the plan's Phase-3 RaptorQ gate: "beat baseline
  // bytes-to-completion on a >=5% loss link". Same bench, 5% datagram loss
  // through the lossy-link rig.
  {
    name: 'replicate-lossy',
    mod: {
      run: function (opts) {
        return replicateBench.run({ ...opts, loss: 0.05 })
      }
    }
  }
]

// Decision-gate metrics, encoded explicitly per bench.
//
//   higherIsBetter (throughput-like): --check fails when the metric drops
//     more than THRESHOLD below the baseline.
//   lowerIsBetter (latency/overhead-like): --check fails when the metric
//     grows more than THRESHOLD above the baseline.
//
// Metrics not listed (p95/min latencies, counts, notes) are reported in
// the table but never gate: with quick's small sample counts the tail
// percentiles are just the max of a handful of samples and too noisy to
// gate a decision on. The handshake setupBytes* rx-delta windows are also
// reported-only - they vary with which DHT nodes each connect() lookup
// happens to route through (observed bimodal 297/550 bytes on an idle
// testnet), so they signal routing luck, not regressions. The
// deterministic wire-size gate is firstMessageBytes (the Noise message a
// PQ hybrid would grow).
// The append single* metrics are reported but NOT gated: single-append
// wall time is dominated by per-append storage flush latency, and the
// recorded results show best-of-N singleAppendsPerSec swinging ~2x with
// ambient machine load, so a 15% gate on it flaps (observed: --check
// FAILED at -27.4% five minutes after its own baseline, then PASSED on
// an immediate rerun). The batched metrics are what the PQ amortization
// decision actually needs, and they gate with a widened per-metric
// threshold (see THRESHOLD_OVERRIDES).
const GATES = {
  append: {
    higherIsBetter: ['batchedAppendsPerSec', 'batchedMBPerSec'],
    lowerIsBetter: []
  },
  handshake: {
    higherIsBetter: [],
    lowerIsBetter: ['latencyMsMedian', 'firstMessageBytes']
  },
  replicate: {
    higherIsBetter: ['wireEfficiency'],
    lowerIsBetter: ['wallMs', 'totalBytesWired', 'bytesPerBlockOverhead']
  },
  // Under loss, wall time is dominated by UDX retransmission timeouts and
  // swings far more than 15% run-to-run, so it is report-only here. The
  // RaptorQ decision is about bytes-to-completion, and those gate.
  'replicate-lossy': {
    higherIsBetter: ['wireEfficiency'],
    lowerIsBetter: ['totalBytesWired', 'bytesPerBlockOverhead']
  }
}

// Machine-PORTABLE gated metrics (bench.metric qualified): deterministic
// functions of the protocol, stable across machines, so valid to gate on CI
// against a baseline recorded on a different machine. Throughput (appends/sec,
// MB/sec) and wall/latency are machine-LOCAL — a slow CI runner is ~40% slower
// than a dev laptop, which is not a regression. And CLEAN-link byte counts are
// deterministic (fixed sparse subset, no retransmissions), but LOSSY-link
// bytes-to-completion is NOT portable: under loss the byte count depends on the
// OS's UDX retransmission timing (measured >40% ubuntu-vs-macos), so it is
// excluded here — the coded-vs-want/have RaptorQ comparison is same-machine
// (the raptorq-gate CI job), not a cross-machine baseline. `--portable-only`
// (used by CI) checks only this set; a local `--check` gates everything.
const PORTABLE_METRICS = new Set([
  'handshake.firstMessageBytes',
  'replicate.wireEfficiency',
  'replicate.totalBytesWired',
  'replicate.bytesPerBlockOverhead'
])

// Absolute noise floors for gated metrics, in the metric's own unit. A
// gate only fails when the relative move exceeds THRESHOLD AND the
// absolute move exceeds this floor. Local-loopback timings sit at 2-4 ms
// where scheduler jitter alone moves them a few hundred us; the plan's
// PQ latency budget is "adds < 1 ms", so sub-1 ms movements are beneath
// the decision gate's resolution anyway. Byte and throughput gates keep
// the default floor of 0.
const NOISE_FLOORS = {
  'handshake.latencyMsMedian': 1, // ms
  'replicate.wallMs': 1 // ms
}

// Per-metric threshold overrides (fraction, replaces THRESHOLD for that
// gate). Append throughput is wall-clock storage throughput on a shared
// machine: ambient load moves even best-of-N by far more than 15%
// (batched aggregates ranged ~56k-141k appends/sec across the recording
// session), so those gates use a wider band that still catches a real
// order-of-magnitude regression without flapping on scheduler noise.
const THRESHOLD_OVERRIDES = {
  'append.batchedAppendsPerSec': 0.35,
  'append.batchedMBPerSec': 0.35,
  // Under loss, bytes-to-completion carries real retransmission-framing variance:
  // the seeded drop pattern is fixed but UDX's retransmit/ACK framing around it is
  // not, so even the byte metrics swing ~15% run-to-run (and more across machines).
  // Widen so the portable CI gate catches an order-of-magnitude regression without
  // flapping on that inherent variance; the clean-link replicate byte gate stays
  // tight at 15%.
  'replicate-lossy.bytesPerBlockOverhead': 0.4,
  'replicate-lossy.totalBytesWired': 0.4,
  'replicate-lossy.wireEfficiency': 0.4
}

const QUICK_REPS = 5
const FULL_REPS = 3
const MAX_GATE_RETRIES = 2

module.exports = { runAll, checkGates, aggregate, GATES, NOISE_FLOORS, THRESHOLD_OVERRIDES, THRESHOLD }

async function runAll (opts = {}) {
  const quick = opts.quick === true
  const reps = opts.reps || (quick ? QUICK_REPS : FULL_REPS)
  const benches = {}
  const rawRuns = {}

  for (const bench of BENCHES) {
    rawRuns[bench.name] = await runReps(bench, quick, reps)
    benches[bench.name] = aggregate(bench.name, rawRuns[bench.name])
  }

  const record = {
    recorded: new Date().toISOString(),
    node: process.version,
    quick,
    reps,
    benches
  }

  return { record, rawRuns }
}

async function runReps (bench, quick, reps) {
  const started = Date.now()
  process.stderr.write('bench: running ' + bench.name + (quick ? ' (quick)' : '') + ' x' + reps + ' ...\n')

  const runs = []
  for (let rep = 0; rep < reps; rep++) {
    runs.push(await bench.mod.run({ quick }))
  }

  process.stderr.write('bench: ' + bench.name + ' done in ' + ((Date.now() - started) / 1000).toFixed(1) + 's\n')
  return runs
}

// Folds N repetitions of one bench into a single flat metric object.
// Gated metrics take their best value across reps (max for
// higher-is-better, min for lower-is-better), other numerics take the
// median, non-numerics come from the first rep that has them.
function aggregate (name, runs) {
  const gates = GATES[name] || { higherIsBetter: [], lowerIsBetter: [] }
  const out = {}

  const keys = []
  for (const run of runs) {
    for (const key of Object.keys(run)) {
      if (!keys.includes(key)) keys.push(key)
    }
  }

  for (const key of keys) {
    const values = runs
      .map(function (run) { return run[key] })
      .filter(function (v) { return v !== undefined })

    if (typeof values[0] !== 'number') {
      out[key] = values[0]
    } else if (gates.higherIsBetter.includes(key)) {
      out[key] = Math.max(...values)
    } else if (gates.lowerIsBetter.includes(key)) {
      out[key] = Math.min(...values)
    } else {
      out[key] = median(values)
    }
  }

  return out
}

function median (values) {
  const sorted = values.slice().sort(function (a, b) { return a - b })
  const mid = sorted.length >> 1
  return sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2
}

// Returns [{ bench, metric, direction, current, base, delta, status }]
// where status is 'pass' | 'fail' | 'skip'.
function checkGates (benches, baseline, threshold = THRESHOLD, portableOnly = false) {
  const baseBenches = (baseline && baseline.benches) || {}
  const results = []
  const keep = (name, m) => !portableOnly || PORTABLE_METRICS.has(name + '.' + m)

  for (const name of Object.keys(GATES)) {
    const current = benches[name] || {}
    const base = baseBenches[name] || {}

    for (const metric of GATES[name].higherIsBetter) {
      if (!keep(name, metric)) continue
      results.push(gateOne(name, metric, 'higher-is-better', current[metric], base[metric], threshold))
    }
    for (const metric of GATES[name].lowerIsBetter) {
      if (!keep(name, metric)) continue
      results.push(gateOne(name, metric, 'lower-is-better', current[metric], base[metric], threshold))
    }
  }

  return results
}

function gateOne (bench, metric, direction, current, base, threshold) {
  const result = { bench, metric, direction, current, base, delta: null, status: 'skip' }

  if (typeof current !== 'number' || typeof base !== 'number' || !isFinite(current) || !isFinite(base) || base === 0) {
    return result // metric missing on one side (e.g. byte counters unobservable) - reported, never gates
  }

  threshold = THRESHOLD_OVERRIDES[bench + '.' + metric] || threshold

  result.delta = (current - base) / base

  const floor = NOISE_FLOORS[bench + '.' + metric] || 0
  const worsened = direction === 'higher-is-better' ? base - current : current - base

  const regressed = direction === 'higher-is-better'
    ? result.delta < -threshold && worsened > floor
    : result.delta > threshold && worsened > floor

  result.status = regressed ? 'fail' : 'pass'
  return result
}

function loadBaseline (quick) {
  const file = baselinesPath(quick)
  if (!fs.existsSync(file)) return null
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

async function writeResults (record) {
  await fs.promises.mkdir(RESULTS_DIR, { recursive: true })
  const file = path.join(RESULTS_DIR, record.recorded.replace(/[:.]/g, '-') + '.json')
  await fs.promises.writeFile(file, JSON.stringify(record, null, 2) + '\n')
  return file
}

function printTable (benches, baseline) {
  const baseBenches = (baseline && baseline.benches) || {}

  for (const name of Object.keys(benches)) {
    const metrics = benches[name]
    const base = baseBenches[name] || {}
    const rows = [['metric', 'value', baseline ? 'baseline' : '', baseline ? 'delta' : '']]

    for (const key of Object.keys(metrics)) {
      if (key === 'name') continue

      const value = metrics[key]
      const baseValue = base[key]
      let baseCell = ''
      let deltaCell = ''

      if (baseline && typeof value === 'number' && typeof baseValue === 'number') {
        baseCell = formatValue(baseValue)
        deltaCell = baseValue === 0 ? 'n/a' : formatDelta((value - baseValue) / baseValue)
      }

      rows.push([key, formatValue(value), baseCell, deltaCell])
    }

    console.log('\n== ' + name + ' ==')
    printRows(rows)
  }
}

function printRows (rows) {
  const widths = []
  for (const row of rows) {
    row.forEach(function (cell, i) {
      widths[i] = Math.max(widths[i] || 0, cell.length)
    })
  }

  for (const row of rows) {
    const line = row
      .map(function (cell, i) { return cell.padEnd(widths[i]) })
      .join('  ')
      .trimEnd()
    console.log('  ' + line)
  }
}

function formatValue (value) {
  if (typeof value !== 'number') {
    const str = String(value)
    return str.length > 56 ? str.slice(0, 53) + '...' : str
  }
  if (Number.isInteger(value)) return String(value)
  const abs = Math.abs(value)
  if (abs >= 1000) return value.toFixed(0)
  if (abs >= 100) return value.toFixed(1)
  if (abs >= 1) return value.toFixed(2)
  return value.toFixed(4)
}

function formatDelta (delta) {
  const pct = delta * 100
  return (pct >= 0 ? '+' : '') + pct.toFixed(1) + '%'
}

function parseArgs (argv) {
  const args = { quick: false, baseline: false, check: false, portableOnly: false, reps: 0 }

  for (const arg of argv) {
    if (arg === '--quick') args.quick = true
    else if (arg === '--baseline') args.baseline = true
    else if (arg === '--check') args.check = true
    else if (arg === '--portable-only') args.portableOnly = true
    else if (/^--reps=\d+$/.test(arg)) args.reps = parseInt(arg.slice(7), 10)
    else {
      console.error('unknown argument: ' + arg)
      console.error('usage: node bench/run.js [--quick] [--baseline] [--check] [--portable-only] [--reps=N]')
      return null
    }
  }

  return args
}

async function main () {
  const args = parseArgs(process.argv.slice(2))
  if (args === null) return 1

  const baseline = loadBaseline(args.quick)

  if (args.check && baseline === null) {
    console.error('--check requires ' + baselinesPath(args.quick) + ' - record one first with --baseline')
    return 1
  }

  if (args.check && baseline.quick !== args.quick) {
    console.error(
      '--check aborted: baseline was recorded with quick=' + baseline.quick +
      ' but this run has quick=' + args.quick +
      ' - bench sizes differ, deltas would be meaningless. Rerun with matching flags or re-record the baseline.'
    )
    return 1
  }

  const { record, rawRuns } = await runAll({ quick: args.quick, reps: args.reps })

  let gates = null

  if (args.check) {
    gates = checkGates(record.benches, baseline, THRESHOLD, args.portableOnly)

    // Retry only the failing benches with fresh reps and merge the
    // samples before the verdict, so one noisy batch cannot fail the
    // gate - a real regression keeps failing because no retry can
    // produce a sample near the old ceiling.
    for (let attempt = 1; attempt <= MAX_GATE_RETRIES; attempt++) {
      const failing = [...new Set(gates
        .filter(function (g) { return g.status === 'fail' })
        .map(function (g) { return g.bench }))]

      if (failing.length === 0) break

      process.stderr.write(
        'check: ' + failing.join(', ') + ' over threshold - retrying (' +
        attempt + '/' + MAX_GATE_RETRIES + ') to rule out machine noise\n'
      )

      for (const name of failing) {
        const bench = BENCHES.find(function (b) { return b.name === name })
        const extra = await runReps(bench, record.quick, record.reps)
        rawRuns[name] = rawRuns[name].concat(extra)
        record.benches[name] = aggregate(name, rawRuns[name])
      }

      gates = checkGates(record.benches, baseline, THRESHOLD, args.portableOnly)
    }
  }

  const resultsFile = await writeResults(record)

  if (baseline !== null && baseline.quick !== record.quick) {
    console.error(
      'warning: baseline quick=' + baseline.quick + ' differs from this run (quick=' + record.quick +
      ') - deltas below compare different bench sizes'
    )
  }

  printTable(record.benches, baseline)

  console.log('\nraw results: ' + resultsFile)

  if (args.baseline) {
    const file = baselinesPath(record.quick)
    await fs.promises.writeFile(file, JSON.stringify(record, null, 2) + '\n')
    console.log('baseline recorded: ' + file)
  }

  if (!args.check) return 0

  const failed = gates.filter(function (g) { return g.status === 'fail' })

  console.log('\n== check (threshold ' + (THRESHOLD * 100) + '%) ==')

  const rows = [['status', 'bench', 'metric', 'direction', 'value', 'baseline', 'delta']]
  for (const g of gates) {
    rows.push([
      g.status.toUpperCase(),
      g.bench,
      g.metric,
      g.direction,
      typeof g.current === 'number' ? formatValue(g.current) : '-',
      typeof g.base === 'number' ? formatValue(g.base) : '-',
      g.delta === null ? '-' : formatDelta(g.delta)
    ])
  }
  printRows(rows)

  if (failed.length > 0) {
    console.error('\ncheck FAILED: ' + failed.length + ' metric(s) moved >' + (THRESHOLD * 100) + '% the wrong way vs baseline')
    return 1
  }

  console.log('\ncheck passed: no gated metric moved >' + (THRESHOLD * 100) + '% the wrong way vs baseline')
  return 0
}

if (require.main === module) {
  main()
    .then(function (code) {
      process.exitCode = code
    })
    .catch(function (err) {
      console.error(err)
      process.exitCode = 1
    })
}
