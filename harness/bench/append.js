// Hypercore append-throughput benchmark.
//
// Baseline yardstick for the PQ signer research gate: if hybrid
// Ed25519+ML-DSA drops append throughput >15%, batched-append
// amortization must ship first.
//
// Measures appends of blockSize-byte blocks in two modes:
//   (a) single appends in a loop (one block per core.append call)
//   (b) batched appends (an array of ~batchSize blocks per call)

const os = require('os')
const fs = require('fs')
const path = require('path')
const b4a = require('b4a')
const Hypercore = require('hypercore')

const DEFAULT_BLOCK_SIZE = 1024
const DEFAULT_TOTAL_BLOCKS = 20000
const QUICK_TOTAL_BLOCKS = 500
const DEFAULT_BATCH_SIZE = 64

module.exports = { run }

async function run (opts = {}) {
  const blockSize = opts.blockSize || DEFAULT_BLOCK_SIZE
  const totalBlocks = opts.totalBlocks || (opts.quick === true ? QUICK_TOTAL_BLOCKS : DEFAULT_TOTAL_BLOCKS)
  const batchSize = opts.batchSize || DEFAULT_BATCH_SIZE

  const block = b4a.alloc(blockSize).fill(0xab)

  const single = await benchSingle(block, totalBlocks)
  const batched = await benchBatched(block, totalBlocks, batchSize)

  const totalMB = (totalBlocks * blockSize) / (1024 * 1024)

  return {
    name: 'append',
    blockSize,
    totalBlocks,
    batchSize,
    singleAppendsPerSec: totalBlocks / single.seconds,
    batchedAppendsPerSec: totalBlocks / batched.seconds,
    singleMBPerSec: totalMB / single.seconds,
    batchedMBPerSec: totalMB / batched.seconds
  }
}

async function benchSingle (block, totalBlocks) {
  const { core, dir } = await createCore()

  try {
    const start = process.hrtime.bigint()

    for (let i = 0; i < totalBlocks; i++) {
      await core.append(block)
    }

    const seconds = elapsedSeconds(start)

    if (core.length !== totalBlocks) {
      throw new Error('single append bench appended ' + core.length + ' of ' + totalBlocks + ' blocks')
    }

    return { seconds }
  } finally {
    await destroyCore(core, dir)
  }
}

async function benchBatched (block, totalBlocks, batchSize) {
  const { core, dir } = await createCore()

  try {
    const fullBatch = new Array(batchSize).fill(block)
    const start = process.hrtime.bigint()

    for (let appended = 0; appended < totalBlocks; appended += batchSize) {
      const remaining = totalBlocks - appended
      const batch = remaining >= batchSize ? fullBatch : fullBatch.slice(0, remaining)
      await core.append(batch)
    }

    const seconds = elapsedSeconds(start)

    if (core.length !== totalBlocks) {
      throw new Error('batched append bench appended ' + core.length + ' of ' + totalBlocks + ' blocks')
    }

    return { seconds }
  } finally {
    await destroyCore(core, dir)
  }
}

async function createCore () {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'hyperlab-bench-append-'))
  const core = new Hypercore(dir)
  await core.ready()
  return { core, dir }
}

async function destroyCore (core, dir) {
  await core.close()
  await fs.promises.rm(dir, { recursive: true, force: true })
}

function elapsedSeconds (start) {
  return Number(process.hrtime.bigint() - start) / 1e9
}

if (require.main === module) {
  const quick = process.argv.includes('--quick')

  run({ quick })
    .then(function (metrics) {
      console.log(JSON.stringify(metrics))
    })
    .catch(function (err) {
      console.error(err)
      process.exitCode = 1
    })
}
