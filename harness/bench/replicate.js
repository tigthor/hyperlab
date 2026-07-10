// Hypercore sparse-download bytes-to-completion benchmark.
//
// Baseline for the RaptorQ research gate: RaptorQ-coded replication must
// beat the want/have protocol on bytes-to-completion over a >=5% loss
// link. This bench measures the want/have side on a clean link by
// default, and on an impaired link with { loss, latencyMs, jitterMs }
// (CLI: --loss=0.05 --latency=20 --jitter=5).
//
// Scenario: peer A holds a writer core with totalBlocks blocks of
// blockSize bytes. Peer B replicates SPARSELY, downloading a
// deterministic pseudo-random subset (seeded xorshift32, default 10% of
// blocks) so runs are comparable.
//
// Clean link: the peers replicate over a real hyperdht testnet socket.
// Wire bytes are counted with the NoiseSecretStream rawBytesWritten /
// rawBytesRead counters on peer B's DHT socket (both directions,
// encrypted wire frames), snapshotted after the socket opens and before
// replication attaches, so the number covers the full replication
// conversation: sync, want/have, requests and data.
//
// Impaired link: DHT peers learn each other's REAL UDX socket addresses
// via the DHT, so their direct traffic cannot be routed through a proxy.
// The loss mode instead replicates over two plain UDX streams (the same
// reliable retransmitting transport hyperdht rides on) whose datagrams
// go through one lossy-link proxy per direction. Wire bytes are the sum
// of both peers' UDX socket bytesTransmitted counters, so retransmissions
// - the cost RaptorQ must beat - are included in bytes-to-completion.

const os = require('os')
const fs = require('fs')
const path = require('path')
const { createRequire } = require('module')
const b4a = require('b4a')
const Hypercore = require('hypercore')
const twoPeer = require('../two-peer')
const { createLossyLink } = require('../lossy-link')

const DEFAULT_BLOCK_SIZE = 4096
const DEFAULT_TOTAL_BLOCKS = 1000
const QUICK_BLOCK_SIZE = 1024
const QUICK_TOTAL_BLOCKS = 100
const DEFAULT_FRACTION = 0.1
const DEFAULT_SEED = 0x51ab1e

const WIRE_METHOD = 'secret-stream rawBytesWritten+rawBytesRead deltas on peer B DHT socket'
const LOSSY_WIRE_METHOD = 'udx socket bytesTransmitted sum over both peers (includes retransmissions)'

module.exports = { run, makeBlock, pickBlocks }

async function run (opts = {}) {
  const quick = opts.quick === true
  const blockSize = opts.blockSize || (quick ? QUICK_BLOCK_SIZE : DEFAULT_BLOCK_SIZE)
  const totalBlocks = opts.totalBlocks || (quick ? QUICK_TOTAL_BLOCKS : DEFAULT_TOTAL_BLOCKS)
  const fraction = opts.fraction || DEFAULT_FRACTION
  const seed = opts.seed || DEFAULT_SEED
  const onblock = opts.onblock || null
  const loss = opts.loss || 0
  const latencyMs = opts.latencyMs || 0
  const jitterMs = opts.jitterMs || 0
  const impaired = loss > 0 || latencyMs > 0

  const dirA = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'hyperlab-bench-replicate-a-'))
  const dirB = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'hyperlab-bench-replicate-b-'))

  let writer = null
  let reader = null
  let peers = null
  let rig = null

  try {
    writer = new Hypercore(dirA)
    await writer.ready()

    const source = new Array(totalBlocks)
    for (let i = 0; i < totalBlocks; i++) source[i] = makeBlock(seed, i, blockSize)
    await writer.append(source)

    if (writer.length !== totalBlocks) {
      throw new Error('replicate bench appended ' + writer.length + ' of ' + totalBlocks + ' blocks')
    }

    reader = new Hypercore(dirB, writer.key)
    await reader.ready()

    let bytesWired = null

    if (impaired) {
      rig = await createLossyRig({ loss, latencyMs, jitterMs, seed })

      rig.attach(
        writer.replicate(false, { keepAlive: false }),
        reader.replicate(true, { keepAlive: false })
      )

      bytesWired = function () {
        return rig.socketA.bytesTransmitted + rig.socketB.bytesTransmitted
      }
    } else {
      peers = await twoPeer()
      const { socketA, socketB } = peers

      const txBefore = socketB.rawBytesWritten
      const rxBefore = socketB.rawBytesRead

      writer.replicate(socketA, { keepAlive: false })
      reader.replicate(socketB, { keepAlive: false })

      bytesWired = function () {
        return (socketB.rawBytesWritten - txBefore) + (socketB.rawBytesRead - rxBefore)
      }
    }

    const indices = pickBlocks(totalBlocks, Math.max(1, Math.round(totalBlocks * fraction)), seed)

    const start = process.hrtime.bigint()
    const range = reader.download({ blocks: indices })
    await range.done()
    const wallMs = Number(process.hrtime.bigint() - start) / 1e6

    const totalBytesWired = bytesWired()

    let blocksVerified = 0
    for (const index of indices) {
      const block = await reader.get(index, { wait: false })
      if (block === null) throw new Error('replicate bench: block ' + index + ' missing after download')
      if (!b4a.equals(block, source[index])) {
        throw new Error('replicate bench: block ' + index + ' does not match source')
      }
      blocksVerified++
      if (onblock) onblock(index, block)
    }

    const blocksRequested = indices.length
    const payloadBytes = blocksRequested * blockSize

    const metrics = {
      name: 'replicate',
      transport: impaired ? 'udx-lossy-link' : 'hyperdht-testnet-socket',
      wireMethod: impaired ? LOSSY_WIRE_METHOD : WIRE_METHOD,
      blockSize,
      totalBlocks,
      seed,
      blocksRequested,
      blocksVerified,
      wallMs,
      totalBytesWired,
      payloadBytes,
      bytesPerBlockOverhead: (totalBytesWired - payloadBytes) / blocksRequested,
      wireEfficiency: payloadBytes / totalBytesWired
    }

    if (impaired) {
      metrics.loss = loss
      metrics.latencyMs = latencyMs
      metrics.jitterMs = jitterMs
      metrics.retransmits = rig.streamA.retransmits + rig.streamB.retransmits
      metrics.droppedDatagrams = rig.linkToA.stats.dropped + rig.linkToB.stats.dropped
    }

    return metrics
  } finally {
    if (rig) await rig.destroy()
    if (peers) await peers.destroy()
    if (reader) await reader.close()
    if (writer) await writer.close()
    await fs.promises.rm(dirA, { recursive: true, force: true })
    await fs.promises.rm(dirB, { recursive: true, force: true })
  }
}

// Two UDX streams over loopback whose datagrams traverse one lossy-link
// proxy per direction (B->A through linkToA, A->B through linkToB), so
// each direction independently drops with probability `loss` and is
// delayed latencyMs +/- jitterMs. UDX retransmits through the loss, so
// replication still completes and the retransmission cost shows up in
// the byte counters.
async function createLossyRig ({ loss, latencyMs, jitterMs, seed }) {
  const UDX = requireUDX()
  const udx = new UDX()

  const socketA = udx.createSocket()
  socketA.bind(0, '127.0.0.1')
  const socketB = udx.createSocket()
  socketB.bind(0, '127.0.0.1')

  let linkToA = null
  let linkToB = null
  let streamA = null
  let streamB = null
  let repA = null
  let repB = null

  try {
    linkToA = await createLossyLink({
      target: { host: '127.0.0.1', port: socketA.address().port },
      loss,
      latencyMs,
      jitterMs,
      seed
    })
    // decorrelate the two directions' drop sequences
    linkToB = await createLossyLink({
      target: { host: '127.0.0.1', port: socketB.address().port },
      loss,
      latencyMs,
      jitterMs,
      seed: (seed ^ 0x9e3779b9) >>> 0
    })

    // datagrams arrive from the proxies' per-flow back sockets, not from
    // the connected remote - accept them (false = allow, hyperdht-style)
    const accept = function () { return false }
    streamA = udx.createStream(1, { firewall: accept })
    streamB = udx.createStream(2, { firewall: accept })

    streamA.connect(socketA, 2, linkToB.port, linkToB.host)
    streamB.connect(socketB, 1, linkToA.port, linkToA.host)
  } catch (err) {
    await destroy()
    throw err
  }

  return { socketA, socketB, streamA, streamB, linkToA, linkToB, attach, destroy }

  function attach (writerStream, readerStream) {
    repA = writerStream
    repB = readerStream
    repA.pipe(streamA).pipe(repA)
    repB.pipe(streamB).pipe(repB)
  }

  async function destroy () {
    if (repA) repA.destroy()
    if (repB) repB.destroy()
    await Promise.all([closeUdxStream(streamA), closeUdxStream(streamB)])
    await Promise.all([socketA.close(), socketB.close()])
    if (linkToA) await linkToA.close()
    if (linkToB) await linkToB.close()
  }
}

// udx-native is not a direct harness dependency - resolve it through
// dht-rpc, so the loss rig always uses the exact UDX build the hyperdht
// stack under test rides on.
function requireUDX () {
  const fromHyperdht = createRequire(require.resolve('hyperdht'))
  return createRequire(fromHyperdht.resolve('dht-rpc'))('udx-native')
}

function closeUdxStream (stream) {
  if (!stream || stream.destroyed) return Promise.resolve()

  return new Promise(function (resolve) {
    stream.once('close', resolve)
    stream.destroy()
  })
}

// Deterministic per-block content: xorshift32 stream seeded by the bench
// seed and the block index, so any run can regenerate the source blocks.
function makeBlock (seed, index, size) {
  const block = b4a.alloc(size)
  const rng = createRng((seed ^ ((index + 1) * 0x9e3779b9)) >>> 0)

  for (let offset = 0; offset < size; offset += 4) {
    const word = rng()
    for (let i = 0; i < 4 && offset + i < size; i++) {
      block[offset + i] = (word >>> (i * 8)) & 0xff
    }
  }

  return block
}

// Deterministic pseudo-random subset of [0, total), sorted ascending.
function pickBlocks (total, count, seed) {
  if (count > total) count = total

  const rng = createRng(seed)
  const picked = new Set()

  while (picked.size < count) {
    picked.add(rng() % total)
  }

  return [...picked].sort(function (a, b) {
    return a - b
  })
}

// xorshift32 returning unsigned 32-bit ints
function createRng (seed) {
  let state = seed >>> 0
  if (state === 0) state = 0xdeadbeef

  return function () {
    state ^= (state << 13) >>> 0
    state ^= state >>> 17
    state ^= (state << 5) >>> 0
    state >>>= 0
    return state
  }
}

if (require.main === module) {
  const quick = process.argv.includes('--quick')

  run({
    quick,
    loss: numberFlag('--loss='),
    latencyMs: numberFlag('--latency='),
    jitterMs: numberFlag('--jitter=')
  })
    .then(function (metrics) {
      console.log(JSON.stringify(metrics))
    })
    .catch(function (err) {
      console.error(err)
      process.exitCode = 1
    })

  function numberFlag (prefix) {
    const arg = process.argv.find(function (a) { return a.startsWith(prefix) })
    const value = arg ? parseFloat(arg.slice(prefix.length)) : 0
    return Number.isFinite(value) && value >= 0 ? value : 0
  }
}
