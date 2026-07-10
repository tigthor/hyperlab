const test = require('brittle')
const dgram = require('dgram')
const b4a = require('b4a')
const { createLossyLink } = require('../lossy-link')
const twoPeer = require('../two-peer')
const createTestnet = require('../testnet')

// Rigorous property + fuzz suite for hyperlab-harness.
//
// Everything is driven by a SEEDED prng so any failure reproduces exactly:
// the failing iteration prints its seed. mulberry32 here is a byte-for-byte
// copy of the generator inside lossy-link.js, which lets us PREDICT the exact
// drop count the injector must produce and assert equality - a test that
// would fail on a subtly broken drop path (wrong comparison, shared rng,
// off-by-one) rather than merely "looks plausible".

function mulberry32 (seed) {
  let a = seed >>> 0
  return function () {
    a = (a + 0x6d2b79f5) | 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

// Predict exactly how many of N one-way datagrams the injector drops for a
// given (seed, loss), by replaying the same generator it uses internally.
function predictDrops (seed, loss, n) {
  const rng = mulberry32(seed)
  let dropped = 0
  for (let i = 0; i < n; i++) {
    if (rng() < loss) dropped++
  }
  return dropped
}

// ---------------------------------------------------------------------------
// PROPERTY 1: seeded one-way loss is deterministic, exactly predictable, and
// converges to the configured loss rate over random loss rates.
// ---------------------------------------------------------------------------

test('fuzz: seeded loss is exactly predictable and deterministic over random loss rates', async function (t) {
  const meta = mulberry32(0xC0FFEE)
  const iterations = 24
  const n = 150

  let totalDropped = 0
  let totalExpected = 0

  for (let it = 0; it < iterations; it++) {
    const seed = (meta() * 0xffffffff) >>> 0
    const loss = meta() // uniform in [0, 1)

    const predicted = predictDrops(seed, loss, n)

    const first = await runOneWay({ seed, loss, n })
    const second = await runOneWay({ seed, loss, n })

    t.is(
      first, predicted,
      'iter ' + it + ' seed=' + seed + ' loss=' + loss.toFixed(4) +
      ': drop count matches predicted mulberry32 draws (' + predicted + ')'
    )
    t.is(
      second, first,
      'iter ' + it + ' seed=' + seed + ': re-running the same seed reproduces the drop count'
    )

    // Per-iteration statistical sanity: within a wide (6-sigma + slack) band.
    const mean = n * loss
    const sd = Math.sqrt(n * loss * (1 - loss)) || 0
    t.ok(
      Math.abs(first - mean) <= 6 * sd + 2,
      'iter ' + it + ': drop count ' + first + ' near mean ' + mean.toFixed(1)
    )

    totalDropped += first
    totalExpected += mean
  }

  // Aggregate convergence (law of large numbers over ~3600 datagrams).
  const observedRate = totalDropped / (iterations * n)
  const expectedRate = totalExpected / (iterations * n)
  t.ok(
    Math.abs(observedRate - expectedRate) <= 0.03,
    'aggregate loss rate ' + observedRate.toFixed(4) +
    ' tracks configured ' + expectedRate.toFixed(4)
  )
})

// ---------------------------------------------------------------------------
// PROPERTY 2: jitter configuration must NOT change the drop sequence (the
// injector documents two independent prng streams). This would FAIL if the
// drop and jitter draws ever shared a generator.
// ---------------------------------------------------------------------------

test('fuzz: jitter/latency config does not perturb the seeded drop count', async function (t) {
  const meta = mulberry32(0x1234abcd)
  const n = 120

  for (let it = 0; it < 8; it++) {
    const seed = (meta() * 0xffffffff) >>> 0
    const loss = 0.2 + meta() * 0.5 // [0.2, 0.7)

    const noJitter = await runOneWay({ seed, loss, n })
    const withJitter = await runOneWay({ seed, loss, n, latencyMs: 3, jitterMs: 8 })

    t.is(
      withJitter, noJitter,
      'iter ' + it + ' seed=' + seed + ': drop count invariant to jitter/latency (' + noJitter + ')'
    )
    t.is(withJitter, predictDrops(seed, loss, n), 'iter ' + it + ': still matches prediction')
  }
})

// ---------------------------------------------------------------------------
// PROPERTY 3: bidirectional echo through the proxy under loss + latency.
// Whatever survives the round trip must be a byte-exact, non-duplicated echo
// of something we sent (integrity), never more than we sent, and latency is
// actually applied. A clean (loss=0) config must round-trip every datagram.
// ---------------------------------------------------------------------------

test('bidirectional echo integrity under loss + latency (clean link delivers all)', async function (t) {
  const echo = await createEcho()
  const link = await createLossyLink({
    target: { host: '127.0.0.1', port: echo.port },
    loss: 0,
    latencyMs: 12,
    jitterMs: 4,
    seed: 7
  })
  const client = await createClient()

  const n = 40
  const sent = []
  for (let i = 0; i < n; i++) {
    const payload = 'clean-' + i + '-' + Math.random().toString(36).slice(2)
    sent.push(payload)
    client.socket.send(b4a.from(payload), link.port, link.host)
    if (i % 10 === 9) await tick()
  }

  await waitFor(() => client.received.length === n, 8000)

  const seen = client.received.map(b => b4a.toString(b))
  const sentSet = new Set(sent)
  t.ok(seen.every(p => sentSet.has(p)), 'every echo is a byte-exact payload we sent')
  t.is(new Set(seen).size, n, 'no echo was duplicated or dropped on a clean link')
  t.ok(link.stats.delayedMs > 0, 'latency was actually applied (delayedMs=' + link.stats.delayedMs + ')')
  t.is(link.stats.dropped, 0, 'loss=0 drops nothing')

  await link.close()
  await closeSocket(client.socket)
  await closeSocket(echo.socket)
})

test('fuzz: lossy echo never corrupts, duplicates, or invents payloads', async function (t) {
  const meta = mulberry32(0xBADA55)

  for (let it = 0; it < 6; it++) {
    const echo = await createEcho()
    const seed = (meta() * 0xffffffff) >>> 0
    const loss = 0.1 + meta() * 0.3 // [0.1, 0.4)
    const latencyMs = 2 + Math.floor(meta() * 10)
    const jitterMs = Math.floor(meta() * 5)

    const link = await createLossyLink({
      target: { host: '127.0.0.1', port: echo.port },
      loss,
      latencyMs,
      jitterMs,
      seed
    })
    const client = await createClient()

    const n = 60
    const sent = []
    for (let i = 0; i < n; i++) {
      const payload = 'it' + it + '-pkt' + i
      sent.push(payload)
      client.socket.send(b4a.from(payload), link.port, link.host)
      if (i % 12 === 11) await tick()
    }

    // Wait until all forward datagrams are accounted for, then let the delayed
    // echoes settle (round trip + jitter + generous slack).
    await waitFor(() => link.stats.forwardedA + link.stats.dropped >= n, 8000)
    await settle(2 * latencyMs + jitterMs + 250)

    const seen = client.received.map(b => b4a.toString(b))
    const sentSet = new Set(sent)

    t.ok(
      seen.every(p => sentSet.has(p)),
      'iter ' + it + ' seed=' + seed + ': no corrupted/invented echo'
    )
    t.is(new Set(seen).size, seen.length, 'iter ' + it + ': no duplicated echo')
    t.ok(seen.length <= n, 'iter ' + it + ': never more echoes than sent')
    t.ok(
      link.stats.forwardedB <= link.stats.forwardedA,
      'iter ' + it + ': back-forwarded <= forward-forwarded'
    )

    await link.close()
    await closeSocket(client.socket)
    await closeSocket(echo.socket)
  }
})

// ---------------------------------------------------------------------------
// PROPERTY 4: createTestnet boots and destroys N nodes cleanly for random N,
// leaving no live handles behind (a leak would hang this brittle run).
// ---------------------------------------------------------------------------

test('fuzz: createTestnet boots and destroys N nodes cleanly for random N', async function (t) {
  const meta = mulberry32(0x5EED)

  for (let it = 0; it < 8; it++) {
    const size = 1 + Math.floor(meta() * 6) // [1, 6]
    const testnet = await createTestnet(size)

    t.is(testnet.nodes.length, size, 'iter ' + it + ': booted ' + size + ' nodes')
    t.is(testnet.bootstrap.length, 1, 'iter ' + it + ': single bootstrap entry')
    t.ok(testnet.nodes.every(node => node.bootstrapped), 'iter ' + it + ': all bootstrapped')

    await testnet.destroy()

    t.ok(testnet.nodes.every(node => node.destroyed), 'iter ' + it + ': all destroyed cleanly')
  }
})

// ---------------------------------------------------------------------------
// PROPERTY 5: two-peer bidirectional data integrity. Random-sized frames of
// random bytes, streamed both directions, must arrive byte-exact when
// reassembled (NoiseSecretStream may re-chunk, so we compare concatenations).
// ---------------------------------------------------------------------------

test('fuzz: two-peer bidirectional streams preserve byte-exact data', async function (t) {
  const testnet = await createTestnet(3, { teardown: t })
  const rig = await twoPeer({ testnet })
  t.teardown(rig.destroy)

  const meta = mulberry32(0xF00DBEEF)

  for (let round = 0; round < 6; round++) {
    const bToA = randomBuffer(meta, 200 + Math.floor(meta() * 3000))
    const aToB = randomBuffer(meta, 200 + Math.floor(meta() * 3000))

    const gotOnA = collectBytes(rig.socketA, bToA.length)
    const gotOnB = collectBytes(rig.socketB, aToB.length)

    writeChunked(rig.socketB, bToA, meta)
    writeChunked(rig.socketA, aToB, meta)

    const [onA, onB] = await Promise.all([gotOnA, gotOnB])

    t.ok(b4a.equals(onA, bToA), 'round ' + round + ': b -> a arrived byte-exact (' + bToA.length + 'B)')
    t.ok(b4a.equals(onB, aToB), 'round ' + round + ': a -> b arrived byte-exact (' + aToB.length + 'B)')
  }
})

// --- helpers ---------------------------------------------------------------

async function runOneWay ({ seed, loss, n, latencyMs = 0, jitterMs = 0 }) {
  const sink = await createSink()
  const link = await createLossyLink({
    target: { host: '127.0.0.1', port: sink.port },
    loss,
    latencyMs,
    jitterMs,
    seed
  })
  const client = await createClient()

  for (let i = 0; i < n; i++) {
    client.socket.send(b4a.from('pkt-' + i), link.port, link.host)
    if (i % 20 === 19) await tick()
  }

  await waitFor(() => link.stats.forwardedA + link.stats.dropped === n, 8000)
  const dropped = link.stats.dropped

  await link.close()
  await closeSocket(client.socket)
  await closeSocket(sink.socket)

  return dropped
}

function randomBuffer (rng, len) {
  const buf = b4a.alloc(len)
  for (let i = 0; i < len; i++) buf[i] = Math.floor(rng() * 256)
  return buf
}

function writeChunked (socket, buf, rng) {
  let off = 0
  while (off < buf.length) {
    const chunk = 1 + Math.floor(rng() * 512)
    const end = Math.min(off + chunk, buf.length)
    socket.write(buf.subarray(off, end))
    off = end
  }
}

function collectBytes (socket, total) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let got = 0
    const timer = setTimeout(() => {
      socket.removeListener('data', ondata)
      reject(new Error('collectBytes timed out at ' + got + '/' + total))
    }, 15000)

    socket.on('data', ondata)

    function ondata (data) {
      chunks.push(data)
      got += data.length
      if (got >= total) {
        clearTimeout(timer)
        socket.removeListener('data', ondata)
        resolve(b4a.concat(chunks).subarray(0, total))
      }
    }
  })
}

async function createSink () {
  const socket = dgram.createSocket('udp4')
  const received = []
  socket.on('message', msg => received.push(msg))
  await bind(socket)
  return { socket, received, port: socket.address().port }
}

async function createEcho () {
  const socket = dgram.createSocket('udp4')
  socket.on('message', function (msg, rinfo) {
    socket.send(msg, rinfo.port, rinfo.address)
  })
  await bind(socket)
  return { socket, port: socket.address().port }
}

async function createClient () {
  const socket = dgram.createSocket('udp4')
  const received = []
  socket.on('message', msg => received.push(msg))
  await bind(socket)
  return { socket, received }
}

function bind (socket) {
  return new Promise(resolve => socket.bind(0, '127.0.0.1', resolve))
}

function closeSocket (socket) {
  return new Promise(resolve => socket.close(resolve))
}

function tick () {
  return new Promise(resolve => setImmediate(resolve))
}

function settle (ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function waitFor (fn, timeout = 5000) {
  return new Promise(function (resolve, reject) {
    const start = Date.now()
    check()

    function check () {
      if (fn()) return resolve()
      if (Date.now() - start > timeout) return reject(new Error('waitFor timed out'))
      setTimeout(check, 10)
    }
  })
}
