// HyperDHT handshake benchmark.
//
// Baseline for the PQ-handshake research gate: hybrid Noise+ML-KEM must
// add <1 ms latency, and the first handshake message size matters because
// ML-KEM public keys are >1 KB. This bench records today's numbers.
//
// One long-lived server on node A; each iteration opens a fresh client
// socket from node B and measures:
//   (a) time-to-open latency in ms (median / p95 / min over N handshakes)
//   (b) bytes on the wire for connection setup. The udx socket
//       bytesTransmitted counter reads 0 for hyperdht's DHT request
//       traffic (verified empirically on udx-native 1.20.7), so tx-based
//       counts would be garbage. bytesReceived does track correctly, so
//       both directions are measured with rx deltas instead: the client
//       node's rx delta is the server->client setup traffic and the
//       server node's rx delta is the client->server setup traffic that
//       reaches the server (DHT lookup queries to other nodes excluded).
//   (c) firstMessageBytes: byteLength of the first inbound Noise (IK)
//       handshake message, observed at the server via a wrapped
//       createHandshake.

const DHT = require('hyperdht')
const NoiseWrap = require('hyperdht/lib/noise-wrap')
const createTestnet = require('../testnet')

const DEFAULT_HANDSHAKES = 15
const QUICK_HANDSHAKES = 3
const SETTLE_MS = 10

module.exports = { run }

async function run (opts = {}) {
  const handshakes = opts.handshakes || (opts.quick === true ? QUICK_HANDSHAKES : DEFAULT_HANDSHAKES)

  const testnet = await createTestnet(3)
  const serverNode = testnet.createNode()
  const clientNode = testnet.createNode()

  const firstMessageSizes = []
  const acceptQueue = createAcceptQueue()

  const server = serverNode.createServer({
    createHandshake: function (keyPair, remotePublicKey) {
      return instrumentHandshake(new NoiseWrap(keyPair, remotePublicKey), firstMessageSizes)
    }
  }, function (socket) {
    socket.on('error', noop) // teardown races may surface ECONNRESET
    acceptQueue.push(socket)
  })

  const latencies = []
  const clientRxBytes = []
  const serverRxBytes = []

  let bytesObservable = true

  try {
    await server.listen(DHT.keyPair())

    for (let i = 0; i < handshakes; i++) {
      const clientBefore = receivedBytesTotal(clientNode)
      const serverBefore = receivedBytesTotal(serverNode)

      const start = process.hrtime.bigint()
      const socket = clientNode.connect(server.publicKey)
      socket.on('error', noop)

      if ((await socket.opened) === false) {
        throw new Error('bench/handshake: client socket ' + i + ' failed to open')
      }

      latencies.push(Number(process.hrtime.bigint() - start) / 1e6)

      const clientAfter = receivedBytesTotal(clientNode)
      const serverAfter = receivedBytesTotal(serverNode)

      if (clientBefore === null || clientAfter === null || serverBefore === null || serverAfter === null) {
        bytesObservable = false
      } else {
        clientRxBytes.push(Math.max(0, clientAfter - clientBefore))
        serverRxBytes.push(Math.max(0, serverAfter - serverBefore))
      }

      const serverSocket = await acceptQueue.shift()

      await Promise.all([closeSocket(socket), closeSocket(serverSocket)])

      // let trailing holepunch/upgrade traffic settle so it does not
      // leak into the next iteration's byte window
      await sleep(SETTLE_MS)
    }
  } finally {
    await testnet.destroy()
  }

  const metrics = {
    name: 'handshake',
    handshakes,
    latencyMsMedian: median(latencies),
    latencyMsP95: percentile(latencies, 95),
    latencyMsMin: Math.min(...latencies)
  }

  if (bytesObservable && clientRxBytes.length === handshakes) {
    metrics.setupBytesToClientMedian = median(clientRxBytes)
    metrics.setupBytesToServerMedian = median(serverRxBytes)
    metrics.setupBytesTotalMedian = median(clientRxBytes.map(function (rx, i) {
      return rx + serverRxBytes[i]
    }))
    metrics.bytesNote = 'UDP payload rx deltas over each DHT node UDX sockets (dht-rpc io sockets + hyperdht socket pool) from connect() to stream open; udx bytesTransmitted reads 0 for DHT request traffic on udx-native 1.20.7 so tx counters are not used; toClient = server->client bytes, toServer = client->server bytes reaching the server (DHT lookup queries to other nodes excluded); excludes IP/UDP headers; idle testnet rx noise measured at 0'
  } else {
    metrics.bytesNote = 'UDX socket byte counters were not observable on this hyperdht/udx-native version, so wire bytes are omitted'
  }

  if (firstMessageSizes.length > 0) {
    metrics.firstMessageBytes = median(firstMessageSizes)
    metrics.firstMessageNote = 'byteLength of the first inbound Noise (IK) handshake message observed at the server via createHandshake; it travels inside a DHT request, so the on-wire datagram is larger'
  } else {
    metrics.firstMessageNote = 'no server-side handshake was observed, firstMessageBytes omitted'
  }

  return metrics
}

// Records the size of the first noise message this handshake receives.
function instrumentHandshake (handshake, sizes) {
  const recv = handshake.recv.bind(handshake)
  let first = true

  handshake.recv = function (buf) {
    if (first) {
      first = false
      sizes.push(buf.byteLength)
    }
    return recv(buf)
  }

  return handshake
}

function createAcceptQueue () {
  const sockets = []
  const waiters = []

  return {
    push: function (socket) {
      const waiter = waiters.shift()
      if (waiter) waiter(socket)
      else sockets.push(socket)
    },
    shift: function () {
      if (sockets.length > 0) return Promise.resolve(sockets.shift())
      return new Promise(function (resolve) {
        waiters.push(resolve)
      })
    }
  }
}

// Sums bytesReceived over every UDX socket the node owns: the dht-rpc io
// sockets plus any hyperdht socket-pool sockets (holepunching / raw
// streams). Returns null if the counters are missing.
function receivedBytesTotal (node) {
  const sockets = new Set()

  if (node.io && node.io.clientSocket) sockets.add(node.io.clientSocket)
  if (node.io && node.io.serverSocket) sockets.add(node.io.serverSocket)

  if (node._socketPool && node._socketPool._sockets) {
    for (const socket of node._socketPool._sockets.keys()) sockets.add(socket)
  }

  if (sockets.size === 0) return null

  let total = 0

  for (const socket of sockets) {
    if (typeof socket.bytesReceived !== 'number') return null
    total += socket.bytesReceived
  }

  return total
}

function closeSocket (socket) {
  if (!socket || socket.destroyed) return Promise.resolve()

  return new Promise(function (resolve) {
    socket.once('close', resolve)
    socket.destroy()
  })
}

function sleep (ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, ms)
  })
}

function median (values) {
  return percentile(values, 50)
}

function percentile (values, p) {
  const sorted = values.slice().sort(function (a, b) { return a - b })
  const rank = Math.ceil((p / 100) * sorted.length)
  return sorted[Math.max(0, rank - 1)]
}

function noop () {}

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
