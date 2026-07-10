const test = require('brittle')
const dgram = require('dgram')
const b4a = require('b4a')
const { createLossyLink } = require('../lossy-link')

test('seeded loss 0.5 over 400 datagrams is deterministic and plausible', async function (t) {
  const first = await runSeededLossRun()
  const second = await runSeededLossRun()

  t.is(first, second, 'same seed gives the same drop count (' + first + ')')
  t.ok(first >= 140 && first <= 260, 'drop count within [140, 260], got ' + first)
})

test('latencyMs 50 delays one-way delivery by >= 45ms', async function (t) {
  const sink = await createSink()
  const link = await createLossyLink({ target: { host: '127.0.0.1', port: sink.port }, latencyMs: 50 })
  const client = await createClient()

  const start = Date.now()
  client.socket.send(b4a.from('delayed'), link.port, link.host)

  await waitFor(() => sink.received.length === 1)
  const elapsed = Date.now() - start

  t.ok(elapsed >= 45, 'one-way delay >= 45ms, got ' + elapsed + 'ms')
  t.ok(link.stats.delayedMs >= 45, 'stats.delayedMs accumulated, got ' + link.stats.delayedMs)

  await link.close()
  await closeSocket(client.socket)
  await closeSocket(sink.socket)
})

test('bidirectional echo routes replies back to the right client', async function (t) {
  const echo = await createEcho()
  const link = await createLossyLink({ target: { host: '127.0.0.1', port: echo.port } })

  const clients = []
  for (let i = 0; i < 8; i++) {
    const client = await createClient()
    client.payload = 'client-' + i
    clients.push(client)
  }

  for (const client of clients) {
    client.socket.send(b4a.from(client.payload), link.port, link.host)
  }

  await waitFor(() => clients.every(c => c.received.length === 1))

  for (const client of clients) {
    t.is(b4a.toString(client.received[0]), client.payload, 'reply routed back to ' + client.payload)
  }

  t.is(link.stats.forwardedA, 8, 'forwardedA counted')
  t.is(link.stats.forwardedB, 8, 'forwardedB counted')
  t.is(link.stats.dropped, 0, 'nothing dropped')

  await link.close()
  for (const client of clients) await closeSocket(client.socket)
  await closeSocket(echo.socket)
})

test('setLoss and setLatency take effect at runtime', async function (t) {
  const sink = await createSink()
  const link = await createLossyLink({ target: { host: '127.0.0.1', port: sink.port } })
  const client = await createClient()

  link.setLoss(1)
  client.socket.send(b4a.from('lost'), link.port, link.host)
  await waitFor(() => link.stats.dropped === 1)
  t.is(sink.received.length, 0, 'loss 1 drops everything')

  link.setLoss(0)
  link.setLatency(30)
  const start = Date.now()
  client.socket.send(b4a.from('slow'), link.port, link.host)
  await waitFor(() => sink.received.length === 1)
  t.ok(Date.now() - start >= 25, 'updated latency applied')

  await link.close()
  await closeSocket(client.socket)
  await closeSocket(sink.socket)
})

test('close() clears pending timers and sockets so the process can exit', async function (t) {
  const sink = await createSink()
  const link = await createLossyLink({ target: { host: '127.0.0.1', port: sink.port }, latencyMs: 60000 })
  const client = await createClient()

  client.socket.send(b4a.from('never delivered'), link.port, link.host)
  await waitFor(() => link.stats.delayedMs >= 60000)

  // if close() leaked the 60s timer or a socket, this brittle run would hang
  // instead of exiting - a hang is a failure
  await link.close()
  t.pass('close() resolved with a 60s delayed datagram pending')

  await link.close()
  t.pass('close() is idempotent')

  t.is(sink.received.length, 0, 'pending datagram was discarded')

  await closeSocket(client.socket)
  await closeSocket(sink.socket)
})

async function runSeededLossRun () {
  const sink = await createSink()
  const link = await createLossyLink({ target: { host: '127.0.0.1', port: sink.port }, loss: 0.5, seed: 42 })
  const client = await createClient()

  for (let i = 0; i < 400; i++) {
    client.socket.send(b4a.from('pkt-' + i), link.port, link.host)
    if (i % 20 === 19) await new Promise(resolve => setImmediate(resolve))
  }

  await waitFor(() => link.stats.forwardedA + link.stats.dropped === 400)
  const dropped = link.stats.dropped

  await link.close()
  await closeSocket(client.socket)
  await closeSocket(sink.socket)

  return dropped
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
