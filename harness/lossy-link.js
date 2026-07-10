const dgram = require('dgram')

module.exports = { createLossyLink }

// netem-style UDP impairment proxy.
//
// A front socket listens on 127.0.0.1 (ephemeral port). Datagrams from any
// client are forwarded to the target, and replies are routed back to the
// right client via a per-flow back socket (flow map keyed by client
// addr:port — required because all replies come from the same target
// addr:port, so the only way to demux them is one back socket per client).
//
// Each datagram, independently and in both directions, is:
//   - dropped with probability `loss` (deterministic when `seed` is given)
//   - delayed by latencyMs +/- uniform jitterMs
//
// Two independent PRNG streams are used (drop vs jitter) so the drop
// sequence for a given seed does not depend on the jitter configuration.

function createLossyLink ({ target, loss = 0, latencyMs = 0, jitterMs = 0, seed } = {}) {
  if (!target || typeof target.port !== 'number') {
    throw new Error('createLossyLink: target { host, port } is required')
  }

  const targetHost = target.host || '127.0.0.1'
  const targetPort = target.port

  const seeded = typeof seed === 'number'
  const dropRng = seeded ? mulberry32(seed) : Math.random
  const jitterRng = seeded ? mulberry32((seed ^ 0x9e3779b9) >>> 0) : Math.random

  const stats = { forwardedA: 0, forwardedB: 0, dropped: 0, delayedMs: 0 }

  const flows = new Map() // 'addr:port' -> { socket, address, port }
  const timers = new Set()

  let closed = false

  const front = dgram.createSocket('udp4')

  front.on('error', noop)
  front.on('message', function (msg, rinfo) {
    if (closed) return
    const flow = getFlow(rinfo)
    impair(msg, function (data) {
      if (closed) return
      flow.socket.send(data, targetPort, targetHost)
      stats.forwardedA++
    })
  })

  return new Promise(function (resolve, reject) {
    front.once('error', reject)
    front.bind(0, '127.0.0.1', function () {
      front.removeListener('error', reject)
      bumpRecvBuffer(front)
      resolve({
        host: '127.0.0.1',
        port: front.address().port,
        stats,
        setLoss,
        setLatency,
        close
      })
    })
  })

  function setLoss (p) {
    loss = p
  }

  function setLatency (ms, jitter) {
    latencyMs = ms
    if (typeof jitter === 'number') jitterMs = jitter
  }

  async function close () {
    if (closed) return
    closed = true

    for (const timer of timers) clearTimeout(timer)
    timers.clear()

    const closing = [closeSocket(front)]
    for (const flow of flows.values()) closing.push(closeSocket(flow.socket))
    flows.clear()

    await Promise.all(closing)
  }

  function getFlow (rinfo) {
    const key = rinfo.address + ':' + rinfo.port

    let flow = flows.get(key)
    if (flow) return flow

    const socket = dgram.createSocket('udp4')
    flow = { socket, address: rinfo.address, port: rinfo.port }
    flows.set(key, flow)

    socket.on('error', noop)
    socket.on('message', function (msg) {
      if (closed) return
      impair(msg, function (data) {
        if (closed) return
        front.send(data, flow.port, flow.address)
        stats.forwardedB++
      })
    })

    // dgram queues sends issued while the bind is still in flight
    socket.bind(0, '127.0.0.1', function () {
      bumpRecvBuffer(socket)
    })

    return flow
  }

  function impair (msg, send) {
    if (dropRng() < loss) {
      stats.dropped++
      return
    }

    let delay = latencyMs
    if (jitterMs > 0) delay += (jitterRng() * 2 - 1) * jitterMs
    if (delay <= 0) return send(msg)

    stats.delayedMs += delay

    const timer = setTimeout(function () {
      timers.delete(timer)
      send(msg)
    }, delay)

    timers.add(timer)
  }
}

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

function bumpRecvBuffer (socket) {
  try {
    socket.setRecvBufferSize(1 << 20)
  } catch {
    // best effort, platform dependent
  }
}

function closeSocket (socket) {
  return new Promise(function (resolve) {
    try {
      socket.close(resolve)
    } catch {
      resolve() // already closed / never bound
    }
  })
}

function noop () {}
