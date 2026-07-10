// Chapter 10 gate: fountain-coded replication vs classical want/have on a
// lossy link, measured as BYTES-TO-COMPLETION for a group of ~k blocks.
//
// GATE (the book): coded replication must transfer FEWER bytes to complete a
// download on a >=5% loss link, else it is a research note not a merge. On a
// clean (0%) link the systematic property must make it NO WORSE.
//
// Two sides, both driven over the harness's real lossy-link.js UDP injector:
//
//   want/have : the recorded baseline path — real hypercore + UDX over the
//               lossy rig (replicate.js run()), which retransmits every
//               dropped datagram. Bytes = UDX socket bytesTransmitted over
//               both peers (includes retransmissions), matching
//               baselines.full.json replicate-lossy (bytesPerBlockOverhead
//               ~1233 at 5% loss).
//
//   coded     : our systematic GF(256) random-linear fountain codec
//               (labs/hypercore-raptorq). A sender streams encoding symbols
//               (k systematic, then repair) as UDP datagrams through the SAME
//               lossy-link proxy; the receiver runs the real GF(256) decoder
//               and completes once it has k linearly-independent symbols. No
//               retransmission — loss is absorbed by sending more repair
//               symbols. Bytes-to-completion = total symbol bytes the sender
//               had put on the wire at the instant the receiver decoded (so
//               in-flight/overshoot symbols are counted, fair to want/have's
//               retransmit bytes), plus one completion ACK datagram.
//
// HONESTY. The byte counters are not identical instruments: want/have's total
// includes the UDX transport framing + Noise handshake + want/have control
// messages; the coded total is application symbol datagrams (payload +
// compact-encoding header) + one ACK, with no separate reliability layer
// (the fountain IS the reliability layer). This slightly favors coded on
// fixed overhead, but the term the gate turns on — payload+redundancy vs
// payload+retransmission under loss — is measured fairly on both. The codec
// is RLNC-style, not literal RFC 6330 RaptorQ (O(k^2) decode, no LDPC/HDPC
// precode); see labs/hypercore-raptorq/README.md.

const dgram = require('dgram')
const b4a = require('b4a')
const { createLossyLink } = require('../lossy-link')
const replicate = require('./replicate')
// required by path (the codec is a workspace sibling, not a harness dep)
const { Encoder, Decoder, encodeSymbol, decodeSymbol } = require('../../labs/hypercore-raptorq')

const DEFAULT_K = 64
const DEFAULT_BLOCK_SIZE = 4096
const DEFAULT_SEED = 0x51ab1e
const LOSS_SWEEP = [0, 0.05, 0.10, 0.20]

module.exports = { run, codedTransfer, wantHaveTransfer }

// --- coded side: real symbols over the real lossy-link ---------------------
//
// Resolves once the receiver has decoded and verified all k blocks, or
// rejects on timeout. Everything is torn down in finally (no hangs).
async function codedTransfer ({ k, blockSize, loss, latencyMs = 0, jitterMs = 0, seed }) {
  const source = new Array(k)
  for (let i = 0; i < k; i++) source[i] = replicate.makeBlock(seed, i, blockSize)

  const enc = new Encoder(source, { symbolSize: blockSize })
  const dec = new Decoder(k, { symbolSize: blockSize })

  const receiver = dgram.createSocket('udp4')
  let sender = null
  let link = null

  // shared completion state; snapshotting bytesSent at the decode instant is
  // the true "bytes-to-completion" (counts symbols still in flight, fair)
  const wire = { bytesSent: 0, symbolsSent: 0, done: false }
  let ackBytes = 0

  try {
    await bind(receiver)

    link = await createLossyLink({
      target: { host: '127.0.0.1', port: receiver.address().port },
      loss,
      latencyMs,
      jitterMs,
      seed
    })

    sender = dgram.createSocket('udp4')
    await bind(sender)

    const completion = new Promise(function (resolve, reject) {
      const timer = setTimeout(function () {
        reject(new Error('coded transfer timed out at loss=' + loss + ' (sent ' + wire.symbolsSent + ', rank ' + dec.rank + '/' + k + ')'))
      }, 30000)

      receiver.on('message', function (buf, rinfo) {
        if (wire.done) return
        let m
        try { m = decodeSymbol(buf) } catch { return }
        const decodable = dec.add({ esi: m.esi, symbol: m.symbol })
        if (!decodable) return

        // reached rank k: snapshot bytes-to-completion, verify, ack, resolve
        wire.done = true
        const bytesAtDecode = wire.bytesSent
        const symbolsAtDecode = wire.symbolsSent

        const out = dec.decode()
        let verified = 0
        for (let i = 0; i < k; i++) {
          if (!b4a.equals(out[i], source[i])) {
            clearTimeout(timer)
            return reject(new Error('coded transfer: block ' + i + ' mismatch after decode'))
          }
          verified++
        }

        // completion ACK back to the sender (through the link)
        const ack = b4a.from('done')
        ackBytes = ack.length
        receiver.send(ack, rinfo.port, rinfo.address, function () {})

        clearTimeout(timer)
        resolve({ bytesAtDecode, symbolsAtDecode, verified })
      })
    })

    // sender: stream symbols esi = 0,1,2,... until the receiver decodes
    // (wire.done) or a generous cap is hit. Paced one-per-tick so the event
    // loop delivers arrivals and the decode can stop the stream promptly.
    const cap = Math.ceil(k / Math.max(0.01, 1 - loss)) * 3 + 32
    ;(function sendNext (esi) {
      if (wire.done || esi >= cap) return
      const msg = enc.message(esi)
      const buf = encodeSymbol(msg)
      sender.send(buf, link.port, link.host, function () {})
      wire.bytesSent += buf.length
      wire.symbolsSent++
      setImmediate(sendNext, esi + 1)
    })(0)

    const result = await completion

    const bytesToCompletion = result.bytesAtDecode + ackBytes
    const payloadBytes = k * blockSize
    return {
      side: 'coded',
      k,
      blockSize,
      loss,
      latencyMs,
      symbolsSentAtDecode: result.symbolsAtDecode,
      symbolsSentTotal: wire.symbolsSent,
      overheadSymbols: result.symbolsAtDecode - k,
      bytesToCompletion,
      payloadBytes,
      bytesPerBlockOverhead: (bytesToCompletion - payloadBytes) / k,
      wireEfficiency: payloadBytes / bytesToCompletion,
      droppedDatagrams: link.stats.dropped,
      verified: result.verified
    }
  } finally {
    wire.done = true
    await closeSocket(receiver)
    if (sender) await closeSocket(sender)
    if (link) await link.close()
  }
}

// --- want/have side: the recorded baseline path ----------------------------
//
// Runs real hypercore replication of a k-block core over the UDX lossy rig
// and downloads all k blocks. Bytes = UDX bytesTransmitted over both peers
// (includes retransmissions), exactly the baselines.full.json methodology.
async function wantHaveTransfer ({ k, blockSize, loss, latencyMs = 0, jitterMs = 0, seed }) {
  const m = await replicate.run({
    totalBlocks: k,
    blockSize,
    fraction: 1, // download the whole group
    loss,
    latencyMs,
    jitterMs,
    seed
  })
  return {
    side: 'want-have',
    k,
    blockSize,
    loss,
    latencyMs,
    bytesToCompletion: m.totalBytesWired,
    payloadBytes: m.payloadBytes,
    bytesPerBlockOverhead: m.bytesPerBlockOverhead,
    wireEfficiency: m.wireEfficiency,
    retransmits: m.retransmits,
    droppedDatagrams: m.droppedDatagrams,
    wallMs: m.wallMs
  }
}

async function run (opts = {}) {
  const k = opts.k || DEFAULT_K
  const blockSize = opts.blockSize || DEFAULT_BLOCK_SIZE
  const seed = opts.seed || DEFAULT_SEED
  const latencyMs = opts.latencyMs || 0
  const jitterMs = opts.jitterMs || 0
  const losses = opts.losses || LOSS_SWEEP

  const rows = []
  for (const loss of losses) {
    const wantHave = await wantHaveTransfer({ k, blockSize, loss, latencyMs, jitterMs, seed })
    const coded = await codedTransfer({ k, blockSize, loss, latencyMs, jitterMs, seed })

    const winner = coded.bytesToCompletion < wantHave.bytesToCompletion ? 'coded' : 'want-have'
    const ratio = coded.bytesToCompletion / wantHave.bytesToCompletion
    rows.push({
      loss,
      wantHaveBytes: wantHave.bytesToCompletion,
      codedBytes: coded.bytesToCompletion,
      wantHaveOverheadPerBlock: round(wantHave.bytesPerBlockOverhead),
      codedOverheadPerBlock: round(coded.bytesPerBlockOverhead),
      codedOverheadSymbols: coded.overheadSymbols,
      savingsPct: round((1 - ratio) * 100),
      winner
    })
  }

  // gate verdict: coded beats want/have at every loss >= 5%, and is no worse
  // than a small tolerance at 0% (systematic form).
  const lossy = rows.filter(r => r.loss >= 0.05)
  const beatsAtLoss = lossy.length > 0 && lossy.every(r => r.codedBytes < r.wantHaveBytes)
  const clean = rows.find(r => r.loss === 0)
  const noWorseAtZero = !clean || clean.codedBytes <= clean.wantHaveBytes * 1.02

  return {
    name: 'raptorq-gate',
    codec: 'systematic GF(256) random-linear fountain (RLNC-style, not RFC 6330 RaptorQ)',
    k,
    blockSize,
    seed,
    latencyMs,
    jitterMs,
    rows,
    passes: beatsAtLoss && noWorseAtZero,
    beatsAtLoss,
    noWorseAtZero
  }
}

// --- helpers ---------------------------------------------------------------
function bind (socket) {
  return new Promise(function (resolve, reject) {
    socket.once('error', reject)
    socket.bind(0, '127.0.0.1', function () {
      socket.removeListener('error', reject)
      try { socket.setRecvBufferSize(1 << 20) } catch {}
      resolve()
    })
  })
}

function closeSocket (socket) {
  return new Promise(function (resolve) {
    try { socket.close(resolve) } catch { resolve() }
  })
}

function round (n) {
  return Math.round(n * 100) / 100
}

if (require.main === module) {
  run({
    k: intFlag('--k=', DEFAULT_K),
    blockSize: intFlag('--block=', DEFAULT_BLOCK_SIZE),
    latencyMs: intFlag('--latency=', 0),
    jitterMs: intFlag('--jitter=', 0)
  })
    .then(function (out) {
      console.log(JSON.stringify(out, null, 2))
      console.log('\nGATE: coded beats want/have at >=5% loss =', out.beatsAtLoss,
        '| no worse at 0% =', out.noWorseAtZero, '| PASSES =', out.passes)
    })
    .catch(function (err) {
      console.error(err)
      process.exitCode = 1
    })

  function intFlag (prefix, dflt) {
    const arg = process.argv.find(a => a.startsWith(prefix))
    if (!arg) return dflt
    const v = Number(arg.slice(prefix.length))
    return Number.isFinite(v) ? v : dflt
  }
}
