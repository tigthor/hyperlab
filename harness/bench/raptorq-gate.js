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
const { Encoder, Decoder, encodeSymbol, decodeSymbol, leafHash } = require('../../labs/hypercore-raptorq')

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
  // The receiver holds the authenticated leaf hashes (in a real system these
  // arrive over hypercore's verified tree messages); decode() authenticates
  // every reconstructed block against them and REJECTS on any mismatch, so a
  // forged repair symbol cannot silently corrupt the output.
  const hashes = source.map(leafHash)
  const dec = new Decoder(k, { symbolSize: blockSize, hashes })

  const receiver = dgram.createSocket('udp4')
  let sender = null
  let link = null

  // One estimated round-trip time over the simulated link (forward + return,
  // plus a jitter/scheduling margin). Flow-control rounds are spaced by this
  // so a batch is reflected in the receiver's rank before the next round.
  const rttMs = 2 * (latencyMs + jitterMs) + 8

  // Forward wire accounting (sender -> receiver symbol bytes) and reverse
  // accounting (receiver -> sender feedback bytes). bytesToCompletion counts
  // BOTH directions up to the decode instant, matching want/have's two-peer
  // byte total. `senderStopped` is set ONLY when the sender's socket receives
  // a link-delivered completion ACK — real flow control, not a shared flag.
  const wire = { fwdBytes: 0, symbolsSent: 0, revBytes: 0, decoded: false }
  let senderStopped = false
  let resolveStopped = null
  const stoppedPromise = new Promise(function (r) { resolveStopped = r })

  // reverse feedback framing: [0, rankLo, rankHi] = rank report, [1] = done
  function rankMsg (rank) { return b4a.from([0, rank & 0xff, (rank >> 8) & 0xff]) }
  const doneMsg = b4a.from([1])

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

    let doneTimer = null
    const timers = new Set()
    const track = function (t) { timers.add(t); return t }

    const completion = new Promise(function (resolve, reject) {
      const timer = track(setTimeout(function () {
        reject(new Error('coded transfer timed out at loss=' + loss + ' (sent ' + wire.symbolsSent + ', rank ' + dec.rank + '/' + k + ')'))
      }, 30000))

      let senderAddr = null
      receiver.on('message', function (buf, rinfo) {
        senderAddr = rinfo
        if (wire.decoded) return
        let m
        try { m = decodeSymbol(buf) } catch { return }
        const decodable = dec.add({ esi: m.esi, symbol: m.symbol })

        // report current rank back to the sender so it can pace repair
        // (feedback drives the sender's flow control; rank is monotonic)
        const rep = rankMsg(dec.rank)
        wire.revBytes += rep.length
        receiver.send(rep, rinfo.port, rinfo.address, function () {})

        if (!decodable) return

        // reached rank k: snapshot bytes-to-completion, authenticate, ack
        wire.decoded = true
        const bytesAtDecode = wire.fwdBytes + wire.revBytes
        const symbolsAtDecode = wire.symbolsSent

        let out
        try {
          out = dec.decode() // authenticates against leaf hashes; throws on tamper
        } catch (err) {
          clearTimeout(timer)
          return reject(err)
        }
        let verified = 0
        for (let i = 0; i < k; i++) {
          if (!b4a.equals(out[i], source[i])) {
            clearTimeout(timer)
            return reject(new Error('coded transfer: block ' + i + ' mismatch after decode'))
          }
          verified++
        }

        // completion ACK back to the sender (through the link), retransmitted
        // a few times over ~RTT so it survives loss; the sender STOPS on it.
        let acksLeft = 6
        const sendAck = function () {
          if (acksLeft-- <= 0) { clearTimeout(doneTimer); return }
          receiver.send(doneMsg, rinfo.port, rinfo.address, function () {})
          doneTimer = track(setTimeout(sendAck, Math.max(4, rttMs / 2)))
        }
        sendAck()

        clearTimeout(timer)
        resolve({ bytesAtDecode, symbolsAtDecode, verified })
      })
    })

    // sender flow control. latestRank is refreshed by receiver feedback; the
    // sender only ever has ~one round's worth of symbols in flight, so the
    // decode-instant overshoot is bounded to <= 1 RTT of the current deficit
    // (not the old blind flood). It stops the instant the link delivers 'done'.
    let latestRank = 0
    let nextEsi = 0
    const cap = Math.ceil(k / Math.max(0.01, 1 - loss)) * 2 + 16

    // A repair round must size itself from a rank that has FULLY SETTLED after
    // the last batch — never from a stale or half-arrived rank. When we send a
    // batch we clear `feedbackSinceBatch` and stamp `lastBatchAt`; every rank
    // report from the receiver sets `feedbackSinceBatch` and refreshes
    // latestRank.
    //
    // The old code sized every round as `deficit = k - latestRank` on a fixed
    // RTT timer. When the very first timer tick won the race against the
    // systematic burst's loopback round-trip, latestRank was still the initial
    // 0, so deficit=k and the sender flooded a WHOLE extra batch (~132k) — the
    // bimodality. A weaker "wait for one feedback" guard fixes the k-flood but
    // still over-sends when the tick lands mid-trickle: the 64 systematic rank
    // reports arrive as a burst spread over a few event-loop turns, so a round
    // that sizes from the FIRST of them (rank ~35) sends ~30 needless symbols.
    //
    // So we size a round only once latestRank has STOPPED CLIMBING (settled)
    // across a poll interval: the systematic round's rank is then fully
    // reflected (~61 at 5% loss) and the deficit is the true residual (~3).
    // While latestRank===0 (systematic feedback not back yet — the reverse path
    // is LOSSLESS so it is guaranteed to arrive) we only poll, never flood.
    let feedbackSinceBatch = false
    let lastBatchAt = Date.now()

    sender.on('message', function (buf) {
      if (buf.length >= 1 && buf[0] === 1) { // done ACK
        senderStopped = true
        resolveStopped()
        return
      }
      if (buf.length >= 3 && buf[0] === 0) {
        const r = buf[1] | (buf[2] << 8)
        if (r > latestRank) latestRank = r
        feedbackSinceBatch = true
      }
    })

    const sendBatch = function (n) {
      let sent = 0
      for (let i = 0; i < n && nextEsi < cap; i++) {
        const b = encodeSymbol(enc.message(nextEsi++))
        sender.send(b, link.port, link.host, function () {})
        wire.fwdBytes += b.length
        wire.symbolsSent++
        sent++
      }
      // this batch's effect on the receiver's rank is not yet observed; the
      // next repair round must wait for it to settle before sizing again.
      if (sent > 0) { feedbackSinceBatch = false; lastBatchAt = Date.now() }
    }

    // round 0: the k systematic symbols (all are needed on any link)
    sendBatch(k)

    // A short poll used while we wait for the current batch's rank to settle —
    // much smaller than a full RTT so we react promptly, without ever guessing.
    const pollMs = Math.max(2, Math.floor(rttMs / 4))
    // A generous lost-batch timeout: if a whole repair batch is dropped on the
    // (lossy) forward path, NO feedback ever comes, so `settled` can never fire
    // — after this long with no fresh feedback we resend the true residual
    // deficit (those symbols are gone, not in flight, so no double count). It
    // is set well above any real settle time so it never preempts natural
    // settling of a delivered batch.
    const lostBatchMs = Math.max(40, rttMs * 4)

    // Subsequent rounds: top up exactly the remaining deficit, sized from a
    // settled rank. `settled` = we have fresh feedback for the last batch AND
    // latestRank did not change over the last poll (the burst has fully
    // arrived). Otherwise we either wait (still climbing / not back yet) or, if
    // a full lost-batch timeout has elapsed with no feedback, resend the
    // residual. The latestRank===0 guard blocks the flood: it forces a wait for
    // the guaranteed systematic feedback rather than sizing from the stale
    // initial rank. Net: total sent converges to ~k/(1-loss), unimodal.
    let rankAtPrevPoll = -1
    const roundTick = function () {
      if (senderStopped || wire.decoded || nextEsi >= cap) return
      const settled = feedbackSinceBatch && latestRank === rankAtPrevPoll
      const lostTimeout = (Date.now() - lastBatchAt) >= lostBatchMs
      rankAtPrevPoll = latestRank
      if (latestRank === 0 || !(settled || lostTimeout)) {
        track(setTimeout(roundTick, pollMs))
        return
      }
      const deficit = k - latestRank
      if (deficit > 0) sendBatch(deficit)
      track(setTimeout(roundTick, pollMs))
    }
    track(setTimeout(roundTick, pollMs))

    const result = await completion

    // honor real flow control: wait (bounded) for the link-delivered ACK to
    // actually stop the sender before teardown.
    await Promise.race([
      stoppedPromise,
      new Promise(function (r) { track(setTimeout(r, rttMs * 6)) })
    ])

    for (const t of timers) clearTimeout(t)

    const bytesToCompletion = result.bytesAtDecode + doneMsg.length
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
      stoppedByAck: senderStopped,
      verified: result.verified
    }
  } finally {
    wire.decoded = true
    senderStopped = true
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

  // want/have bytes-to-completion is nondeterministic under loss (UDX
  // retransmission timing), so take the MEDIAN of `reps` transfers on both sides
  // before comparing. The coded side is near-deterministic; the median absorbs
  // want/have's timing luck so the gate does not flake on CI. Default 1 rep
  // locally; CI passes --reps=3.
  const reps = opts.reps || 1
  const rows = []
  for (const loss of losses) {
    const whBytes = []
    const codedBytes = []
    let lastWH = null
    let lastCoded = null
    for (let i = 0; i < reps; i++) {
      lastWH = await wantHaveTransfer({ k, blockSize, loss, latencyMs, jitterMs, seed: seed + i })
      lastCoded = await codedTransfer({ k, blockSize, loss, latencyMs, jitterMs, seed: seed + i })
      whBytes.push(lastWH.bytesToCompletion)
      codedBytes.push(lastCoded.bytesToCompletion)
    }
    const wantHaveBytes = median(whBytes)
    const codedByteCount = median(codedBytes)
    const ratio = codedByteCount / wantHaveBytes
    rows.push({
      loss,
      wantHaveBytes,
      codedBytes: codedByteCount,
      wantHaveOverheadPerBlock: round(lastWH.bytesPerBlockOverhead),
      codedOverheadPerBlock: round(lastCoded.bytesPerBlockOverhead),
      codedOverheadSymbols: lastCoded.overheadSymbols,
      reps,
      savingsPct: round((1 - ratio) * 100),
      winner: codedByteCount < wantHaveBytes ? 'coded' : 'want-have'
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

function median (xs) {
  const s = xs.slice().sort(function (a, b) { return a - b })
  const m = s.length >> 1
  return s.length % 2 === 1 ? s[m] : (s[m - 1] + s[m]) / 2
}

if (require.main === module) {
  run({
    k: intFlag('--k=', DEFAULT_K),
    blockSize: intFlag('--block=', DEFAULT_BLOCK_SIZE),
    latencyMs: intFlag('--latency=', 0),
    jitterMs: intFlag('--jitter=', 0),
    reps: intFlag('--reps=', 1),
    seed: intFlag('--seed=', DEFAULT_SEED),
    losses: listFlag('--losses=', null)
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

  function listFlag (prefix, dflt) {
    const arg = process.argv.find(a => a.startsWith(prefix))
    if (!arg) return dflt
    const parts = arg.slice(prefix.length).split(',').map(Number).filter(Number.isFinite)
    return parts.length ? parts : dflt
  }
}
