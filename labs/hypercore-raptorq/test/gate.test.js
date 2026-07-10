const test = require('brittle')

// The Chapter 10 gate under a REALISTIC RTT (latency 20ms, jitter 5ms), the
// regime where the old blind-flood sender lost: without flow control it put a
// full RTT of in-flight symbols on the wire and overshot ~25 symbols/round.
// With ACK-paced rounds the decode-instant overshoot is bounded to ~1 RTT of
// the residual deficit, so coded beats want/have bytes-to-completion at every
// loss >= 5% and is no worse on a clean link.
//
// This drives real hypercore+UDX replication for the want/have side, so it is
// heavier than the unit tests but still completes in a few seconds; the gate
// tears down every socket/link/tmp dir in its own finally blocks.
const gate = require('../../../harness/bench/raptorq-gate')

test('latency-regime gate: coded beats want/have at >=5% loss under 20ms RTT', async function (t) {
  const out = await gate.run({ latencyMs: 20, jitterMs: 5 })

  for (const row of out.rows) {
    t.comment('loss=' + row.loss + ' coded=' + row.codedBytes + ' wantHave=' + row.wantHaveBytes +
      ' overshootSymbols=' + row.codedOverheadSymbols + ' winner=' + row.winner)
  }

  const clean = out.rows.find(r => r.loss === 0)
  t.ok(clean.codedBytes <= clean.wantHaveBytes * 1.02, 'no worse than want/have on a clean link')

  for (const row of out.rows.filter(r => r.loss >= 0.05)) {
    t.ok(row.codedBytes < row.wantHaveBytes,
      'coded beats want/have at loss=' + row.loss + ' (' + row.codedBytes + ' < ' + row.wantHaveBytes + ')')
    // flow control: decode-instant overshoot is bounded (~1 RTT of deficit),
    // not the old ~25+ symbol/round flood. Comfortable ceiling of k/2.
    t.ok(row.codedOverheadSymbols <= 32,
      'overshoot bounded at loss=' + row.loss + ' (' + row.codedOverheadSymbols + ' symbols)')
  }

  t.ok(out.beatsAtLoss, 'gate: coded beats want/have at every loss >= 5%')
  t.ok(out.noWorseAtZero, 'gate: no worse at 0% loss')
  t.ok(out.passes, 'gate PASSES under realistic RTT')
})
