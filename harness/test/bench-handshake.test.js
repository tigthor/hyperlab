const test = require('brittle')

const { run } = require('../bench/handshake')

test('bench/handshake quick run reports sane metrics', async function (t) {
  const metrics = await run({ quick: true })

  t.is(metrics.name, 'handshake', 'has name field')
  t.is(metrics.handshakes, 3, 'quick run does 3 handshakes')

  for (const key of ['latencyMsMedian', 'latencyMsP95', 'latencyMsMin']) {
    t.is(typeof metrics[key], 'number', key + ' is a number')
    t.ok(Number.isFinite(metrics[key]), key + ' is finite')
    t.ok(metrics[key] > 0, key + ' is > 0')
  }

  t.ok(metrics.latencyMsMin <= metrics.latencyMsMedian, 'min <= median')
  t.ok(metrics.latencyMsMedian <= metrics.latencyMsP95, 'median <= p95')

  t.is(typeof metrics.bytesNote, 'string', 'bytesNote explains the byte metrics')

  if (typeof metrics.setupBytesTotalMedian === 'number') {
    for (const key of ['setupBytesToClientMedian', 'setupBytesToServerMedian', 'setupBytesTotalMedian']) {
      t.ok(Number.isFinite(metrics[key]), key + ' is finite')
      t.ok(metrics[key] > 0, key + ' is > 0')
    }
  }

  if (typeof metrics.firstMessageBytes === 'number') {
    t.ok(Number.isFinite(metrics.firstMessageBytes), 'firstMessageBytes is finite')
    t.ok(metrics.firstMessageBytes > 0, 'firstMessageBytes is > 0')
  }

  for (const value of Object.values(metrics)) {
    const type = typeof value
    t.ok(type === 'number' || type === 'string', 'metrics object is flat (numbers/strings only)')
  }
})
