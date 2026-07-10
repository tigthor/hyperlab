const test = require('brittle')

const { run } = require('../bench/append')

test('bench/append quick run reports sane metrics', async function (t) {
  const metrics = await run({ quick: true })

  t.is(metrics.name, 'append', 'has name field')
  t.is(metrics.blockSize, 1024, 'default block size')
  t.is(metrics.totalBlocks, 500, 'quick run uses 500 blocks')
  t.is(metrics.batchSize, 64, 'default batch size')

  for (const key of ['singleAppendsPerSec', 'batchedAppendsPerSec', 'singleMBPerSec', 'batchedMBPerSec']) {
    t.is(typeof metrics[key], 'number', key + ' is a number')
    t.ok(Number.isFinite(metrics[key]), key + ' is finite')
    t.ok(metrics[key] > 0, key + ' is > 0')
  }

  for (const value of Object.values(metrics)) {
    const type = typeof value
    t.ok(type === 'number' || type === 'string', 'metrics object is flat (numbers/strings only)')
  }
})
