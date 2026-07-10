const test = require('brittle')
const b4a = require('b4a')

const { run, makeBlock, pickBlocks } = require('../bench/replicate')

test('bench/replicate quick run reports sane metrics and blocks verify', async function (t) {
  const downloaded = new Map()

  const metrics = await run({
    quick: true,
    onblock: function (index, block) {
      downloaded.set(index, block)
    }
  })

  t.is(metrics.name, 'replicate', 'has name field')
  t.is(metrics.transport, 'hyperdht-testnet-socket', 'ran over the DHT socket transport')
  t.is(typeof metrics.wireMethod, 'string', 'states how wire bytes were counted')
  t.is(metrics.blockSize, 1024, 'quick run uses 1KiB blocks')
  t.is(metrics.totalBlocks, 100, 'quick run uses 100 blocks')
  t.is(metrics.blocksRequested, 10, 'quick run requests 10% of blocks')
  t.is(metrics.blocksVerified, metrics.blocksRequested, 'every requested block verified')
  t.is(metrics.payloadBytes, metrics.blocksRequested * metrics.blockSize, 'payload bytes match request')

  for (const key of ['wallMs', 'totalBytesWired', 'bytesPerBlockOverhead', 'wireEfficiency']) {
    t.is(typeof metrics[key], 'number', key + ' is a number')
    t.ok(Number.isFinite(metrics[key]), key + ' is finite')
    t.ok(metrics[key] > 0, key + ' is > 0')
  }

  t.ok(metrics.totalBytesWired > metrics.payloadBytes, 'wire bytes exceed raw payload (protocol overhead)')
  t.ok(metrics.wireEfficiency < 1, 'wire efficiency below 1')

  for (const value of Object.values(metrics)) {
    const type = typeof value
    t.ok(type === 'number' || type === 'string', 'metrics object is flat (numbers/strings only)')
  }

  // Independently verify the downloaded blocks against regenerated source
  const expected = pickBlocks(metrics.totalBlocks, metrics.blocksRequested, metrics.seed)

  t.is(downloaded.size, expected.length, 'saw every requested block')

  for (const index of expected) {
    const block = downloaded.get(index)
    t.ok(block, 'downloaded block ' + index)
    t.ok(b4a.equals(block, makeBlock(metrics.seed, index, metrics.blockSize)), 'block ' + index + ' matches source')
  }
})

test('bench/replicate loss mode completes over an impaired link and counts the damage', async function (t) {
  const metrics = await run({ quick: true, fraction: 0.4, loss: 0.15 })

  t.is(metrics.transport, 'udx-lossy-link', 'ran over the impaired udx transport')
  t.is(metrics.wireMethod, 'udx socket bytesTransmitted sum over both peers (includes retransmissions)', 'states the loss-mode wire accounting')
  t.is(metrics.loss, 0.15, 'reports the configured loss')
  t.is(metrics.blocksRequested, 40, 'requested 40% of the quick core')
  t.is(metrics.blocksVerified, metrics.blocksRequested, 'every requested block verified despite loss')
  t.ok(metrics.droppedDatagrams > 0, 'the links actually dropped datagrams (' + metrics.droppedDatagrams + ')')
  t.ok(metrics.retransmits >= 0, 'retransmit counter reported (' + metrics.retransmits + ')')
  t.ok(metrics.totalBytesWired > metrics.payloadBytes, 'wire bytes exceed raw payload')
  t.ok(metrics.wireEfficiency > 0 && metrics.wireEfficiency < 1, 'wire efficiency in (0, 1)')

  for (const value of Object.values(metrics)) {
    const type = typeof value
    t.ok(type === 'number' || type === 'string', 'loss-mode metrics object stays flat')
  }
})

test('bench/replicate block subset is deterministic across runs', function (t) {
  const a = pickBlocks(1000, 100, 0x51ab1e)
  const b = pickBlocks(1000, 100, 0x51ab1e)
  const c = pickBlocks(1000, 100, 0xbeef)

  t.alike(a, b, 'same seed picks the same subset')
  t.not(JSON.stringify(a), JSON.stringify(c), 'different seed picks a different subset')
  t.is(a.length, 100, 'picks the requested count')
})
