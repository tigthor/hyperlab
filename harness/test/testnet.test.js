const test = require('brittle')
const createTestnet = require('../testnet')

test('testnet boots N nodes and destroys cleanly', async function (t) {
  const testnet = await createTestnet(4)

  t.is(testnet.nodes.length, 4, 'booted 4 nodes')
  t.is(testnet.bootstrap.length, 1, 'has a bootstrap node')

  for (const node of testnet.nodes) {
    t.ok(node.bootstrapped, 'node is bootstrapped')
  }

  await testnet.destroy()

  for (const node of testnet.nodes) {
    t.ok(node.destroyed, 'node is destroyed')
  }
})

test('testnet accepts a teardown function (upstream behaviour)', async function (t) {
  let testnet = null

  await t.test('boot with fn teardown', async function (sub) {
    testnet = await createTestnet(2, { teardown: sub.teardown.bind(sub) })
    sub.is(testnet.nodes.length, 2, 'booted 2 nodes')
  })

  t.ok(
    testnet.nodes.every((node) => node.destroyed),
    'teardown fn destroyed the testnet'
  )
})

test('testnet accepts a brittle test object as opts.teardown', async function (t) {
  let testnet = null

  await t.test('boot with test object teardown', async function (sub) {
    testnet = await createTestnet(2, { teardown: sub })
    sub.is(testnet.nodes.length, 2, 'booted 2 nodes')
    sub.ok(
      testnet.nodes.every((node) => !node.destroyed),
      'nodes alive inside the test'
    )
  })

  t.ok(
    testnet.nodes.every((node) => node.destroyed),
    'test object teardown destroyed the testnet'
  )
})

test('createNode joins the testnet', async function (t) {
  const testnet = await createTestnet(3, { teardown: t })

  const node = testnet.createNode()
  await node.fullyBootstrapped()

  t.is(testnet.nodes.length, 4, 'created node was tracked by the testnet')
  t.ok(node.ephemeral, 'created node is ephemeral')
})
