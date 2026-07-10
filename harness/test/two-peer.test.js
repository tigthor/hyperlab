const test = require('brittle')
const b4a = require('b4a')
const twoPeer = require('../two-peer')
const createTestnet = require('../testnet')

test('two-peer sockets are open and exchange data both ways', async function (t) {
  const rig = await twoPeer()
  t.teardown(rig.destroy)

  t.ok(rig.socketA, 'has a server-side socket')
  t.ok(rig.socketB, 'has a client socket')
  t.is(await rig.socketA.opened, true, 'server-side socket opened')
  t.is(await rig.socketB.opened, true, 'client socket opened')
  t.alike(
    rig.socketB.remotePublicKey,
    rig.server.publicKey,
    'client is connected to the server key'
  )

  const fromB = new Promise((resolve) => rig.socketA.once('data', resolve))
  rig.socketB.write(b4a.from('hello from b'))
  t.alike(await fromB, b4a.from('hello from b'), 'b -> a data arrived')

  const fromA = new Promise((resolve) => rig.socketB.once('data', resolve))
  rig.socketA.write(b4a.from('hello from a'))
  t.alike(await fromA, b4a.from('hello from a'), 'a -> b data arrived')
})

test('two-peer destroy tears everything down', async function (t) {
  const rig = await twoPeer()

  await rig.destroy()

  t.ok(rig.socketA.destroyed, 'server-side socket destroyed')
  t.ok(rig.socketB.destroyed, 'client socket destroyed')
  t.ok(rig.nodeA.destroyed, 'node A destroyed')
  t.ok(rig.nodeB.destroyed, 'node B destroyed')
  t.ok(
    rig.testnet.nodes.every((node) => node.destroyed),
    'testnet destroyed'
  )

  await rig.destroy() // idempotent
  t.pass('destroy is idempotent')
})

test('two-peer reuses a provided testnet and leaves it alive', async function (t) {
  const testnet = await createTestnet(3, { teardown: t })

  const rig = await twoPeer({ testnet })

  t.is(rig.testnet, testnet, 'reused the provided testnet')

  const fromB = new Promise((resolve) => rig.socketA.once('data', resolve))
  rig.socketB.write(b4a.from('ping'))
  t.alike(await fromB, b4a.from('ping'), 'data flows on the reused testnet')

  await rig.destroy()

  t.ok(rig.nodeA.destroyed, 'node A destroyed')
  t.ok(rig.nodeB.destroyed, 'node B destroyed')
  t.ok(
    testnet.nodes.slice(0, 3).every((node) => !node.destroyed),
    'bootstrap testnet nodes still alive after destroy'
  )
})
