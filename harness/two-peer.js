const DHT = require('hyperdht')
const createTestnet = require('./testnet')

// Boots (or reuses opts.testnet) a small testnet, stands up a server on
// node A, connects from node B and waits for both NoiseSecretStreams to
// open. Returns { testnet, nodeA, nodeB, server, socketA, socketB, destroy }
// where socketA is the server-side accepted socket and socketB the client
// socket. destroy() tears everything down - the testnet only if we made it.
module.exports = async function twoPeer (opts = {}) {
  const ownsTestnet = !opts.testnet
  const testnet = opts.testnet || (await createTestnet(opts.size || 3, opts))

  const nodeA = testnet.createNode()
  const nodeB = testnet.createNode()

  let server = null
  let socketA = null
  let socketB = null
  let destroyed = false

  try {
    let onconnection = null
    const accepted = new Promise((resolve) => {
      onconnection = resolve
    })

    server = nodeA.createServer(onconnection)
    await server.listen(DHT.keyPair())

    socketB = nodeB.connect(server.publicKey)

    if ((await socketB.opened) === false) {
      throw new Error('two-peer: client socket failed to open')
    }

    socketA = await accepted

    if ((await socketA.opened) === false) {
      throw new Error('two-peer: server socket failed to open')
    }
  } catch (err) {
    await destroy()
    throw err
  }

  return { testnet, nodeA, nodeB, server, socketA, socketB, destroy }

  async function destroy () {
    if (destroyed) return
    destroyed = true

    await Promise.all([closeSocket(socketA), closeSocket(socketB)])
    if (server) await server.close()
    await nodeB.destroy()
    await nodeA.destroy()
    if (ownsTestnet) await testnet.destroy()
  }
}

function closeSocket (socket) {
  if (!socket || socket.destroyed) return Promise.resolve()

  return new Promise((resolve) => {
    socket.once('close', resolve)
    socket.destroy()
  })
}
