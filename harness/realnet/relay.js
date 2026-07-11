#!/usr/bin/env node
// realnet/relay — a blind-relay node on the real public DHT.
//
// This is the missing piece for the symmetric-NAT case: two peers whose NATs
// both randomize ports cannot holepunch, and stock hyperdht simply fails the
// connection. Any machine that runs this relay (ideally one with an open or
// full-cone NAT — a VPS) lets such peers fall back to TURN-style relaying:
// clients pass `relayThrough: <this key>` and hyperdht races direct vs relay,
// upgrading to direct when the punch succeeds.
//
//   node harness/realnet/relay.js [--seed <32-byte hex>] [--json]
//
// Prints the relay public key (give it to filedrop/sync via --relay /
// FILEDROP_RELAY) and serves until killed.

const DHT = require('hyperdht')
const RelayServer = require('blind-relay').Server
const b4a = require('b4a')
const { parseArgs, emit, note } = require('./lib')

async function main () {
  const args = parseArgs(process.argv.slice(2), { json: 'bool' })
  const seed = args.seed ? b4a.from(args.seed, 'hex') : null
  if (seed && seed.byteLength !== 32) throw new Error('--seed must be 32 bytes of hex')

  const node = new DHT()
  await node.fullyBootstrapped()

  const relay = new RelayServer({
    createStream (opts) {
      return node.createRawStream({ ...opts, framed: true })
    }
  })

  const keyPair = DHT.keyPair(seed)
  const server = node.createServer(function (socket) {
    const session = relay.accept(socket, { id: socket.remotePublicKey })
    session.on('error', () => {})
  })
  await server.listen(keyPair)

  // every address a peer might see this relay's traffic from: external
  // (host:port via the DHT) plus each local interface on both bound sockets
  const serverPort = node.io.serverSocket.address().port
  const clientPort = node.io.clientSocket.address().port
  const addrs = [{ host: node.host, port: node.port }]
  for (const iface of Object.values(require('os').networkInterfaces()).flat()) {
    if (iface.family === 'IPv4' && !iface.internal) {
      addrs.push({ host: iface.address, port: serverPort })
      addrs.push({ host: iface.address, port: clientPort })
    }
  }

  const info = {
    role: 'relay',
    publicKey: b4a.toString(keyPair.publicKey, 'hex'),
    host: node.host,
    port: node.port,
    addrList: addrs.map(a => a.host + ':' + a.port).join(','),
    firewalled: node.firewalled,
    randomized: node.randomized
  }

  if (args.json) emit(info)
  else {
    note('blind-relay up on the public DHT')
    note('  relay key:  ' + info.publicKey)
    note('  address:    ' + info.host + ':' + info.port + (info.firewalled ? '  (firewalled — fine for relaying, both sides dial out)' : ''))
    note('  use:        filedrop send/receive --relay ' + info.publicKey)
  }

  setInterval(() => {
    const s = relay.stats
    note('[relay] sessions active=' + s.sessions.active + ' pairings matched=' + s.pairings.matched + ' streams active=' + s.streams.active)
  }, 30000).unref()

  // serve until killed
  await new Promise(() => {})
}

main().catch(err => {
  console.error('relay error: ' + err.message)
  process.exit(1)
})
