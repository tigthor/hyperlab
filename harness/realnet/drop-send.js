#!/usr/bin/env node
// realnet/drop-send — instrumented filedrop sender on the real public DHT.
//
//   node drop-send.js <file> [--passphrase <p>] [--relay <hex>] [--relay-addr host:port]
//                            [--force-relay] [--timeout <ms>]
//
// Emits one JSON line on stdout when the transfer settles:
//   { role, ok, passphrase, bootstrapMs, listenMs, connectWaitMs, transferMs,
//     bytes, throughputBps, path, remoteHost, remotePort, error? }
// Human progress goes to stderr. --force-relay disables holepunching so the
// transfer MUST flow through the relay (proves the fallback really carries data).

const b4a = require('b4a')
const DHT = require('hyperdht')
const filedrop = require('filedrop')
const { classifyPath, parseAddrList, parseArgs, emit, note, withTimeout } = require('./lib')

async function main () {
  const args = parseArgs(process.argv.slice(2), { 'force-relay': 'bool' })
  const file = args._[0]
  if (!file) throw new Error('usage: drop-send.js <file> [--relay <hex>] [--force-relay]')
  const timeoutMs = +(args.timeout || 300000)
  const relayThrough = args.relay ? b4a.from(args.relay, 'hex') : null
  const relayAddr = parseAddrList(args['relay-addr'])

  const result = { role: 'send', ok: false, file }
  const t0 = Date.now()

  const forceRelay = !!args['force-relay']
  if (forceRelay && !relayThrough) throw new Error('--force-relay needs --relay')

  const node = new DHT()
  await node.fullyBootstrapped()
  result.bootstrapMs = Date.now() - t0
  note('[send] bootstrapped in ' + result.bootstrapMs + ' ms (' + node.host + ':' + node.port +
    ' firewalled=' + node.firewalled + ' randomized=' + node.randomized + ')')

  let sock = null
  let tConnected = 0
  let tFirstChunk = 0

  const sender = filedrop.createSender(file, {
    node,
    passphrase: args.passphrase,
    relayThrough,
    // relay-only mode: no punching, no LAN candidates — bytes MUST cross the relay
    holepunch: forceRelay ? false : undefined,
    shareLocalAddress: forceRelay ? false : undefined,
    onConnection (s) {
      sock = s
      tConnected = Date.now()
      note('[send] peer connected after ' + (tConnected - tListen) + ' ms wait')
    },
    onProgress ({ chunk, totalChunks }) {
      if (!tFirstChunk) tFirstChunk = Date.now()
      if (chunk === totalChunks) note('[send] all ' + totalChunks + ' chunks written')
    }
  })

  result.passphrase = sender.passphrase
  const tL0 = Date.now()
  await sender.listen()
  const tListen = Date.now()
  result.listenMs = tListen - tL0
  note('[send] listening; passphrase: ' + sender.passphrase)
  // parseable marker for orchestrators
  emit({ role: 'send', event: 'listening', passphrase: sender.passphrase, size: sender.size })

  try {
    const done = await withTimeout(sender.finished, timeoutMs, 'waiting for receiver')
    const tEnd = Date.now()
    result.ok = true
    result.bytes = done.bytes
    result.connectWaitMs = tConnected ? tConnected - tListen : null
    result.transferMs = tConnected ? tEnd - tConnected : null
    result.throughputBps = result.transferMs ? Math.round(done.bytes / (result.transferMs / 1000)) : null
    result.receiptVerified = true
    Object.assign(result, sock ? classifyPath(sock, relayAddr) : {})
  } catch (err) {
    result.error = err.message
  }

  emit(result)
  await sender.close().catch(() => {})
  await node.destroy().catch(() => {})
  process.exit(result.ok ? 0 : 1)
}

main().catch(err => {
  emit({ role: 'send', ok: false, error: err.message })
  process.exit(1)
})
