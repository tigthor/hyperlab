#!/usr/bin/env node
// realnet/drop-recv — instrumented filedrop receiver on the real public DHT.
//
//   node drop-recv.js <passphrase> <outdir> [--relay <hex>] [--relay-addr host:port]
//                     [--force-relay] [--timeout <ms>]
//
// Emits one JSON line on stdout when the transfer settles:
//   { role, ok, bootstrapMs, connectMs, transferMs, bytes, throughputBps,
//     path, remoteHost, remotePort, error? }

const b4a = require('b4a')
const DHT = require('hyperdht')
const filedrop = require('filedrop')
const { classifyPath, parseAddrList, parseArgs, emit, note, withTimeout } = require('./lib')

async function main () {
  const args = parseArgs(process.argv.slice(2), { 'force-relay': 'bool' })
  const [passphrase, outdir] = args._
  if (!passphrase || !outdir) throw new Error('usage: drop-recv.js <passphrase> <outdir> [--relay <hex>]')
  const timeoutMs = +(args.timeout || 300000)
  const relayThrough = args.relay ? b4a.from(args.relay, 'hex') : null
  const relayAddr = parseAddrList(args['relay-addr'])

  const result = { role: 'recv', ok: false }
  const t0 = Date.now()

  const forceRelay = !!args['force-relay']
  if (forceRelay && !relayThrough) throw new Error('--force-relay needs --relay')

  const node = new DHT()
  await node.fullyBootstrapped()
  result.bootstrapMs = Date.now() - t0
  note('[recv] bootstrapped in ' + result.bootstrapMs + ' ms (' + node.host + ':' + node.port +
    ' firewalled=' + node.firewalled + ' randomized=' + node.randomized + ')')

  let sock = null
  let tOpen = 0
  const tC0 = Date.now()

  try {
    const done = await withTimeout(filedrop.receive(passphrase, outdir, {
      node,
      relayThrough,
      holepunch: forceRelay ? false : undefined,
      localConnection: forceRelay ? false : undefined,
      onConnection (s) {
        sock = s
        s.once('open', () => {
          tOpen = Date.now()
          note('[recv] connected in ' + (tOpen - tC0) + ' ms (' + s.rawStream.remoteHost + ':' + s.rawStream.remotePort + ')')
        })
      },
      onProgress ({ chunk, totalChunks }) {
        if (chunk === totalChunks) note('[recv] all ' + totalChunks + ' chunks verified')
      }
    }), timeoutMs, 'receive')

    const tEnd = Date.now()
    result.ok = true
    result.bytes = done.bytes
    result.path_file = done.path
    result.connectMs = tOpen ? tOpen - tC0 : null
    result.transferMs = tOpen ? tEnd - tOpen : null
    result.throughputBps = result.transferMs ? Math.round(done.bytes / (result.transferMs / 1000)) : null
    Object.assign(result, sock ? classifyPath(sock, relayAddr) : {})
  } catch (err) {
    result.error = err.message
    if (sock) Object.assign(result, classifyPath(sock, relayAddr))
  }

  emit(result)
  await node.destroy().catch(() => {})
  process.exit(result.ok ? 0 : 1)
}

main().catch(err => {
  emit({ role: 'recv', ok: false, error: err.message })
  process.exit(1)
})
