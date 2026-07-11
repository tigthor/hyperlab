// realnet shared helpers — path classification + JSON reporting.

const b4a = require('b4a')
const bogon = require('bogon')

// Classify how an open NoiseSecretStream is actually flowing right now.
// UDX streams can change remote mid-life (relay -> direct upgrade), so callers
// should sample this after the work is done, not just at open.
//
// relayAddrs is an optional array of `{ host, port }` for the blind-relay
// node (external + local socket addresses — on a shared LAN peers reach the
// relay via its LAN address). An exact match is reported as 'relayed'.
// Otherwise a private/bogon remote means the peers found each other via
// shared-LAN candidates ('direct-lan'), and a public remote is a real
// across-the-internet path ('direct-wan').
function classifyPath (sock, relayAddrs) {
  const raw = sock.rawStream
  if (!raw) return { path: 'unknown', remoteHost: null, remotePort: 0 }
  const remoteHost = raw.remoteHost
  const remotePort = raw.remotePort
  let path
  if ((relayAddrs || []).some(a => a && a.host === remoteHost && a.port === remotePort)) {
    path = 'relayed'
  } else if (!remoteHost) {
    path = 'unknown'
  } else {
    path = bogon(remoteHost) ? 'direct-lan' : 'direct-wan'
  }
  return { path, remoteHost, remotePort }
}

// "h1:p1,h2:p2" -> [{host, port}]
function parseAddrList (s) {
  if (!s) return []
  return s.split(',').filter(Boolean).map(part => {
    const i = part.lastIndexOf(':')
    return { host: part.slice(0, i), port: +part.slice(i + 1) }
  })
}

function parseArgs (argv, flags = {}) {
  const out = { _: [] }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      const name = a.slice(2)
      if (flags[name] === 'bool') out[name] = true
      else out[name] = argv[++i]
    } else {
      out._.push(a)
    }
  }
  return out
}

function emit (obj) {
  process.stdout.write(JSON.stringify(obj) + '\n')
}

function note (msg) {
  process.stderr.write(msg + '\n')
}

function hexKey (k) {
  return k ? b4a.toString(k, 'hex') : null
}

function withTimeout (promise, ms, label) {
  let timer
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error('timeout after ' + ms + ' ms: ' + label)), ms)
  })
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer))
}

module.exports = { classifyPath, parseAddrList, parseArgs, emit, note, hexKey, withTimeout }
