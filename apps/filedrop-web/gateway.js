#!/usr/bin/env node
// filedrop-web gateway — one process that gives browsers the DHT.
//
// - HTTP: serves the static web app (web/dist) — the landing page + app
// - WS /relay: each websocket becomes a @hyperswarm/dht-relay session backed
//   by this process's real hyperdht node
//
// Trust model: the gateway relays DHT packets and (non-custodially) proxies
// the noise transport; the browser keeps its own keypairs. Above that, the
// filedrop protocol's CPace gate + per-chunk BLAKE2b verification run inside
// the browser, so a malicious gateway without the passphrase cannot read or
// forge file bytes — it can only refuse service. Run your own gateway with
//   npx filedrop-web [--port 8080] [--bootstrap host:port,...]

const http = require('http')
const path = require('path')
const fs = require('fs')
const DHT = require('hyperdht')
const { WebSocketServer } = require('ws')
const { relay } = require('@hyperswarm/dht-relay')
const Stream = require('@hyperswarm/dht-relay/ws')

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2'
}

function createGateway (opts = {}) {
  const root = opts.root || path.join(__dirname, 'web', 'dist')
  const dht = opts.dht || new DHT({ bootstrap: opts.bootstrap })

  const server = http.createServer((req, res) => {
    let url = req.url.split('?')[0]
    if (url === '/') url = '/index.html'
    if (url === '/app') url = '/app.html'
    const file = path.normalize(path.join(root, url))
    if (!file.startsWith(root) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.writeHead(404, { 'content-type': 'text/plain' })
      res.end('not found')
      return
    }
    res.writeHead(200, {
      'content-type': MIME[path.extname(file)] || 'application/octet-stream',
      'cache-control': 'no-cache'
    })
    fs.createReadStream(file).pipe(res)
  })

  const wss = new WebSocketServer({ server, path: '/relay' })
  wss.on('connection', (socket) => {
    relay(dht, new Stream(false, socket))
  })

  return {
    dht,
    server,
    wss,
    async listen (port = 8080, host) {
      await dht.ready()
      await new Promise((resolve, reject) => {
        server.once('error', reject)
        server.listen(port, host, () => resolve())
      })
      return server.address()
    },
    async close () {
      wss.close()
      await new Promise((resolve) => server.close(() => resolve()))
      if (!opts.dht) await dht.destroy() // only destroy a node we created
    }
  }
}

module.exports = createGateway

if (require.main === module) {
  const args = process.argv.slice(2)
  let port = 8080
  let bootstrap
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port') port = +args[++i]
    if (args[i] === '--bootstrap') bootstrap = args[++i].split(',').map(s => ({ host: s.split(':')[0], port: +s.split(':')[1] }))
  }
  const gw = createGateway({ bootstrap })
  gw.listen(port).then(async (addr) => {
    console.log('filedrop-web gateway listening on http://localhost:' + addr.port)
    console.log('  ws relay:  ws://localhost:' + addr.port + '/relay')
    console.log('  dht node:  ' + gw.dht.host + ':' + gw.dht.port + ' (firewalled=' + gw.dht.firewalled + ')')
  }).catch((err) => {
    console.error('gateway failed: ' + err.message)
    process.exit(1)
  })
}
