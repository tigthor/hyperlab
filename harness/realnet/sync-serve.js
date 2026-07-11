#!/usr/bin/env node
// realnet/sync-serve — side A of a SyncDB pair on the real public DHT.
//
//   node sync-serve.js [--keys <n=50>] [--relay <hex>] [--timeout <ms>] [--storage <dir>]
//
// Creates a fresh SyncDB, seeds it with n keys, prints the db key (share it
// with side B), then grants write access to any 64-hex writer key that
// arrives on stdin (sync-join prints exactly that). Succeeds when side B's
// ack write replicates back — proving discovery, replication and multi-writer
// both ways over the real DHT. Emits progress markers and one final JSON line.

const os = require('os')
const path = require('path')
const fs = require('fs')
const b4a = require('b4a')
const Hyperswarm = require('hyperswarm')
const SyncDB = require('p2p-sync')
const { parseArgs, emit, note, withTimeout } = require('./lib')

async function main () {
  const args = parseArgs(process.argv.slice(2), {})
  const nKeys = +(args.keys || 50)
  const timeoutMs = +(args.timeout || 600000)
  const relayThrough = args.relay ? b4a.from(args.relay, 'hex') : null
  const storage = args.storage || fs.mkdtempSync(path.join(os.tmpdir(), 'sync-serve-'))

  const result = { role: 'serve', ok: false }
  const t0 = Date.now()

  const swarm = new Hyperswarm({ relayThrough })
  const conns = []
  swarm.on('connection', (conn, info) => {
    conns.push(conn)
    note('[serve] peer connected (' + conn.rawStream.remoteHost + ':' + conn.rawStream.remotePort + ') after ' + (Date.now() - t0) + ' ms')
  })

  const db = new SyncDB({ storage, swarm })
  await db.ready()

  for (let i = 0; i < nKeys; i++) {
    await db.set('seed/' + i, { i, payload: 'x'.repeat(200) })
  }
  result.seeded = nKeys

  const key = b4a.toString(db.key, 'hex')
  note('[serve] db key: ' + key)
  note('[serve] on the other machine run:  node harness/realnet/sync-join.js ' + key + (args.relay ? ' --relay ' + args.relay : ''))
  note('[serve] paste the writer key it prints here (stdin) to grant write access')
  emit({ role: 'serve', event: 'ready', key, storage })

  // grant writers from stdin (paste) or from a polled --grant-file (orchestration)
  const granted = new Set()
  const grant = (l) => {
    const key = l.trim()
    if (!/^[0-9a-f]{64}$/i.test(key) || granted.has(key)) return
    granted.add(key)
    note('[serve] granting writer ' + key.slice(0, 16) + '...')
    db.addWriter(key).catch(err => note('[serve] addWriter failed: ' + err.message))
  }
  process.stdin.setEncoding('utf8')
  process.stdin.on('data', (line) => line.split('\n').forEach(grant))
  if (args['grant-file']) {
    const iv = setInterval(() => {
      try { fs.readFileSync(args['grant-file'], 'utf8').split('\n').forEach(grant) } catch {}
    }, 500)
    iv.unref()
  }

  // succeed when any peer/*/ack key shows up (side B wrote back)
  try {
    await withTimeout(new Promise((resolve) => {
      const check = async () => {
        for await (const node of db.createReadStream({ gte: 'peer/', lt: 'peer0' })) {
          if (node.value && node.value.value && node.value.value.status === 'done') return resolve(node.key)
        }
      }
      db.on('update', () => { check().catch(() => {}) })
      check().catch(() => {})
    }), timeoutMs, 'waiting for peer ack write')

    result.ok = true
    result.ackAfterMs = Date.now() - t0
    result.connections = conns.length
    result.remotes = conns.map(c => c.rawStream.remoteHost + ':' + c.rawStream.remotePort)
  } catch (err) {
    result.error = err.message
  }

  emit(result)
  await db.close().catch(() => {})
  process.exit(result.ok ? 0 : 1)
}

main().catch(err => {
  emit({ role: 'serve', ok: false, error: err.message })
  process.exit(1)
})
