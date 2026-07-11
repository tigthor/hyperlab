#!/usr/bin/env node
// realnet/sync-join — side B of a SyncDB pair on the real public DHT.
//
//   node sync-join.js <db-key-hex> [--keys <n=50>] [--relay <hex>] [--timeout <ms>]
//
// Joins the db, measures time-to-first-connection and time-to-convergence
// (all n seed keys readable), prints its writer key (side A pastes it to
// grant write access), then writes an ack and exits once it is writable and
// the ack is appended. Emits one final JSON line on stdout.

const os = require('os')
const path = require('path')
const fs = require('fs')
const b4a = require('b4a')
const Hyperswarm = require('hyperswarm')
const SyncDB = require('p2p-sync')
const { parseArgs, emit, note, withTimeout } = require('./lib')

async function main () {
  const args = parseArgs(process.argv.slice(2), {})
  const keyHex = args._[0]
  if (!keyHex) throw new Error('usage: sync-join.js <db-key-hex>')
  const nKeys = +(args.keys || 50)
  const timeoutMs = +(args.timeout || 600000)
  const relayThrough = args.relay ? b4a.from(args.relay, 'hex') : null
  const storage = args.storage || fs.mkdtempSync(path.join(os.tmpdir(), 'sync-join-'))

  const result = { role: 'join', ok: false }
  const t0 = Date.now()

  const swarm = new Hyperswarm({ relayThrough })
  let tConn = 0
  const remotes = []
  swarm.on('connection', (conn) => {
    if (!tConn) tConn = Date.now()
    remotes.push(conn.rawStream.remoteHost + ':' + conn.rawStream.remotePort)
    note('[join] connected (' + conn.rawStream.remoteHost + ':' + conn.rawStream.remotePort + ') in ' + (tConn - t0) + ' ms')
  })

  const db = new SyncDB({ storage, swarm, key: b4a.from(keyHex, 'hex') })
  await db.ready()

  note('[join] writer key (paste on the serving machine to grant write): ')
  // stdout marker so an orchestrator can pipe it straight into sync-serve stdin
  emit({ role: 'join', event: 'writer', writerKey: db.writerKey })

  try {
    // converge: all seed keys readable
    await withTimeout(new Promise((resolve) => {
      const check = async () => {
        const v = await db.get('seed/' + (nKeys - 1))
        if (v !== null) {
          // spot-check the full range
          let have = 0
          for (let i = 0; i < nKeys; i++) if (await db.get('seed/' + i) !== null) have++
          if (have === nKeys) resolve()
        }
      }
      db.on('update', () => { check().catch(() => {}) })
      const iv = setInterval(() => { check().catch(() => {}) }, 1000)
      iv.unref()
      check().catch(() => {})
    }), timeoutMs, 'convergence')

    result.connectMs = tConn ? tConn - t0 : null
    result.convergeMs = Date.now() - t0
    result.keys = nKeys
    note('[join] converged: ' + nKeys + ' keys in ' + result.convergeMs + ' ms')

    // wait for writability (side A must addWriter our key), then ack
    await withTimeout(new Promise((resolve) => {
      const check = () => { if (db.writable) resolve() }
      db.on('update', check)
      const iv = setInterval(check, 500)
      iv.unref()
      check()
    }), timeoutMs, 'writability grant')

    result.writableMs = Date.now() - t0
    await db.set('peer/' + db.writerKey.slice(0, 16) + '/ack', { status: 'done', at: result.writableMs })
    note('[join] writable in ' + result.writableMs + ' ms; ack written')

    result.ok = true
    result.remotes = remotes
  } catch (err) {
    result.error = err.message
    result.remotes = remotes
  }

  emit(result)
  await db.close().catch(() => {})
  process.exit(result.ok ? 0 : 1)
}

main().catch(err => {
  emit({ role: 'join', ok: false, error: err.message })
  process.exit(1)
})
