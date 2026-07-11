#!/usr/bin/env node
// realnet/trial — repeated two-process trials over the REAL public DHT.
//
//   node trial.js drop --n 3 --size 4194304 [--mode direct|relay|force-relay] [--relay <hex> --relay-addr <h:p>]
//   node trial.js sync --n 2 --keys 50 [--relay <hex>]
//
// Spawns sender/receiver (or serve/join) as separate OS processes, each with
// its own real DHT node, and aggregates success rate, path taken (direct vs
// relayed), connect time and throughput. In force-relay mode a local
// blind-relay is spawned and holepunching is disabled in both children, so
// bytes MUST flow through the relay — proving the symmetric-NAT fallback.
//
// Results land in harness/realnet/results/ as JSON, one file per run.

const { spawn } = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const { parseArgs, note } = require('./lib')

const HERE = __dirname

function spawnJson (script, argv, opts = {}) {
  const child = spawn(process.execPath, [path.join(HERE, script), ...argv], {
    stdio: ['pipe', 'pipe', 'pipe'],
    ...opts
  })
  const events = []
  const finals = []
  let buffered = ''
  const waiters = []
  child.stdout.on('data', (d) => {
    buffered += d.toString()
    let idx
    while ((idx = buffered.indexOf('\n')) !== -1) {
      const line = buffered.slice(0, idx).trim()
      buffered = buffered.slice(idx + 1)
      if (!line) continue
      try {
        const obj = JSON.parse(line)
        if (obj.event) events.push(obj)
        else finals.push(obj)
        for (const w of waiters.splice(0)) w(obj)
      } catch {}
    }
  })
  child.stderr.on('data', (d) => {
    for (const l of d.toString().split('\n')) if (l.trim()) note('    ' + l.trim())
  })
  const exit = new Promise((resolve) => child.on('exit', resolve))
  return {
    child,
    events,
    finals,
    exit,
    nextJson () {
      return new Promise((resolve) => waiters.push(resolve))
    },
    async waitFor (pred, ms, label) {
      const t0 = Date.now()
      while (Date.now() - t0 < ms) {
        const hit = events.find(pred) || finals.find(pred)
        if (hit) return hit
        await this.nextJsonOrTick()
      }
      throw new Error('timeout waiting for ' + label)
    },
    nextJsonOrTick () {
      return Promise.race([this.nextJson(), new Promise(r => setTimeout(r, 250))])
    }
  }
}

function stats (xs) {
  const v = xs.filter(x => typeof x === 'number' && isFinite(x)).sort((a, b) => a - b)
  if (!v.length) return null
  return { n: v.length, min: v[0], med: v[Math.floor(v.length / 2)], max: v[v.length - 1] }
}

function fmtBps (n) {
  if (n == null) return '-'
  const u = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s']
  let i = 0
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++ }
  return n.toFixed(1) + ' ' + u[i]
}

async function startRelay () {
  const r = spawnJson('relay.js', ['--json'])
  const info = await r.waitFor(o => o.role === 'relay', 60000, 'relay ready')
  note('  relay up: ' + info.publicKey.slice(0, 16) + '... at ' + info.host + ':' + info.port)
  return { proc: r, info }
}

async function dropTrial (i, size, mode, relayInfo, timeoutMs) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'realnet-drop-'))
  const file = path.join(tmp, 'payload-' + i + '.bin')
  fs.writeFileSync(file, crypto.randomBytes(size))

  const relayArgs = []
  if (relayInfo) {
    relayArgs.push('--relay', relayInfo.publicKey, '--relay-addr', relayInfo.addrList || (relayInfo.host + ':' + relayInfo.port))
  }
  if (mode === 'force-relay') relayArgs.push('--force-relay')

  const send = spawnJson('drop-send.js', [file, '--timeout', String(timeoutMs), ...relayArgs])
  let recv = null
  const trial = { i, size, mode }
  try {
    const listening = await send.waitFor(o => o.event === 'listening', 120000, 'sender listening')
    recv = spawnJson('drop-recv.js', [listening.passphrase, tmp, '--timeout', String(timeoutMs), ...relayArgs])

    await Promise.all([send.exit, recv.exit])
    const s = send.finals.find(o => o.role === 'send' && !o.event)
    const r = recv.finals.find(o => o.role === 'recv' && !o.event)
    trial.send = s || { ok: false, error: 'no sender report' }
    trial.recv = r || { ok: false, error: 'no receiver report' }

    const received = r && r.ok && fs.existsSync(path.join(tmp, path.basename(file)))
    const bytesMatch = received && fs.statSync(path.join(tmp, path.basename(file))).size === size
    // the received file re-verified against the manifest inside filedrop; this
    // is a belt-and-braces orchestrator-side check
    trial.ok = !!(s && s.ok && r && r.ok && bytesMatch)
  } catch (err) {
    trial.ok = false
    trial.error = err.message
    send.child.kill('SIGKILL')
    if (recv) recv.child.kill('SIGKILL')
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
  return trial
}

async function syncTrial (i, keys, relayInfo, timeoutMs) {
  const relayArgs = relayInfo ? ['--relay', relayInfo.publicKey] : []
  const serve = spawnJson('sync-serve.js', ['--keys', String(keys), '--timeout', String(timeoutMs), ...relayArgs])
  let join = null
  const trial = { i, keys }
  try {
    const ready = await serve.waitFor(o => o.event === 'ready', 120000, 'serve ready')
    join = spawnJson('sync-join.js', [ready.key, '--keys', String(keys), '--timeout', String(timeoutMs), ...relayArgs])
    const writer = await join.waitFor(o => o.event === 'writer', 120000, 'join writer key')
    serve.child.stdin.write(writer.writerKey + '\n')

    await Promise.all([serve.exit, join.exit])
    trial.serve = serve.finals.find(o => o.role === 'serve') || { ok: false, error: 'no serve report' }
    trial.join = join.finals.find(o => o.role === 'join') || { ok: false, error: 'no join report' }
    trial.ok = !!(trial.serve.ok && trial.join.ok)
  } catch (err) {
    trial.ok = false
    trial.error = err.message
    serve.child.kill('SIGKILL')
    if (join) join.child.kill('SIGKILL')
  }
  return trial
}

async function main () {
  const kind = process.argv[2]
  const args = parseArgs(process.argv.slice(3), {})
  const n = +(args.n || 3)
  const mode = args.mode || 'direct'
  const timeoutMs = +(args.timeout || 240000)

  if (!['drop', 'sync'].includes(kind)) {
    throw new Error('usage: trial.js <drop|sync> [--n 3] [--size 4194304] [--mode direct|relay|force-relay] [--relay <hex> --relay-addr <h:p>]')
  }

  let relayInfo = null
  let relayProc = null
  if (args.relay) {
    relayInfo = { publicKey: args.relay, host: (args['relay-addr'] || ':').split(':')[0], port: +(args['relay-addr'] || ':0').split(':')[1] }
  } else if (mode === 'relay' || mode === 'force-relay') {
    const r = await startRelay()
    relayInfo = r.info
    relayProc = r.proc
  }

  const trials = []
  for (let i = 0; i < n; i++) {
    note('trial ' + (i + 1) + '/' + n + ' (' + kind + ', ' + mode + ')')
    const t = kind === 'drop'
      ? await dropTrial(i, +(args.size || 4 * 1024 * 1024), mode, relayInfo, timeoutMs)
      : await syncTrial(i, +(args.keys || 50), relayInfo, timeoutMs)
    trials.push(t)
    note('  -> ' + (t.ok ? 'OK' : 'FAIL' + (t.error ? ' (' + t.error + ')' : '')))
  }

  if (relayProc) relayProc.child.kill('SIGKILL')

  const okCount = trials.filter(t => t.ok).length
  const summary = { kind, mode, n, ok: okCount, failed: n - okCount, when: new Date().toISOString() }

  if (kind === 'drop') {
    summary.paths = {}
    for (const t of trials) {
      const p = (t.recv && t.recv.path) || 'unknown'
      summary.paths[p] = (summary.paths[p] || 0) + 1
    }
    summary.connectMs = stats(trials.map(t => t.recv && t.recv.connectMs))
    summary.throughputBps = stats(trials.map(t => t.recv && t.recv.throughputBps))
    summary.bootstrapMs = stats(trials.flatMap(t => [t.send && t.send.bootstrapMs, t.recv && t.recv.bootstrapMs]))
  } else {
    summary.connectMs = stats(trials.map(t => t.join && t.join.connectMs))
    summary.convergeMs = stats(trials.map(t => t.join && t.join.convergeMs))
    summary.roundTripMs = stats(trials.map(t => t.serve && t.serve.ackAfterMs))
  }

  const outDir = path.join(HERE, 'results')
  fs.mkdirSync(outDir, { recursive: true })
  const outFile = path.join(outDir, Date.now() + '-' + kind + '-' + mode + '.json')
  fs.writeFileSync(outFile, JSON.stringify({ summary, trials }, null, 2))

  note('')
  note('== realnet ' + kind + ' (' + mode + ') — ' + okCount + '/' + n + ' ok ==')
  if (kind === 'drop') {
    note('  paths:       ' + JSON.stringify(summary.paths))
    note('  connect ms:  ' + JSON.stringify(summary.connectMs))
    note('  throughput:  ' + (summary.throughputBps ? fmtBps(summary.throughputBps.med) + ' median' : '-'))
  } else {
    note('  connect ms:  ' + JSON.stringify(summary.connectMs))
    note('  converge ms: ' + JSON.stringify(summary.convergeMs))
    note('  full loop:   ' + JSON.stringify(summary.roundTripMs))
  }
  note('  details:     ' + path.relative(process.cwd(), outFile))

  process.exit(okCount === n ? 0 : 1)
}

main().catch(err => {
  console.error('trial error: ' + err.message)
  process.exit(1)
})
