const test = require('brittle')
const createTestnet = require('hyperlab-harness/testnet')
const Hyperswarm = require('hyperswarm')
const os = require('os')
const path = require('path')
const fs = require('fs')
const SyncDB = require('..')

function tmpdir () {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'syncdb-'))
}

async function waitFor (label, fn, { timeout = 60000, interval = 50 } = {}) {
  const start = Date.now()
  let last = null
  while (Date.now() - start < timeout) {
    try {
      if (await fn()) return true
    } catch (e) { last = e }
    await new Promise((r) => setTimeout(r, interval))
  }
  throw new Error('waitFor timed out: ' + label + (last ? ' (' + last.message + ')' : ''))
}

// A directly-piped replication link between two SyncDB stores. This is the
// "provided connection" path (no swarm) and lets the test deterministically
// CUT the link (partition) and re-establish it (heal).
function link (a, b) {
  const sa = a.replicate(true)
  const sb = b.replicate(false)
  sa.on('error', () => {})
  sb.on('error', () => {})
  sa.pipe(sb).pipe(sa)
  return {
    cut () {
      return new Promise((resolve) => {
        let n = 0
        const done = () => { if (++n === 2) resolve() }
        sa.on('close', done); sb.on('close', done)
        sa.destroy(); sb.destroy()
      })
    }
  }
}

// Wire a test-owned swarm to a SyncDB and join its topic (real DHT discovery).
async function connectSwarm (db, swarm) {
  swarm.on('connection', (conn) => db.replicate(conn))
  const disc = swarm.join(db.discoveryKey, { server: true, client: true })
  await disc.flushed()
  return disc
}

async function dump (db) {
  const out = {}
  for await (const { key, value } of db.createReadStream()) out[key] = value.value
  return out
}

test('multi-writer union, LWW, partition-heal, late reader', async (t) => {
  t.timeout(180000)
  const testnet = await createTestnet(4, { teardown: t.teardown })

  const dirs = []
  const swarms = []
  const dbs = []
  const track = (d) => { dirs.push(d); return d }
  const mkswarm = () => {
    const s = new Hyperswarm({ bootstrap: testnet.bootstrap })
    swarms.push(s)
    return s
  }

  // Mandatory cleanup — runs even if an assertion/waitFor throws. Closes happen
  // first (with a timeout guard so a stuck close can never hang teardown), THEN
  // scratch dirs are removed so no close can re-write a just-deleted dir.
  const withTimeout = (p, ms) => Promise.race([Promise.resolve(p).catch(() => {}), new Promise((r) => setTimeout(r, ms))])
  t.teardown(async () => {
    for (const db of dbs) await withTimeout(db.close(), 10000)
    for (const s of swarms) await withTimeout(s.destroy(), 10000)
    for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }) } catch {} }
  })

  // --- Peer A (root writer) ---
  const A = new SyncDB({ storage: track(tmpdir()), join: false })
  dbs.push(A)
  await A.ready()

  // --- Peer B bootstraps from A's autobase key ---
  const B = new SyncDB({ storage: track(tmpdir()), key: A.key, join: false })
  dbs.push(B)
  await B.ready()

  t.alike(B.discoveryKey, A.discoveryKey, 'peers share the same discovery topic')

  let ab = link(A, B)

  // === (1) invite flow: A grants B write access, both write, full union ===
  t.ok(A.writable, 'A is writable (root)')
  t.absent(B.writable, 'B is read-only before invite')

  await A.addWriter(B.writerKey)
  await waitFor('B becomes writable', async () => { await B.update(); return B.writable })
  t.ok(B.writable, 'B is writable after invite linearizes')

  await A.set('a', 'from-A')
  await B.set('b', 'from-B')

  await waitFor('union propagates', async () =>
    (await A.get('b')) === 'from-B' && (await B.get('a')) === 'from-A')

  const unionA = await dump(A)
  const unionB = await dump(B)
  t.alike(unionA, { a: 'from-A', b: 'from-B' }, 'A sees the full union')
  t.alike(unionB, { a: 'from-A', b: 'from-B' }, 'B sees the full union')
  t.alike(unionA, unionB, 'union identical across peers')

  // === (2) concurrent write to SAME key -> deterministic LWW ===
  await Promise.all([A.set('k', 'k-from-A'), B.set('k', 'k-from-B')])
  await waitFor('conflict converges', async () => {
    const ka = await A.get('k'); const kb = await B.get('k')
    return ka !== null && kb !== null && ka === kb
  })
  const kA = await A.get('k')
  t.is(kA, await B.get('k'), 'both peers converge to the SAME winner for conflicting key')
  t.ok(kA === 'k-from-A' || kA === 'k-from-B', 'winner is one of the two writes')

  // === (3) partition: cut the link, both write, then heal and converge ===
  // Invariant is AGREEMENT across peers, not a fixed winner: the linearizer
  // deterministically picks a last-writer per key (LWW by causal order), and
  // that winner can be either peer's value — but both peers MUST agree on it.
  await ab.cut()
  await A.set('p', 'A-wrote')
  await B.set('p', 'B-wrote') // same-key conflict during partition
  await A.set('onlyA', 'A-solo')
  await B.set('onlyB', 'B-solo') // distinct keys during partition

  // sanity: while cut, B must NOT see A's write
  t.is(await B.get('p'), 'B-wrote', 'during partition B keeps its own value (no cross-talk)')
  t.is(await A.get('onlyB'), null, 'during partition A does not see B-only key')

  ab = link(A, B) // heal

  await waitFor('partition heals', async () => {
    const pa = await A.get('p'); const pb = await B.get('p')
    return pa !== null && pa === pb && // conflict key agrees
      (await A.get('onlyA')) === 'A-solo' && (await B.get('onlyA')) === 'A-solo' &&
      (await A.get('onlyB')) === 'B-solo' && (await B.get('onlyB')) === 'B-solo'
  })
  const pWinner = await A.get('p')
  t.is(pWinner, await B.get('p'), 'partition-conflict converges to the SAME value on both peers')
  t.ok(pWinner === 'A-wrote' || pWinner === 'B-wrote', 'winner is one of the two partitioned writes')
  t.is(await B.get('onlyA'), 'A-solo', "A's offline-only write reached B after heal")
  t.is(await A.get('onlyB'), 'B-solo', "B's offline-only write reached A after heal")

  // === (4) fresh third reader discovers over the SWARM and catches up ===
  const C = new SyncDB({ storage: track(tmpdir()), key: A.key, join: false })
  dbs.push(C)
  await C.ready()

  // A and C find each other via real DHT discovery on the in-process testnet.
  const swarmA = mkswarm()
  const swarmC = mkswarm()
  await connectSwarm(A, swarmA)
  await connectSwarm(C, swarmC)

  const expected = await dump(A)
  await waitFor('late reader catches up', async () => {
    await C.update()
    return JSON.stringify(await dump(C)) === JSON.stringify(expected)
  })
  t.alike(await dump(C), expected, 'late reader catches up to full current state over the swarm')
  t.absent(C.writable, 'late reader is read-only')
})
