// Network property + fuzz tests for filedrop, run entirely on the in-process
// hyperdht testnet (never the public DHT). Bounded to a few MB, seeded PRNG so
// any failure reproduces, everything torn down (nodes/servers/streams/tmp).
//
// Properties exercised:
//   1. Files of RANDOM sizes incl. edge cases (0, 1, chunk-1, chunk, chunk+1,
//      multi-chunk, several MB) arrive byte-identical + merkle-verified, and the
//      signed receipt binds the exact byte count and file hash.
//   2. RESUME from a RANDOM kill offset always completes byte-identically and
//      NEVER restarts from 0 (resumes from exactly the kill offset).
//   3. A WRONG passphrase ALWAYS aborts at CPace, before any file byte / dir is
//      written and before a manifest leaks.
//   4. A tampered chunk on the wire is detected (leaf verification) and never
//      renamed into the final file.

const test = require('brittle')
const fs = require('fs')
const os = require('os')
const path = require('path')
const b4a = require('b4a')
const DHT = require('hyperdht')
const crypto = require('hypercore-crypto')
const rm = require('retrieval-market')
const { CPace, topicFromPassphrase } = require('hyperbeam-pake')
const createTestnet = require('hyperlab-harness/testnet')

const {
  createSender,
  receive,
  MessageReader,
  writeMsg,
  runCPace,
  u32be,
  TYPE
} = require('..')

// ---------------------------------------------------------------------------
// seeded PRNG (xorshift32)
// ---------------------------------------------------------------------------
const SEED = (process.env.FILEDROP_SEED ? (parseInt(process.env.FILEDROP_SEED, 10) >>> 0) : 0xc0ffee11) || 1

function makePRNG (seed) {
  let s = seed >>> 0 || 1
  const next = () => {
    s ^= s << 13; s >>>= 0
    s ^= s >>> 17; s >>>= 0
    s ^= s << 5; s >>>= 0
    return s >>> 0
  }
  return {
    u32: next,
    int: (n) => next() % n,
    fill: (buf) => { for (let i = 0; i < buf.byteLength; i++) buf[i] = next() & 0xff; return buf }
  }
}

function mkTmp () {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'filedrop-fuzz-'))
}

function writeFile (rng, dir, name, size) {
  const buf = rng.fill(b4a.alloc(size))
  const p = path.join(dir, name)
  fs.writeFileSync(p, buf)
  return { path: p, buf }
}

// unique passphrase per transfer -> unique rendezvous keypair, so sequential
// transfers on reused nodes never collide.
function passphraseFor (rng) {
  return 'pf-' + rng.u32().toString(16) + '-' + rng.u32().toString(16) + '-' + rng.u32().toString(16)
}

// mirror of index.js encodeManifest (used by the malicious sender below)
function encodeManifest (m) {
  return b4a.from(JSON.stringify({
    name: m.name,
    size: m.size,
    chunkSize: m.chunkSize,
    totalChunks: m.totalChunks,
    merkleRoot: b4a.toString(m.merkleRoot, 'hex'),
    provider: b4a.toString(m.provider, 'hex'),
    leaves: m.leaves.map(l => b4a.toString(l, 'hex'))
  }))
}

// ===========================================================================
test('fuzz: random + edge-size transfers are byte-identical, merkle+receipt bound', async function (t) {
  t.comment('seed=' + SEED)
  const rng = makePRNG(SEED)
  const testnet = await createTestnet(5, t)
  const tmp = mkTmp()
  t.teardown(async () => {
    await testnet.destroy()
    fs.rmSync(tmp, { recursive: true, force: true })
  })

  const senderNode = testnet.createNode()
  const recvNode = testnet.createNode()

  const chunkSize = 4096
  // edge cases around chunk boundaries + a couple of random small sizes + one
  // several-MB transfer at the default chunk size.
  const cases = [
    { size: 0, chunkSize },
    { size: 1, chunkSize },
    { size: chunkSize - 1, chunkSize },
    { size: chunkSize, chunkSize },
    { size: chunkSize + 1, chunkSize },
    { size: 2 * chunkSize, chunkSize },
    { size: 3 * chunkSize + 123, chunkSize },
    { size: 1 + rng.int(9000), chunkSize },
    { size: 1 + rng.int(50000), chunkSize },
    { size: 2 * 1024 * 1024 + 1 + rng.int(1024 * 1024), chunkSize: 64 * 1024 }
  ]

  let idx = 0
  for (const c of cases) {
    const name = 'file' + (idx++) + '.bin'
    const src = writeFile(rng, tmp, name, c.size)
    const outdir = path.join(tmp, 'out-' + name)
    const passphrase = passphraseFor(rng)

    const sender = createSender(src.path, { node: senderNode, passphrase, chunkSize: c.chunkSize })
    await sender.listen()

    const recvResult = await receive(passphrase, outdir, { node: recvNode })
    const sendResult = await sender.finished
    await sender.close()

    const got = b4a.from(fs.readFileSync(recvResult.path))
    if (got.byteLength !== c.size) t.fail(name + ' size ' + got.byteLength + '!=' + c.size)
    if (!b4a.equals(got, src.buf)) t.fail(name + ' (' + c.size + 'B) not byte-identical')
    if (!b4a.equals(recvResult.fileHash, sender.merkleRoot)) t.fail(name + ' fileHash != merkleRoot')

    // receipt binds the REAL byte count + file hash
    const r = sendResult.receipt
    if (!rm.verifyReceipt(r)) t.fail(name + ' receipt does not verify')
    if (r.bytes !== c.size) t.fail(name + ' receipt bytes ' + r.bytes + '!=' + c.size)
    if (!b4a.equals(r.channel, sender.merkleRoot)) t.fail(name + ' receipt channel != file hash')
    if (!b4a.equals(r.consumer, recvResult.receipt.consumer)) t.fail(name + ' consumer mismatch')

    // no leftover scratch
    if (fs.existsSync(path.join(outdir, name + '.part'))) t.fail(name + ' leftover .part')
    if (fs.existsSync(path.join(outdir, name + '.filedrop.json'))) t.fail(name + ' leftover sidecar')
  }

  t.pass('all ' + cases.length + ' edge/random transfers byte-identical + merkle + receipt bound')
})

// ===========================================================================
test('fuzz: RESUME from a random kill offset always completes and never restarts from 0', async function (t) {
  t.comment('seed=' + SEED)
  const rng = makePRNG(SEED ^ 0x1234)
  const testnet = await createTestnet(5, t)
  const tmp = mkTmp()
  t.teardown(async () => {
    await testnet.destroy()
    fs.rmSync(tmp, { recursive: true, force: true })
  })

  const senderNode = testnet.createNode()
  const recvNode = testnet.createNode()

  const ITER = 8
  for (let iter = 0; iter < ITER; iter++) {
    const chunkSize = 8192
    const totalChunks = 8 + rng.int(24) // 8..31 chunks
    const size = (totalChunks - 1) * chunkSize + 1 + rng.int(chunkSize) // partial last chunk
    const name = 'resume' + iter + '.bin'
    const src = writeFile(rng, tmp, name, size)
    const outdir = path.join(tmp, 'out-' + name)
    const passphrase = passphraseFor(rng)
    const realTotal = Math.max(1, Math.ceil(size / chunkSize))

    const killChunk = 1 + rng.int(realTotal - 1) // in [1, realTotal-1] -> >=1 remaining

    const sender = createSender(src.path, { node: senderNode, passphrase, chunkSize })
    await sender.listen()

    // first receiver: kill once we've verified `killChunk` chunks
    let killed = false
    await t.exception(
      receive(passphrase, outdir, {
        node: recvNode,
        onProgress ({ chunk, socket }) {
          if (!killed && chunk >= killChunk) { killed = true; socket.destroy() }
        }
      }),
      /stream ended|closed|ended/,
      'iter ' + iter + ': receiver rejects on mid-transfer kill'
    )

    const sidecarPath = path.join(outdir, name + '.filedrop.json')
    const partPath = path.join(outdir, name + '.part')
    if (!fs.existsSync(sidecarPath)) { t.fail('iter ' + iter + ' no sidecar after kill'); await sender.close(); continue }
    const state = JSON.parse(fs.readFileSync(sidecarPath, 'utf8'))
    if (!(state.verified >= killChunk && state.verified < realTotal)) {
      t.fail('iter ' + iter + ' partial progress out of range: ' + state.verified + '/' + realTotal)
    }
    if (fs.statSync(partPath).size !== state.bytes) t.fail('iter ' + iter + ' .part size != recorded bytes')
    const verifiedAtKill = state.verified

    // second receiver, same outdir: MUST resume from exactly the kill offset
    let resumedFrom = -1
    const recvResult = await receive(passphrase, outdir, {
      node: recvNode,
      onProgress ({ chunk }) { if (resumedFrom < 0) resumedFrom = chunk }
    })
    const sendResult = await sender.finished
    await sender.close()

    // NEVER restarts from 0: first delivered chunk on resume == verifiedAtKill+1
    if (resumedFrom !== verifiedAtKill + 1) {
      t.fail('iter ' + iter + ' resumed from ' + resumedFrom + ' expected ' + (verifiedAtKill + 1) + ' (restart-from-0 or gap)')
    }
    if (resumedFrom <= 1) t.fail('iter ' + iter + ' resume restarted at/near 0')

    const got = b4a.from(fs.readFileSync(recvResult.path))
    if (!b4a.equals(got, src.buf)) t.fail('iter ' + iter + ' resumed file not byte-identical')
    if (!rm.verifyReceipt(sendResult.receipt)) t.fail('iter ' + iter + ' receipt invalid after resume')
    if (sendResult.receipt.bytes !== size) t.fail('iter ' + iter + ' receipt bytes != full size')
    if (!b4a.equals(sendResult.receipt.channel, sender.merkleRoot)) t.fail('iter ' + iter + ' receipt channel != hash')
    if (fs.existsSync(partPath)) t.fail('iter ' + iter + ' leftover .part after resume')
  }

  t.pass(ITER + ' resume iterations: all completed byte-identically, none restarted from 0')
})

// ===========================================================================
test('fuzz: a wrong passphrase ALWAYS aborts at CPace — no dir/bytes written, no manifest leaked', async function (t) {
  t.comment('seed=' + SEED)
  const rng = makePRNG(SEED ^ 0xabcd)
  const testnet = await createTestnet(5, t)
  const tmp = mkTmp()
  t.teardown(async () => {
    await testnet.destroy()
    fs.rmSync(tmp, { recursive: true, force: true })
  })

  const senderNode = testnet.createNode()
  const advNode = testnet.createNode()

  // one honest sender that stays listening across every wrong-passphrase attempt
  const src = writeFile(rng, tmp, 'secret.bin', 256 * 1024)
  const passphrase = passphraseFor(rng)
  const sender = createSender(src.path, { node: senderNode, passphrase, chunkSize: 4096 })
  await sender.listen()

  const keyPair = DHT.keyPair(topicFromPassphrase(passphrase))
  const sid = b4a.from(topicFromPassphrase(passphrase).subarray(0, 16))

  const ITER = 20
  for (let iter = 0; iter < ITER; iter++) {
    const wrong = 'WRONG-' + rng.u32().toString(16) + '-' + rng.u32().toString(16)
    const outdir = path.join(tmp, 'adv-out-' + iter) // must NEVER be created

    const sock = advNode.connect(keyPair.publicKey, { keyPair })
    const reader = new MessageReader(sock)
    if ((await sock.opened) !== true) { t.fail('iter ' + iter + ' adversary socket did not open'); reader.destroy(); sock.destroy(); continue }

    // Faithful adversary that mirrors receive()'s ordering: it only touches the
    // filesystem AFTER CPace resolves. If CPace failed to abort (a bug), the
    // mkdir/write below WOULD run and the outdir assertion would fail.
    let cpaceAborted = false
    let wroteBytes = false
    try {
      await runCPace(sock, reader, wrong, sid, false)
      // (only reached if CPace wrongly accepted)
      fs.mkdirSync(outdir, { recursive: true })
      fs.writeFileSync(path.join(outdir, 'leak.bin'), b4a.from('leaked'))
      wroteBytes = true
    } catch (err) {
      cpaceAborted = /key confirmation failed/.test(err.message)
    }

    if (!cpaceAborted) t.fail('iter ' + iter + ' CPace did NOT abort on wrong passphrase')
    if (wroteBytes) t.fail('iter ' + iter + ' wrote file bytes despite wrong passphrase')
    if (fs.existsSync(outdir)) t.fail('iter ' + iter + ' output dir was created despite wrong passphrase')

    // nothing about the file leaked to the wrong peer
    const leaked = reader.queue.some(m => m.type === TYPE.MANIFEST || m.type === TYPE.CHUNK)
    if (leaked) t.fail('iter ' + iter + ' manifest/chunk leaked to wrong-passphrase peer')

    reader.destroy()
    sock.destroy()
  }

  // the honest sender never completed a transfer for any adversary
  let resolved = false
  sender.finished.then(() => { resolved = true })
  await new Promise(r => setTimeout(r, 150))
  t.absent(resolved, 'sender produced no receipt for any wrong-passphrase peer')
  await sender.close()

  t.pass(ITER + ' wrong-passphrase attempts all aborted at CPace with zero file bytes')
})

// ===========================================================================
test('fuzz: a tampered chunk on the wire is detected and never lands in the final file', async function (t) {
  t.comment('seed=' + SEED)
  const rng = makePRNG(SEED ^ 0x77aa)
  const testnet = await createTestnet(5, t)
  const tmp = mkTmp()
  t.teardown(async () => {
    await testnet.destroy()
    fs.rmSync(tmp, { recursive: true, force: true })
  })

  const ITER = 5
  for (let iter = 0; iter < ITER; iter++) {
    // fresh nodes per iteration: the malicious server's abrupt teardown after a
    // rejected chunk otherwise leaves reused-node mux state racy across rounds.
    const advNode = testnet.createNode()
    const recvNode = testnet.createNode()
    const chunkSize = 4096
    const totalChunks = 6 + rng.int(10)
    const size = (totalChunks - 1) * chunkSize + 1 + rng.int(chunkSize)
    const name = 'tamper' + iter + '.bin'
    const src = writeFile(rng, tmp, name, size)
    const outdir = path.join(tmp, 'out-' + name)
    const passphrase = passphraseFor(rng)
    const realTotal = Math.max(1, Math.ceil(size / chunkSize))
    // Tamper within the first few chunks so detection is deterministic and
    // happens well before any tail-of-stream reset window. Never the last
    // (partial) chunk, so there are always full bytes to flip.
    const badIndex = rng.int(Math.min(3, realTotal - 1))

    // manifest with HONEST leaves (so tamper is a wire mutation, not a manifest lie)
    const manifest = require('..').computeManifest(name, src.buf, chunkSize)
    manifest.provider = rm.keyPair().publicKey

    const keyPair = DHT.keyPair(topicFromPassphrase(passphrase))
    const sid = b4a.from(topicFromPassphrase(passphrase).subarray(0, 16))

    // malicious sender: honest CPace + manifest, but flips a byte in one chunk
    const server = advNode.createServer({
      firewall (pk) { return !b4a.equals(pk, keyPair.publicKey) }
    }, async (sock) => {
      sock.on('error', () => {}) // receiver resets us when it rejects the bad chunk
      const reader = new MessageReader(sock)
      try {
        if ((await sock.opened) === false) throw new Error('open failed')
        await runCPace(sock, reader, passphrase, sid, true)
        await writeMsg(sock, TYPE.MANIFEST, encodeManifest(manifest))
        const resume = await reader.expect(TYPE.RESUME)
        const fromChunk = JSON.parse(b4a.toString(resume.payload)).fromChunk | 0
        for (let i = fromChunk; i < realTotal; i++) {
          const chunk = b4a.from(src.buf.subarray(i * chunkSize, Math.min(size, (i + 1) * chunkSize)))
          if (i === badIndex) chunk[0] ^= 0xff // corrupt on the wire
          await writeMsg(sock, TYPE.CHUNK, b4a.concat([u32be(i), chunk]))
        }
        await writeMsg(sock, TYPE.DONE)
        // Wait for the receiver to detect the tamper and close FIRST, so the bad
        // chunk's bytes fully flush before the socket tears down. If we reset
        // eagerly, the TCP reset can outrun the in-flight chunk and the receiver
        // would see ECONNRESET instead of a leaf-verification failure.
        await new Promise(res => { sock.once('close', res); sock.once('end', res) })
      } catch {
      } finally {
        reader.destroy()
        if (!sock.destroyed) sock.destroy()
      }
    })
    await server.listen(keyPair)

    await t.exception(
      receive(passphrase, outdir, { node: recvNode }),
      /failed leaf verification/,
      'iter ' + iter + ': tampered chunk ' + badIndex + ' detected'
    )

    // the tampered bytes never made it into a final file
    if (fs.existsSync(path.join(outdir, name))) t.fail('iter ' + iter + ' final file created despite tamper')
    // only the good prefix (chunks 0..badIndex-1) was ever written
    const partPath = path.join(outdir, name + '.part')
    if (fs.existsSync(partPath)) {
      const partSize = fs.statSync(partPath).size
      if (partSize !== badIndex * chunkSize) t.fail('iter ' + iter + ' .part size ' + partSize + ' != ' + (badIndex * chunkSize) + ' (bad chunk was written)')
    }

    await server.close()
  }

  t.pass(ITER + ' tampered-chunk iterations: every corruption detected, none reached the final file')
})
