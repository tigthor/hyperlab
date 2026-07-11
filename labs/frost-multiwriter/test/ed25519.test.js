// FROST-Ed25519 (RFC 9591 FROST(Ed25519, SHA-512)): the aggregate is a
// standard RFC 8032 signature, so it drops into hypercore's stock ed25519
// verifier — proven here end-to-end with a live 2-of-3 threshold hypercore
// replicating to a completely stock replica.

const test = require('brittle')
const fs = require('fs')
const os = require('os')
const path = require('path')
const b4a = require('b4a')
const crypto = require('hypercore-crypto') // sodium ed25519 — the stock verifier
const Hypercore = require('hypercore')
const CoreStorage = require('hypercore-storage')

const frost = require('..')
const { ed25519, createCore } = frost

function sessionsFor (dealt, ids, threshold, signers) {
  return ids.map((id) => new ed25519.SignSession({
    id,
    secret: dealt.shares[id - 1].secret,
    group: dealt.group,
    threshold,
    signers
  }))
}

function tmpStorage (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'frost-core-'))
  const db = new CoreStorage(dir)
  t.teardown(() => fs.rmSync(dir, { recursive: true, force: true }), { order: 2 })
  return db
}

test('ed25519 aggregate verifies as a stock RFC 8032 signature (sodium)', function (t) {
  const dealt = ed25519.dealerKeygen(2, 3)
  const message = b4a.from('the group speaks with one voice')

  const sig = ed25519.thresholdSign(message, sessionsFor(dealt, [1, 2], 2, 3))

  t.is(sig.byteLength, 64, 'one 64-byte signature')
  t.ok(crypto.verify(message, sig, dealt.publicKey), 'sodium crypto_sign_verify_detached accepts it')
  t.ok(ed25519.verify(sig, message, dealt.publicKey), 'suite verify accepts it')

  const tampered = b4a.from(sig)
  tampered[10] ^= 0xff
  t.absent(crypto.verify(message, tampered, dealt.publicKey), 'tampered signature rejected by sodium')

  const wrongMsg = b4a.from('a different message')
  t.absent(crypto.verify(wrongMsg, sig, dealt.publicKey), 'signature does not transfer to another message')
})

test('every 2-of-3 pair produces a signature for the same single group key', function (t) {
  const dealt = ed25519.dealerKeygen(2, 3)
  const message = b4a.from('any quorum, one key')

  for (const pair of [[1, 2], [2, 3], [1, 3]]) {
    const sig = ed25519.thresholdSign(message, sessionsFor(dealt, pair, 2, 3))
    t.ok(crypto.verify(message, sig, dealt.publicKey), 'pair ' + pair.join('+') + ' verifies under sodium')
  }
})

test('below quorum fails closed; forged share is caught at aggregation', function (t) {
  const dealt = ed25519.dealerKeygen(2, 3)
  const message = b4a.from('no minority signatures')

  t.exception(
    () => ed25519.thresholdSign(message, sessionsFor(dealt, [1], 2, 3)),
    /below quorum/,
    'one signer alone cannot sign'
  )

  const [a, b] = sessionsFor(dealt, [1, 2], 2, 3)
  const commitments = [a.commit(), b.commit()]
  const shares = [a.sign(message, commitments), b.sign(message, commitments)]
  shares[1] = { ...shares[1], share: b4a.alloc(32, 7) } // forged co-signer share

  try {
    ed25519.aggregate(message, commitments, shares, dealt.group)
    t.fail('aggregation accepted a forged share')
  } catch (err) {
    t.pass('aggregation failed closed on the forged share')
    if (err.cheaters) t.alike(err.cheaters, [shares[1].identifier], 'the forger is identified')
  }
})

test('ristretto255 output is NOT an ed25519 signature (suites stay distinct)', function (t) {
  const dealtR = frost.dealerKeygen(2, 3)
  const message = b4a.from('suite confusion must fail')
  const sessions = [1, 2].map((id) => new frost.SignSession({
    id, secret: dealtR.shares[id - 1].secret, group: dealtR.group, threshold: 2, signers: 3
  }))
  const sigR = frost.thresholdSign(message, sessions)

  t.ok(frost.verify(sigR, message, dealtR.publicKey), 'valid under ristretto255')
  t.absent(crypto.verify(message, sigR, dealtR.publicKey), 'sodium ed25519 rejects a ristretto255 signature')
})

test('live 2-of-3 threshold hypercore, verified by a completely stock replica', async function (t) {
  const dealt = ed25519.dealerKeygen(2, 3)

  const g = await createCore(tmpStorage(t), dealt.publicKey)
  t.teardown(() => g.core.close().catch(() => {}), { order: 1 })

  // three appends, each signed by a DIFFERENT pair of writers
  await g.append(b4a.from('block 0 — signed by writers 1+2'), sessionsFor(dealt, [1, 2], 2, 3))
  await g.append(b4a.from('block 1 — signed by writers 2+3'), sessionsFor(dealt, [2, 3], 2, 3))
  await g.append([b4a.from('block 2 — signed by writers 1+3'), b4a.from('block 3 — same round')],
    sessionsFor(dealt, [1, 3], 2, 3))

  t.is(g.core.length, 4, 'group core appended 4 blocks across 3 different quorums')

  // a STOCK replica: same manifest, zero FROST code anywhere near it
  const replica = new Hypercore(tmpStorage(t), { manifest: g.manifest })
  await replica.ready()
  t.teardown(() => replica.close().catch(() => {}), { order: 1 })

  t.ok(b4a.equals(replica.key, g.core.key), 'stock replica derives the same core key from the manifest')

  const s1 = g.core.replicate(true)
  const s2 = replica.replicate(false)
  s1.pipe(s2).pipe(s1)

  // wait for full sync, then read every block back through the stock verifier
  const deadline = Date.now() + 30000
  while (replica.length < g.core.length) {
    if (Date.now() > deadline) throw new Error('replication timed out')
    await new Promise((resolve) => setTimeout(resolve, 50))
  }

  t.is(replica.length, 4, 'stock replica verified and accepted all threshold-signed blocks')
  t.alike(await replica.get(0), b4a.from('block 0 — signed by writers 1+2'))
  t.alike(await replica.get(3), b4a.from('block 3 — same round'))

  s1.destroy()
  s2.destroy()
})

test('a garbage signature cannot append; a real quorum still can afterwards', async function (t) {
  const dealt = ed25519.dealerKeygen(2, 3)
  const g = await createCore(tmpStorage(t), dealt.publicKey)
  t.teardown(() => g.core.close().catch(() => {}), { order: 1 })

  // hypercore refuses the append (resolving without appending rather than
  // throwing) — the property that matters is that no unsigned block lands
  await g.core.append(b4a.from('unauthorized'), { signature: b4a.alloc(64, 9) }).catch(() => {})
  t.is(g.core.length, 0, 'nothing was appended with a non-quorum signature')

  await g.append(b4a.from('authorized'), sessionsFor(dealt, [1, 3], 2, 3))
  t.is(g.core.length, 1, 'a real threshold signature still appends')
})
