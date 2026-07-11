const test = require('brittle')
const b4a = require('b4a')

const frost = require('..')

// Drive a real FROST signing round: `quorum` is an array of session objects
// that all commit, then each sign over the shared commitment set, then the
// coordinator aggregates. Returns { signature, publicKey }.
function roundSign (dealt, sessions, message) {
  const commitments = sessions.map((s) => s.commit())
  const shares = sessions.map((s) => s.sign(message, commitments))
  const signature = frost.aggregate(message, commitments, shares, dealt.group)
  return signature
}

function makeSessions (dealt, threshold, signers, ids) {
  return ids.map((id) => new frost.SignSession({
    id,
    secret: dealt.shares[id - 1].secret,
    group: dealt.group,
    threshold,
    signers
  }))
}

test('module loads with expected api surface', function (t) {
  t.is(typeof frost.dealerKeygen, 'function')
  t.is(typeof frost.SignSession, 'function')
  t.is(typeof frost.aggregate, 'function')
  t.is(typeof frost.verify, 'function')
  t.is(typeof frost.createCore, 'function')
  t.is(frost.constants.SIGNATURE_BYTES, 64)
  t.is(frost.constants.PUBLICKEY_BYTES, 32)
})

test('validateConfig accepts sane t-of-n and rejects nonsense', function (t) {
  frost.validateConfig(2, 3)
  frost.validateConfig(3, 5)
  t.pass('valid configs accepted')

  t.exception(() => frost.validateConfig(1, 5), />= 2/)
  t.exception(() => frost.validateConfig(4, 3), /signers must be >= threshold/)
  t.exception(() => frost.validateConfig(2.5, 5), /integers/)
})

test('dealerKeygen produces a group key and n consistent shares', function (t) {
  const dealt = frost.dealerKeygen(2, 3)
  t.is(dealt.publicKey.byteLength, 32, 'group public key is 32 bytes')
  t.is(dealt.shares.length, 3, 'n shares dealt')
  for (let i = 0; i < 3; i++) {
    t.is(dealt.shares[i].id, i + 1)
    t.is(dealt.shares[i].verificationShare.byteLength, 32)
  }
})

test('real 2-of-3 threshold: any 2 sign, aggregate verifies against group key', function (t) {
  const dealt = frost.dealerKeygen(2, 3)
  const message = b4a.from('hypercore root hash')

  // every 2-of-3 pair must independently produce a valid group signature
  for (const pair of [[1, 2], [1, 3], [2, 3]]) {
    const sessions = makeSessions(dealt, 2, 3, pair)
    const signature = roundSign(dealt, sessions, message)
    t.is(signature.byteLength, 64, 'aggregate is a 64-byte signature for ' + pair)
    t.ok(frost.verify(signature, message, dealt.publicKey), 'pair ' + pair + ' verifies against the single group key')
  }
})

test('t-1 signers cannot forge: below-quorum signing fails closed', function (t) {
  const dealt = frost.dealerKeygen(2, 3)
  const message = b4a.from('hypercore root hash')

  // a lone signer (t-1 = 1) commits, but cannot even run round 2: there are
  // fewer than `threshold` commitments in the set.
  const lone = makeSessions(dealt, 2, 3, [1])[0]
  const commitments = [lone.commit()]
  t.exception(() => lone.sign(message, commitments), /below quorum/, 'one signer cannot produce a share')

  // and a fabricated second signer (attacker guesses a share they do not own)
  // is caught: aggregation verifies each share and fails closed on the forgery.
  const s1 = makeSessions(dealt, 2, 3, [1])[0]
  const c1 = s1.commit()
  // forge a commitment for id 2 with a made-up secret share
  const { ristretto255_FROST: RAW } = require('@noble/curves/ed25519.js')
  const fakeSecret = { identifier: RAW.Identifier.fromNumber(2), signingShare: RAW.utils.randomScalar() }
  const fakeGen = RAW.commit(fakeSecret)
  const cFake = {
    id: 2,
    identifier: fakeSecret.identifier,
    hidingCommitment: b4a.from(fakeGen.commitments.hiding),
    bindingCommitment: b4a.from(fakeGen.commitments.binding)
  }
  const commitList = [c1, cFake]
  const realShare = s1.sign(message, commitList)
  const fakeList = frostCommitmentList(commitList)
  const fakeShare = {
    id: 2,
    identifier: fakeSecret.identifier,
    share: b4a.from(RAW.signShare(fakeSecret, dealt.group, fakeGen.nonces, fakeList, message))
  }
  t.exception(() => frost.aggregate(message, commitList, [realShare, fakeShare], dealt.group), /aggregation failed/, 'forged share caught at aggregation')

  function frostCommitmentList (cs) {
    return cs
      .map((c) => ({ identifier: c.identifier, hiding: c.hidingCommitment, binding: c.bindingCommitment }))
      .sort((a, b) => (a.identifier < b.identifier ? -1 : 1))
  }
})

test('wrong message fails and tampered signature fails', function (t) {
  const dealt = frost.dealerKeygen(2, 3)
  const message = b4a.from('the real root hash')
  const sessions = makeSessions(dealt, 2, 3, [2, 3])
  const signature = roundSign(dealt, sessions, message)

  t.ok(frost.verify(signature, message, dealt.publicKey), 'valid signature verifies')
  t.absent(frost.verify(signature, b4a.from('a different root hash'), dealt.publicKey), 'wrong message rejected')

  const tampered = b4a.from(signature)
  tampered[0] ^= 1
  t.absent(frost.verify(tampered, message, dealt.publicKey), 'tampered signature rejected')

  // wrong group key rejects too
  const other = frost.dealerKeygen(2, 3)
  t.absent(frost.verify(signature, message, other.publicKey), 'wrong group key rejected')
})

test('verify input validation', function (t) {
  const dealt = frost.dealerKeygen(2, 3)
  const message = b4a.from('root')
  const sessions = makeSessions(dealt, 2, 3, [1, 2])
  const signature = roundSign(dealt, sessions, message)

  t.exception(() => frost.verify(b4a.alloc(3), message, dealt.publicKey), /64-byte/)
  t.exception(() => frost.verify(signature, message, b4a.alloc(3)), /32-byte/)
})

test('SignSession id bounds and createCore input validation', async function (t) {
  const dealt = frost.dealerKeygen(3, 5)
  t.exception(() => new frost.SignSession({ id: 0, group: dealt.group, threshold: 3, signers: 5 }), /id must be/)
  t.exception(() => new frost.SignSession({ id: 6, group: dealt.group, threshold: 3, signers: 5 }), /id must be/)

  // createCore is real now (FROST-Ed25519, see test/ed25519.test.js) — it
  // requires the 32-byte group key up front
  await t.exception(frost.createCore(null, null), /groupPublicKey/)
})
