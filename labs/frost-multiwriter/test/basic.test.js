const test = require('brittle')
const sodium = require('sodium-universal')
const b4a = require('b4a')

const frost = require('..')

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

test('verify is real: accepts a standard ed25519 signature', function (t) {
  // a FROST group signature is byte-compatible with single-key ed25519,
  // so the verify path is exactly this
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)

  const message = b4a.from('hypercore root hash goes here')
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, message, secretKey)

  t.ok(frost.verify(signature, message, publicKey), 'valid signature verifies')
  t.absent(frost.verify(signature, b4a.from('other message'), publicKey), 'wrong message fails')

  const tampered = b4a.from(signature)
  tampered[0] ^= 1
  t.absent(frost.verify(tampered, message, publicKey), 'tampered signature fails')

  t.exception(() => frost.verify(b4a.alloc(3), message, publicKey), /64-byte/)
  t.exception(() => frost.verify(signature, message, b4a.alloc(3)), /32-byte/)
})

test('sign session shape and honest not-implemented paths', function (t) {
  const session = new frost.SignSession({ id: 2, threshold: 3, signers: 5 })
  t.is(session.id, 2)
  t.is(session.threshold, 3)
  t.is(session.signers, 5)

  t.exception(() => session.commit(), /not implemented/)
  t.exception(() => session.sign(b4a.from('msg'), []), /not implemented/)
  t.exception(() => new frost.SignSession({ id: 0, threshold: 3, signers: 5 }), /id must be/)
  t.exception(() => new frost.SignSession({ id: 6, threshold: 3, signers: 5 }), /id must be/)

  t.exception(() => frost.dealerKeygen(3, 5), /not implemented/)
  t.exception(() => frost.dealerKeygen(9, 5), /signers must be >= threshold/)
  t.exception(() => frost.aggregate(b4a.from('msg'), [], [], b4a.alloc(32)), /not implemented/)
  t.exception(() => frost.createCore(null, {}), /not implemented/)
})
