const test = require('brittle')
const b4a = require('b4a')
const sodium = require('sodium-universal')

const pq = require('..')

test('module loads with expected api surface', function (t) {
  t.is(typeof pq.PQSecretStream, 'function')
  t.is(typeof pq.selectMode, 'function')
  t.is(typeof pq.bindModes, 'function')
  t.is(typeof pq.combineSecrets, 'function')
  t.is(typeof pq.keygen, 'function')
  t.is(typeof pq.encapsulate, 'function')
  t.is(typeof pq.decapsulate, 'function')
  t.alike(pq.constants.MODES, ['classical', 'hybrid'])
})

test('ml-kem-768 constants match fips 203', function (t) {
  t.is(pq.constants.MLKEM768.publicKeyBytes, 1184)
  t.is(pq.constants.MLKEM768.secretKeyBytes, 2400)
  t.is(pq.constants.MLKEM768.ciphertextBytes, 1088)
  t.is(pq.constants.MLKEM768.sharedSecretBytes, 32)
})

test('selectMode picks strongest common mode', function (t) {
  t.is(pq.selectMode(['classical', 'hybrid'], ['classical', 'hybrid']), 'hybrid')
  t.is(pq.selectMode(['classical', 'hybrid'], ['classical']), 'classical')
  t.is(pq.selectMode(['hybrid'], ['hybrid', 'classical']), 'hybrid')
})

test('selectMode downgrade protection', function (t) {
  t.exception(() => pq.selectMode(['classical', 'hybrid'], ['classical'], { requireHybrid: true }), /downgrade rejected/)
  t.exception(() => pq.selectMode(['hybrid'], ['classical']), /no common handshake mode/)
  t.exception(() => pq.selectMode(['hybrid'], ['kyber']), /unknown mode/)
})

test('bindModes is deterministic and order-independent', function (t) {
  const a = pq.bindModes(['classical', 'hybrid'])
  const b = pq.bindModes(['hybrid', 'classical'])
  const c = pq.bindModes(['classical'])

  t.is(a.byteLength, 32)
  t.alike(a, b)
  t.unlike(a, c)
  t.exception(() => pq.bindModes([]), /non-empty/)
})

test('combineSecrets is deterministic and input-sensitive', function (t) {
  const s1 = b4a.alloc(32).fill(1)
  const s2 = b4a.alloc(32).fill(2)

  const out = pq.combineSecrets(s1, s2)
  t.is(out.byteLength, 32)
  t.alike(out, pq.combineSecrets(s1, s2))
  t.unlike(out, pq.combineSecrets(s2, s1))
  t.unlike(out, pq.combineSecrets(s1, b4a.alloc(32).fill(3)))
  t.exception(() => pq.combineSecrets(b4a.alloc(16), s2), /32-byte/)
})

test('wire integration still throws honestly (Noise fragmentation not built yet)', function (t) {
  t.exception(() => new pq.PQSecretStream(true), /not implemented/)
  t.exception(() => new pq.PQSecretStream('nope'), /isInitiator/)
})

test('ml-kem-768 keygen/encapsulate/decapsulate is a real roundtrip', function (t) {
  const { publicKey, secretKey } = pq.keygen()
  t.is(publicKey.byteLength, 1184)
  t.is(secretKey.byteLength, 2400)

  const { ciphertext, sharedSecret } = pq.encapsulate(publicKey)
  t.is(ciphertext.byteLength, 1088)
  t.is(sharedSecret.byteLength, 32)

  const recovered = pq.decapsulate(ciphertext, secretKey)
  t.alike(recovered, sharedSecret, 'encapsulated secret == decapsulated secret')

  t.exception(() => pq.encapsulate(b4a.alloc(100)), /1184-byte/)
  t.exception(() => pq.decapsulate(b4a.alloc(100), secretKey), /1088-byte/)
})

test('hybrid handshake: initiator and responder derive identical session keys', function (t) {
  const { state, offer } = pq.initiate({ modes: ['classical', 'hybrid'], requireHybrid: true })
  t.is(offer.x25519pk.byteLength, 32)
  t.is(offer.mlkemPk.byteLength, 1184)

  const r = pq.respond(offer, { modes: ['classical', 'hybrid'], requireHybrid: true })
  t.is(r.mode, 'hybrid')
  t.is(r.message.ciphertext.byteLength, 1088)

  const i = pq.finalize(state, r.message)
  t.is(i.mode, 'hybrid')
  t.is(i.sessionKey.byteLength, 32)
  t.alike(i.sessionKey, r.sessionKey, 'both sides agree on the session key over the hybrid path')
})

test('downgrade half 1: requireHybrid rejects a stripped offer (policy check)', function (t) {
  const { offer } = pq.initiate({ modes: ['classical', 'hybrid'] })

  // MITM strips 'hybrid' from what the responder sees.
  const stripped = { ...offer, modes: ['classical'] }
  t.exception(
    () => pq.respond(stripped, { modes: ['classical', 'hybrid'], requireHybrid: true }),
    /downgrade rejected/,
    'responder with requireHybrid hard-fails on a stripped offer'
  )
})

test('downgrade half 2: tampered offered-mode digest makes keys diverge (cryptographic)', function (t) {
  // requireHybrid off so the policy check does NOT short-circuit; we want to
  // prove the transcript binding alone breaks the shared key.
  const { state, offer } = pq.initiate({ modes: ['classical', 'hybrid'] })

  // MITM strips 'hybrid' from the offered modes the responder authenticates,
  // but the initiator still binds its GENUINE offered modes on its own side.
  const tampered = { ...offer, modes: ['classical'] }
  const r = pq.respond(tampered, { modes: ['classical', 'hybrid'] })
  const i = pq.finalize(state, r.message)

  t.unlike(i.sessionKey, r.sessionKey, 'mismatched offered-mode digests => different session keys')

  // Control: with no tampering the same run agrees.
  const clean = pq.initiate({ modes: ['classical', 'hybrid'] })
  const rc = pq.respond(clean.offer, { modes: ['classical', 'hybrid'] })
  const ic = pq.finalize(clean.state, rc.message)
  t.alike(ic.sessionKey, rc.sessionKey, 'untampered run still agrees')
})

test('tampered X25519 share yields a different key (classical half)', function (t) {
  const { state, offer } = pq.initiate({ modes: ['hybrid'] })
  const r = pq.respond(offer, { modes: ['hybrid'] })

  const tamperedMsg = { ...r.message, x25519pk: b4a.alloc(32) }
  sodium.randombytes_buf(tamperedMsg.x25519pk)
  const i = pq.finalize(state, tamperedMsg)
  t.unlike(i.sessionKey, r.sessionKey, 'tampered X25519 public share breaks the shared key')
})

test('wrong ML-KEM ciphertext yields a different key (post-quantum half)', function (t) {
  const { state, offer } = pq.initiate({ modes: ['hybrid'] })
  const r = pq.respond(offer, { modes: ['hybrid'] })

  // Fresh ciphertext from an unrelated encapsulation against the SAME pk: it
  // decapsulates cleanly to a *different* shared secret than the one the
  // responder derived => a different derived session key.
  const other = pq.encapsulate(offer.mlkemPk)
  const tamperedMsg = { ...r.message, ciphertext: other.ciphertext }
  const i = pq.finalize(state, tamperedMsg)
  t.unlike(i.sessionKey, r.sessionKey, 'wrong ML-KEM ciphertext breaks the shared key')
})
