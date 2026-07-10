const test = require('brittle')
const b4a = require('b4a')

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

test('unimplemented crypto throws honestly', function (t) {
  t.exception(() => pq.keygen(), /not implemented/)
  t.exception(() => pq.encapsulate(b4a.alloc(1184)), /not implemented/)
  t.exception(() => pq.decapsulate(b4a.alloc(1088), b4a.alloc(2400)), /not implemented/)
  t.exception(() => new pq.PQSecretStream(true), /not implemented/)
  t.exception(() => new pq.PQSecretStream('nope'), /isInitiator/)
})
