const test = require('brittle')
const b4a = require('b4a')

const pq = require('..')

test('module loads with expected api surface', function (t) {
  t.is(typeof pq.detect, 'function')
  t.is(typeof pq.mlkem.keygen, 'function')
  t.is(typeof pq.mlkem.encapsulate, 'function')
  t.is(typeof pq.mlkem.decapsulate, 'function')
  t.is(typeof pq.mldsa.keygen, 'function')
  t.is(typeof pq.mldsa.sign, 'function')
  t.is(typeof pq.mldsa.verify, 'function')
})

test('constants match fips 203 (ml-kem)', function (t) {
  t.alike(pq.constants['ML-KEM-512'], { publicKeyBytes: 800, secretKeyBytes: 1632, ciphertextBytes: 768, sharedSecretBytes: 32 })
  t.alike(pq.constants['ML-KEM-768'], { publicKeyBytes: 1184, secretKeyBytes: 2400, ciphertextBytes: 1088, sharedSecretBytes: 32 })
  t.alike(pq.constants['ML-KEM-1024'], { publicKeyBytes: 1568, secretKeyBytes: 3168, ciphertextBytes: 1568, sharedSecretBytes: 32 })
  t.is(pq.constants.DEFAULT_KEM, 'ML-KEM-768')
})

test('constants match fips 204 (ml-dsa)', function (t) {
  t.alike(pq.constants['ML-DSA-44'], { publicKeyBytes: 1312, secretKeyBytes: 2560, signatureBytes: 2420 })
  t.alike(pq.constants['ML-DSA-65'], { publicKeyBytes: 1952, secretKeyBytes: 4032, signatureBytes: 3309 })
  t.alike(pq.constants['ML-DSA-87'], { publicKeyBytes: 2592, secretKeyBytes: 4896, signatureBytes: 4627 })
  t.is(pq.constants.DEFAULT_DSA, 'ML-DSA-65')
})

test('feature detection returns an honest report', function (t) {
  const d = pq.detect()
  t.is(typeof d.wasm, 'boolean')
  t.is(typeof d.native, 'boolean')
  t.is(typeof d.bare, 'boolean')
  t.is(d.backend, null) // no backend implemented yet
  t.is(d.wasm, true) // node has WebAssembly
  t.is(d.bare, false) // we are running under node here
})

test('primitive ops throw honestly, bad input throws first', function (t) {
  t.exception(() => pq.mlkem.keygen(), /not implemented/)
  t.exception(() => pq.mlkem.keygen('ML-KEM-9000'), /unknown algorithm/)
  t.exception(() => pq.mlkem.encapsulate(b4a.alloc(1184)), /not implemented/)
  t.exception(() => pq.mlkem.encapsulate(b4a.alloc(4)), /must be 1184 bytes/)
  t.exception(() => pq.mlkem.decapsulate(b4a.alloc(1088), b4a.alloc(2400)), /not implemented/)
  t.exception(() => pq.mlkem.decapsulate(b4a.alloc(4), b4a.alloc(2400)), /must be 1088 bytes/)

  t.exception(() => pq.mldsa.keygen(), /not implemented/)
  t.exception(() => pq.mldsa.sign(b4a.from('msg'), b4a.alloc(4032)), /not implemented/)
  t.exception(() => pq.mldsa.verify(b4a.alloc(3309), b4a.from('msg'), b4a.alloc(1952)), /not implemented/)
  t.exception(() => pq.mldsa.verify(b4a.alloc(64), b4a.from('msg'), b4a.alloc(1952)), /must be 3309 bytes/)
})
