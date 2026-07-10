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

test('feature detection reports the real backend', function (t) {
  const d = pq.detect()
  t.is(typeof d.wasm, 'boolean')
  t.is(typeof d.native, 'boolean')
  t.is(typeof d.bare, 'boolean')
  t.is(d.backend, 'noble-js') // pure-JS FIPS 203/204 backend is wired
  t.is(d.wasm, true) // node has WebAssembly
  t.is(d.bare, false) // we are running under node here
})

test('ml-kem keygen produces exact FIPS 203 byte sizes', function (t) {
  for (const alg of ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']) {
    const p = pq.constants[alg]
    const kp = pq.mlkem.keygen(alg)
    t.ok(b4a.isBuffer(kp.publicKey), alg + ' publicKey is a buffer')
    t.ok(b4a.isBuffer(kp.secretKey), alg + ' secretKey is a buffer')
    t.is(kp.publicKey.byteLength, p.publicKeyBytes, alg + ' publicKey size')
    t.is(kp.secretKey.byteLength, p.secretKeyBytes, alg + ' secretKey size')
  }
})

test('ml-kem encapsulate/decapsulate roundtrip yields identical 32-byte shared secrets', function (t) {
  for (const alg of ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']) {
    const p = pq.constants[alg]
    const kp = pq.mlkem.keygen(alg)
    const { ciphertext, sharedSecret } = pq.mlkem.encapsulate(kp.publicKey, alg)
    t.is(ciphertext.byteLength, p.ciphertextBytes, alg + ' ciphertext size')
    t.is(sharedSecret.byteLength, 32, alg + ' shared secret is 32 bytes')
    const ss2 = pq.mlkem.decapsulate(ciphertext, kp.secretKey, alg)
    t.is(ss2.byteLength, 32, alg + ' decapsulated secret is 32 bytes')
    t.alike(ss2, sharedSecret, alg + ' shared secrets match')
  }
})

test('ml-dsa keygen produces exact FIPS 204 byte sizes', function (t) {
  for (const alg of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
    const p = pq.constants[alg]
    const kp = pq.mldsa.keygen(alg)
    t.is(kp.publicKey.byteLength, p.publicKeyBytes, alg + ' publicKey size')
    t.is(kp.secretKey.byteLength, p.secretKeyBytes, alg + ' secretKey size')
  }
})

test('ml-dsa sign/verify roundtrip is true; tampering fails', function (t) {
  for (const alg of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
    const p = pq.constants[alg]
    const kp = pq.mldsa.keygen(alg)
    const msg = b4a.from('the sovereign stack — ' + alg)
    const sig = pq.mldsa.sign(msg, kp.secretKey, alg)
    t.is(sig.byteLength, p.signatureBytes, alg + ' signature size')
    t.is(pq.mldsa.verify(sig, msg, kp.publicKey, alg), true, alg + ' valid signature verifies')

    // flip one bit of the signature
    const badSig = b4a.from(sig)
    badSig[10] ^= 0x01
    t.is(pq.mldsa.verify(badSig, msg, kp.publicKey, alg), false, alg + ' flipped-bit signature rejected')

    // wrong message
    const wrongMsg = b4a.from('the sovereign stack — tampered')
    t.is(pq.mldsa.verify(sig, wrongMsg, kp.publicKey, alg), false, alg + ' wrong message rejected')
  }
})

test('unknown algorithm and bad input sizes throw honestly', function (t) {
  t.exception(() => pq.mlkem.keygen('ML-KEM-9000'), /unknown algorithm/)
  t.exception(() => pq.mlkem.encapsulate(b4a.alloc(4)), /must be 1184 bytes/)
  t.exception(() => pq.mlkem.decapsulate(b4a.alloc(4), b4a.alloc(2400)), /must be 1088 bytes/)
  t.exception(() => pq.mldsa.keygen('ML-DSA-9000'), /unknown algorithm/)
  t.exception(() => pq.mldsa.sign(b4a.from('msg'), b4a.alloc(4)), /secret key must be 4032 bytes/)
  t.exception(() => pq.mldsa.verify(b4a.alloc(64), b4a.from('msg'), b4a.alloc(1952)), /must be 3309 bytes/)
})
