const test = require('brittle')
const b4a = require('b4a')
const crypto = require('crypto')

const pq = require('..')

// Known-answer tests.
//
// Honesty note: @noble/post-quantum does NOT ship the NIST ACVP/KAT response
// files inside the installed npm package (only compiled JS + TS source, no
// vector fixtures). Rather than fabricate external vectors we cannot verify,
// these KATs pin the DETERMINISTIC outputs of the seeded APIs: ML-KEM and
// ML-DSA keygen from a fixed seed, and ML-KEM encapsulation from fixed coins,
// are reproducible by construction (FIPS 203 K-PKE.KeyGen / FIPS 204 KeyGen
// derive everything from the seed). The pinned hashes below were captured once
// from this backend; any drift in the underlying implementation will flip
// these tests, which is exactly the regression signal a KAT provides.
//
// These are self-consistency KATs against a captured reference, NOT NIST ACVP
// conformance vectors. Full ACVP conformance would require importing NIST's
// published .json fixtures (out of scope here).

const sha = x => crypto.createHash('sha256').update(x).digest('hex')

test('ML-KEM-768 deterministic keygen KAT (fixed 64-byte seed)', function (t) {
  const seed = b4a.alloc(64, 0x2a)
  const kp = pq.mlkem.keygen('ML-KEM-768', seed)
  t.is(kp.publicKey.byteLength, 1184, 'publicKey size')
  t.is(kp.secretKey.byteLength, 2400, 'secretKey size')
  t.is(sha(kp.publicKey), '61478b1d7a03527d8a2fa89ff7de964779a8d8a83492060282da375068dec694', 'publicKey KAT')
  t.is(sha(kp.secretKey), 'f222a0eeb1ad5cad6c118b9737982c3a16b1217aa3555cbc5ec4be492a9480cb', 'secretKey KAT')

  // determinism: same seed -> identical key
  const kp2 = pq.mlkem.keygen('ML-KEM-768', seed)
  t.alike(kp2.publicKey, kp.publicKey, 'seed is deterministic')
})

test('ML-KEM-768 deterministic encapsulation KAT (fixed coins) + decaps roundtrip', function (t) {
  const seed = b4a.alloc(64, 0x2a)
  const coins = b4a.alloc(32, 0x07)
  const kp = pq.mlkem.keygen('ML-KEM-768', seed)
  const enc = pq.mlkem.encapsulate(kp.publicKey, 'ML-KEM-768', coins)
  t.is(enc.ciphertext.byteLength, 1088, 'ciphertext size')
  t.is(enc.sharedSecret.byteLength, 32, 'shared secret size')
  t.is(sha(enc.ciphertext), '53e147f660a3ac9828a4429e9aa2029d3ede8d958d5216ce209bace9956adebe', 'ciphertext KAT')
  t.is(b4a.toString(enc.sharedSecret, 'hex'), '891fec1fd2bc58dbc53e9f3aa8772448a08070a5495dd64c9623df46fdcbd791', 'shared secret KAT')

  // decapsulation must recover the exact same shared secret
  const ss = pq.mlkem.decapsulate(enc.ciphertext, kp.secretKey, 'ML-KEM-768')
  t.alike(ss, enc.sharedSecret, 'decaps recovers KAT shared secret')
})

test('ML-DSA-65 deterministic keygen KAT (fixed 32-byte seed)', function (t) {
  const seed = b4a.alloc(32, 0x11)
  const kp = pq.mldsa.keygen('ML-DSA-65', seed)
  t.is(kp.publicKey.byteLength, 1952, 'publicKey size')
  t.is(kp.secretKey.byteLength, 4032, 'secretKey size')
  t.is(sha(kp.publicKey), '0575d15a041b8b573635522018f2d25d0cc1c1d6d5295da66c52e12bc29402fc', 'publicKey KAT')
  t.is(sha(kp.secretKey), '1913cc43b103bfc18030276e6a2c8df2403f2c34b87a3751be23cc7935bbb95a', 'secretKey KAT')

  // a signature under these pinned keys must verify (sign is hedged/randomized,
  // so we cannot pin the signature bytes, but we can pin the keypair)
  const msg = b4a.from('kat-message')
  const sig = pq.mldsa.sign(msg, kp.secretKey, 'ML-DSA-65')
  t.is(sig.byteLength, 3309, 'signature size')
  t.is(pq.mldsa.verify(sig, msg, kp.publicKey, 'ML-DSA-65'), true, 'signature under pinned keys verifies')
})
