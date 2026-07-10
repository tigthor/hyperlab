// Chapter 4 (HC-C1) — hybrid Ed25519 + ML-DSA-65 signer.
// Verifies: roundtrip true, exact 3373-byte size, and fail-closed behaviour
// when EITHER half of the signature is tampered.

const test = require('brittle')
const b4a = require('b4a')
const { hybridSigner, hybridKeyPair, constants } = require('..')

const ED_BYTES = constants.HYBRID_ED25519_BYTES // 64
const SIG_BYTES = constants.HYBRID_SIG_BYTES // 3373

function root (fill = 0xab) {
  return b4a.alloc(32, fill)
}

test('scheme id and advertised sizes', function (t) {
  const s = hybridSigner()
  t.is(s.scheme, 'hybrid-ed25519-mldsa65')
  t.is(s.signatureBytes, 3373)
  t.is(ED_BYTES, 64)
  t.is(constants.HYBRID_MLDSA_BYTES, 3309)
  t.is(SIG_BYTES, 3373)
})

test('sign produces exactly 3373 bytes (64 ed || 3309 mldsa)', function (t) {
  const s = hybridSigner()
  const sig = s.sign(root())
  t.ok(b4a.isBuffer(sig))
  t.is(sig.byteLength, 3373)
})

test('roundtrip verifies true with both halves intact', function (t) {
  const s = hybridSigner()
  const r = root()
  const sig = s.sign(r)
  t.is(s.verify(r, sig), true)
})

test('verify accepts with explicitly supplied public keys', function (t) {
  const kp = hybridKeyPair()
  const s = hybridSigner(kp)
  const r = root(0x11)
  const sig = s.sign(r)
  t.is(s.verify(r, sig, { ed: kp.ed.publicKey, mldsa: kp.mldsa.publicKey }), true)
})

test('fail-closed: flipping an Ed25519 byte -> false', function (t) {
  const s = hybridSigner()
  const r = root()
  const sig = s.sign(r)
  const tampered = b4a.from(sig)
  tampered[0] ^= 0x01 // inside the classical half [0,64)
  t.is(s.verify(r, tampered), false)
})

test('fail-closed: flipping an ML-DSA byte -> false', function (t) {
  const s = hybridSigner()
  const r = root()
  const sig = s.sign(r)
  const tampered = b4a.from(sig)
  tampered[ED_BYTES + 10] ^= 0x01 // inside the PQ half [64,3373)
  t.is(s.verify(r, tampered), false)
})

test('fail-closed: wrong message -> false', function (t) {
  const s = hybridSigner()
  const sig = s.sign(root(0xaa))
  t.is(s.verify(root(0xbb), sig), false)
})

test('fail-closed: wrong public key on either half -> false', function (t) {
  const a = hybridKeyPair()
  const b = hybridKeyPair()
  const s = hybridSigner(a)
  const r = root()
  const sig = s.sign(r)
  // Wrong ed pubkey, correct mldsa pubkey.
  t.is(s.verify(r, sig, { ed: b.ed.publicKey, mldsa: a.mldsa.publicKey }), false)
  // Correct ed pubkey, wrong mldsa pubkey.
  t.is(s.verify(r, sig, { ed: a.ed.publicKey, mldsa: b.mldsa.publicKey }), false)
})

test('fail-closed: truncated / oversized signature -> false', function (t) {
  const s = hybridSigner()
  const r = root()
  const sig = s.sign(r)
  t.is(s.verify(r, sig.subarray(0, SIG_BYTES - 1)), false)
  t.is(s.verify(r, b4a.concat([sig, b4a.alloc(1)])), false)
  t.is(s.verify(r, b4a.alloc(0)), false)
})

test('fail-closed: missing public-key material -> false', function (t) {
  const s = hybridSigner()
  const r = root()
  const sig = s.sign(r)
  t.is(s.verify(r, sig, { ed: s.publicKey.ed }), false) // no mldsa
  t.is(s.verify(r, sig, {}), false)
})

test('classical-only forgery is rejected (the whole point)', function (t) {
  // An attacker who can only forge the Ed25519 half (e.g. a future quantum
  // adversary against ECC) but pads garbage into the PQ half must fail.
  const s = hybridSigner()
  const r = root()
  const sig = s.sign(r)
  const forged = b4a.from(sig)
  b4a.fill(forged, 0x00, ED_BYTES) // zero out the PQ half entirely
  t.is(s.verify(r, forged), false)
})
