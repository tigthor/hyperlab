// GF(256) arithmetic for the random-linear fountain codec.
//
// Field: bytes as elements of GF(2^8) with the reducing polynomial
// x^8 + x^4 + x^3 + x^2 + 1 (0x11d) and primitive element alpha = 2 — the
// same field RaptorQ (RFC 6330) and Reed-Solomon codecs use, so mul/inv are
// standard log/exp table lookups. This is real finite-field math, not a
// placeholder: a*inv(a) === 1 for every non-zero a (checked in test/gf.test).

const POLY = 0x11d
const GENERATOR = 2

const EXP = new Uint8Array(512)
const LOG = new Uint8Array(256)

;(function buildTables () {
  let x = 1
  for (let i = 0; i < 255; i++) {
    EXP[i] = x
    LOG[x] = i
    // x = x * GENERATOR in GF(256)
    x = mulBy(x, GENERATOR)
  }
  // duplicate so EXP[a+b] needs no modulo for a,b in [0,254]
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]
})()

// carry-less multiply of a byte by the generator, reduced by POLY
function mulBy (a, b) {
  let p = 0
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a
    const hi = a & 0x80
    a = (a << 1) & 0xff
    if (hi) a ^= (POLY & 0xff)
    b >>= 1
  }
  return p
}

function mul (a, b) {
  if (a === 0 || b === 0) return 0
  return EXP[LOG[a] + LOG[b]]
}

function inv (a) {
  if (a === 0) throw new Error('GF(256): 0 has no inverse')
  return EXP[255 - LOG[a]]
}

function div (a, b) {
  if (b === 0) throw new Error('GF(256): division by 0')
  if (a === 0) return 0
  return EXP[(LOG[a] - LOG[b] + 255) % 255]
}

// dst[j] ^= factor * src[j], the inner loop of Gaussian elimination.
// Operates on Uint8Array rows in place.
function addScaled (dst, src, factor, len) {
  if (factor === 0) return
  const base = LOG[factor]
  for (let j = 0; j < len; j++) {
    const s = src[j]
    if (s !== 0) dst[j] ^= EXP[base + LOG[s]]
  }
}

// dst[j] = factor * dst[j] in place (row normalization)
function scale (dst, factor, len) {
  if (factor === 1) return
  const base = LOG[factor]
  for (let j = 0; j < len; j++) {
    const s = dst[j]
    dst[j] = s === 0 ? 0 : EXP[base + LOG[s]]
  }
}

module.exports = { mul, inv, div, addScaled, scale, EXP, LOG, POLY, GENERATOR }
