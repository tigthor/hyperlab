const test = require('brittle')
const gf = require('../gf')

test('exp/log tables are a bijection over the non-zero field', function (t) {
  const seen = new Set()
  for (let a = 1; a < 256; a++) {
    const e = gf.EXP[gf.LOG[a]]
    t.is(e, a, 'exp(log(a)) === a for a=' + a)
    seen.add(gf.EXP[a === 255 ? 254 : a % 255])
  }
  // every non-zero element is hit exactly once by EXP[0..254]
  const hit = new Set()
  for (let i = 0; i < 255; i++) hit.add(gf.EXP[i])
  t.is(hit.size, 255, 'EXP[0..254] enumerates all 255 non-zero elements')
})

test('a * inv(a) === 1 for every non-zero a', function (t) {
  for (let a = 1; a < 256; a++) {
    t.is(gf.mul(a, gf.inv(a)), 1, a + ' * inv(' + a + ') === 1')
  }
})

test('0 has no inverse and division by 0 throws', function (t) {
  t.exception(() => gf.inv(0), /no inverse/)
  t.exception(() => gf.div(5, 0), /division by 0/)
})

test('mul is commutative, associative, distributive; div inverts mul', function (t) {
  const samples = [1, 2, 3, 7, 17, 42, 99, 128, 200, 255]
  for (const a of samples) {
    for (const b of samples) {
      t.is(gf.mul(a, b), gf.mul(b, a), 'commutative')
      if (b !== 0) t.is(gf.div(gf.mul(a, b), b), a, 'div undoes mul')
      for (const cc of samples) {
        t.is(gf.mul(gf.mul(a, b), cc), gf.mul(a, gf.mul(b, cc)), 'associative')
        // a*(b+c) === a*b + a*c   (+ is XOR in GF(2^8))
        t.is(gf.mul(a, b ^ cc), gf.mul(a, b) ^ gf.mul(a, cc), 'distributive')
      }
    }
  }
})

test('mul by 0 is 0', function (t) {
  for (let a = 0; a < 256; a++) {
    t.is(gf.mul(a, 0), 0)
    t.is(gf.mul(0, a), 0)
  }
})
