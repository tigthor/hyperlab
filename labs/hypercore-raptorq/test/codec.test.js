const test = require('brittle')
const b4a = require('b4a')
const { Encoder, Decoder } = require('..')

// deterministic pseudo-random block content
function makeBlocks (k, size, seed = 1) {
  let s = (seed >>> 0) || 1
  const rng = () => {
    s ^= s << 13; s >>>= 0
    s ^= s >>> 17
    s ^= s << 5; s >>>= 0
    return s & 0xff
  }
  const out = []
  for (let i = 0; i < k; i++) {
    const b = b4a.alloc(size)
    for (let j = 0; j < size; j++) b[j] = rng()
    out.push(b)
  }
  return out
}

test('systematic symbols are the source blocks verbatim (no-loss = passthrough)', function (t) {
  const blocks = makeBlocks(16, 512, 7)
  const enc = new Encoder(blocks)
  for (let esi = 0; esi < enc.k; esi++) {
    t.ok(b4a.equals(enc.symbol(esi), blocks[esi]), 'symbol ' + esi + ' === source ' + esi)
  }
})

test('decode from the k systematic symbols reconstructs the source', function (t) {
  const blocks = makeBlocks(32, 256, 11)
  const enc = new Encoder(blocks)
  const dec = new Decoder(enc.k, { symbolSize: enc.symbolSize })

  let ready = false
  for (const m of enc.systematicSymbols()) ready = dec.add(m)
  t.ok(ready, 'decodable after k systematic symbols')

  const out = dec.decode()
  t.is(out.length, blocks.length)
  for (let i = 0; i < blocks.length; i++) {
    t.ok(b4a.equals(out[i], blocks[i]), 'block ' + i + ' matches')
  }
})

test('decode from exactly k independent symbols (repair-only) reconstructs', function (t) {
  const k = 24
  const blocks = makeBlocks(k, 400, 23)
  const enc = new Encoder(blocks)
  const dec = new Decoder(k, { symbolSize: enc.symbolSize })

  // feed only repair symbols (esi >= k): pure random linear combinations
  let esi = k
  while (!dec.decodable) {
    dec.add(enc.message(esi++))
    if (esi > k + 500) break // guard
  }
  t.ok(dec.decodable, 'reached rank k from repair symbols')
  t.ok(esi - k <= k + 3, 'needed ~k symbols (' + (esi - k) + ' for k=' + k + ')')

  const out = dec.decode()
  for (let i = 0; i < k; i++) t.ok(b4a.equals(out[i], blocks[i]), 'block ' + i)
})

test('any k of a mixed systematic+repair stream reconstructs, dropping ~15%', function (t) {
  const k = 64
  const blocks = makeBlocks(k, 1024, 99)
  const enc = new Encoder(blocks)

  // build a stream: k systematic + plenty of repair
  const stream = enc.systematicSymbols().concat(enc.repairSymbols(40))

  // drop a random ~15% of the stream deterministically
  let s = 0x1234abcd
  const rng = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 0xffffffff }
  const kept = stream.filter(() => rng() > 0.15)

  const dec = new Decoder(k, { symbolSize: enc.symbolSize })
  let ready = false
  let used = 0
  for (const m of kept) {
    used++
    if (dec.add(m)) { ready = true; break }
  }
  t.ok(ready, 'decodable after ~15% loss using ' + used + '/' + kept.length + ' kept symbols')

  const out = dec.decode()
  for (let i = 0; i < k; i++) t.ok(b4a.equals(out[i], blocks[i]), 'block ' + i)
})

test('variable-length blocks round-trip via lengths', function (t) {
  const blocks = [b4a.from('hello'), b4a.from('a longer block of bytes'), b4a.from('x')]
  const enc = new Encoder(blocks)
  const dec = new Decoder(enc.k, { symbolSize: enc.symbolSize, lengths: enc.lengths })
  for (const m of enc.repairSymbols(enc.k + 2)) if (dec.add(m)) break
  const out = dec.decode()
  for (let i = 0; i < blocks.length; i++) t.ok(b4a.equals(out[i], blocks[i]), 'block ' + i)
})

test('decode() throws before rank k; extra symbols after decodable are harmless', function (t) {
  const blocks = makeBlocks(8, 64, 3)
  const enc = new Encoder(blocks)
  const dec = new Decoder(enc.k, { symbolSize: enc.symbolSize })
  t.exception(() => dec.decode(), /need k independent symbols/)
  const sys = enc.systematicSymbols()
  for (let i = 0; i < enc.k - 1; i++) dec.add(sys[i])
  t.absent(dec.decodable, 'not decodable at k-1')
  dec.add(sys[enc.k - 1])
  t.ok(dec.decodable)
  // feeding more does not corrupt state
  dec.add(enc.message(enc.k))
  const out = dec.decode()
  for (let i = 0; i < enc.k; i++) t.ok(b4a.equals(out[i], blocks[i]))
})
