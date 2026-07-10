const test = require('brittle')
const b4a = require('b4a')
const c = require('compact-encoding')
const Hypercore = require('hypercore')

const rq = require('..')

const eventFlush = () => new Promise((resolve) => setImmediate(resolve))

test('module loads with expected api surface', function (t) {
  t.is(typeof rq.attach, 'function')
  t.is(typeof rq.Encoder, 'function')
  t.is(typeof rq.Decoder, 'function')
  t.is(typeof rq.symbolEncoding.encode, 'function')
  t.is(rq.constants.EXTENSION_NAME, 'hyperlab/raptorq')
  t.is(rq.constants.DEFAULT_SYMBOL_SIZE, 1024)
})

test('symbol message roundtrips through compact-encoding', function (t) {
  const m = { group: 42, esi: 17, k: 16, symbol: b4a.from('repair bytes') }
  const buf = c.encode(rq.symbolEncoding, m)
  t.alike(c.decode(rq.symbolEncoding, buf), m)
})

test('encoder/decoder honest skeleton', function (t) {
  const blocks = [b4a.from('a'), b4a.from('b')]
  const enc = new rq.Encoder(blocks)
  t.is(enc.k, 2)
  t.exception(() => enc.symbol(3), /not implemented/)
  t.exception(() => enc.repairSymbols(2), /not implemented/)
  t.exception(() => new rq.Encoder([]), /non-empty array/)

  const dec = new rq.Decoder(2)
  t.is(dec.add({ esi: 0, symbol: b4a.from('x') }), false)
  t.is(dec.add({ esi: 5, symbol: b4a.from('y') }), true)
  t.exception(() => dec.decode(), /not implemented/)
  t.exception(() => new rq.Decoder(2).decode(), /need at least k symbols/)
})

test('symbols flow over live hypercore replication', async function (t) {
  t.plan(3)

  const a = new Hypercore(await t.tmp())
  await a.ready()
  const b = new Hypercore(await t.tmp(), a.key)
  await b.ready()

  t.teardown(async () => {
    await a.close()
    await b.close()
  })

  await a.append(['block0', 'block1'])

  const sent = { group: 0, esi: 2, k: 2, symbol: b4a.from('fake repair symbol') }

  rq.attach(a, {
    onsymbol (message, peer) {
      t.alike(message, sent, 'symbol arrived intact')
      t.ok(peer === a.peers[0], 'delivered with the sending peer')
    }
  })
  const rqb = rq.attach(b)

  const s1 = a.replicate(true, { keepAlive: false })
  const s2 = b.replicate(false, { keepAlive: false })
  s1.pipe(s2).pipe(s1)
  t.teardown(() => {
    s1.destroy()
    s2.destroy()
  })

  await eventFlush()
  t.is(b.peers.length, 1, 'peers connected')

  rqb.send(sent, b.peers[0])
  await eventFlush()
})

test('attach validates its target', function (t) {
  t.exception(() => rq.attach({}), /expects a hypercore/)
})
