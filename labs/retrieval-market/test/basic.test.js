const test = require('brittle')
const b4a = require('b4a')

const rm = require('..')

function fixtures () {
  const provider = rm.keyPair(b4a.alloc(32).fill(1))
  const consumer = rm.keyPair(b4a.alloc(32).fill(2))
  const channel = b4a.alloc(32).fill(3)
  return { provider, consumer, channel }
}

test('module loads with expected api surface', function (t) {
  t.is(typeof rm.keyPair, 'function')
  t.is(typeof rm.createReceipt, 'function')
  t.is(typeof rm.signReceipt, 'function')
  t.is(typeof rm.verifyReceipt, 'function')
  t.is(typeof rm.encodeReceipt, 'function')
  t.is(typeof rm.decodeReceipt, 'function')
  t.is(typeof rm.aggregate, 'function')
  t.is(typeof rm.settle, 'function')
  t.is(rm.constants.VERSION, 1)
  t.is(rm.constants.SIGNATURE_BYTES, 64)
})

test('receipt sign/verify roundtrip', function (t) {
  const { provider, consumer, channel } = fixtures()

  const receipt = rm.createReceipt({
    provider: provider.publicKey,
    consumer: consumer.publicKey,
    channel,
    bytes: 65536,
    sequence: 1,
    timestamp: 1752105600000
  })

  const signed = rm.signReceipt(receipt, consumer.secretKey)
  t.is(signed.signature.byteLength, 64)
  t.ok(rm.verifyReceipt(signed), 'valid receipt verifies')

  t.absent(rm.verifyReceipt({ ...signed, bytes: 999999 }), 'tampered bytes fails')
  t.absent(rm.verifyReceipt({ ...signed, provider: consumer.publicKey }), 'tampered provider fails')

  const forged = rm.signReceipt(receipt, provider.secretKey) // wrong signer
  t.absent(rm.verifyReceipt(forged), 'receipt not signed by consumer fails')
})

test('receipt encode/decode roundtrip survives the wire', function (t) {
  const { provider, consumer, channel } = fixtures()

  const signed = rm.signReceipt(rm.createReceipt({
    provider: provider.publicKey,
    consumer: consumer.publicKey,
    channel,
    bytes: 123456789,
    sequence: 42,
    timestamp: 1752105600000
  }), consumer.secretKey)

  const buf = rm.encodeReceipt(signed)
  t.ok(buf.byteLength < 256, 'receipt is compact (' + buf.byteLength + ' bytes)')

  const back = rm.decodeReceipt(buf)
  t.alike(back, signed, 'decode(encode(r)) === r')
  t.ok(rm.verifyReceipt(back), 'still verifies after the roundtrip')
})

test('createReceipt validates input', function (t) {
  const { provider, consumer, channel } = fixtures()
  const base = { provider: provider.publicKey, consumer: consumer.publicKey, channel, bytes: 1, sequence: 0 }

  t.exception(() => rm.createReceipt({ ...base, provider: b4a.alloc(4) }), /provider must be a 32-byte buffer/)
  t.exception(() => rm.createReceipt({ ...base, bytes: -1 }), /bytes must be/)
  t.exception(() => rm.createReceipt({ ...base, sequence: 1.5 }), /sequence must be/)
  t.exception(() => rm.signReceipt(rm.createReceipt(base), b4a.alloc(3)), /secretKey must be/)
})

test('aggregate keeps highest cumulative receipt per channel', function (t) {
  const { provider, consumer, channel } = fixtures()
  const channel2 = b4a.alloc(32).fill(9)

  const mk = (chan, bytes, sequence) => rm.signReceipt(rm.createReceipt({
    provider: provider.publicKey,
    consumer: consumer.publicKey,
    channel: chan,
    bytes,
    sequence
  }), consumer.secretKey)

  const receipts = [mk(channel, 100, 1), mk(channel, 300, 3), mk(channel, 200, 2), mk(channel2, 50, 1)]
  const { claims, totalBytes, invalid } = rm.aggregate(receipts)

  t.is(claims.length, 2, 'one claim per channel')
  t.is(totalBytes, 350, 'cumulative: 300 + 50, not the sum of every receipt')
  t.is(invalid, 0)

  const tampered = { ...mk(channel, 400, 4), bytes: 4000 }
  t.exception(() => rm.aggregate([...receipts, tampered]), /invalid receipt signature/)

  const lax = rm.aggregate([...receipts, tampered], { strict: false })
  t.is(lax.invalid, 1, 'lax mode drops and counts bad receipts')
  t.is(lax.totalBytes, 350)
})

test('settlement throws honestly', async function (t) {
  await t.exception(() => rm.settle({ claims: [] }), /not implemented/)
})
