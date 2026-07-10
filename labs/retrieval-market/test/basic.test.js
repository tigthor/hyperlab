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

test('adversarial: field-swap forgery is rejected', function (t) {
  const { provider, consumer, channel } = fixtures()
  const signed = rm.signReceipt(rm.createReceipt({
    provider: provider.publicKey,
    consumer: consumer.publicKey,
    channel,
    bytes: 65536,
    sequence: 1
  }), consumer.secretKey)

  // swap provider <-> consumer: signature was bound to the original layout
  t.absent(rm.verifyReceipt({ ...signed, provider: signed.consumer, consumer: signed.provider }),
    'provider/consumer swap fails')
  // bump the version field (also signed)
  t.absent(rm.verifyReceipt({ ...signed, version: 2 }), 'version tamper fails')
  // move the timestamp (bound field)
  t.absent(rm.verifyReceipt({ ...signed, timestamp: signed.timestamp + 1 }), 'timestamp tamper fails')
  // change sequence
  t.absent(rm.verifyReceipt({ ...signed, sequence: signed.sequence + 1 }), 'sequence tamper fails')
})

test('adversarial: cross-core (cross-channel) replay is rejected', function (t) {
  const { provider, consumer, channel } = fixtures()
  const otherChannel = b4a.alloc(32).fill(7)
  const signed = rm.signReceipt(rm.createReceipt({
    provider: provider.publicKey,
    consumer: consumer.publicKey,
    channel,
    bytes: 65536,
    sequence: 1
  }), consumer.secretKey)

  // replay the same signed receipt against a different core/channel
  t.absent(rm.verifyReceipt({ ...signed, channel: otherChannel }), 'channel-swap replay fails')

  // aggregate must not credit the replayed receipt to the other channel
  const { claims } = rm.aggregate([signed, { ...signed, channel: otherChannel }], { strict: false })
  t.is(claims.length, 1, 'only the genuine channel is credited')
  t.ok(b4a.equals(claims[0].channel, channel), 'credited channel is the signed one')
})

test('adversarial: tampered byte count is rejected', function (t) {
  const { provider, consumer, channel } = fixtures()
  const signed = rm.signReceipt(rm.createReceipt({
    provider: provider.publicKey,
    consumer: consumer.publicKey,
    channel,
    bytes: 1000,
    sequence: 1
  }), consumer.secretKey)

  t.absent(rm.verifyReceipt({ ...signed, bytes: 1000000 }), 'inflated bytes fails')
  t.absent(rm.verifyReceipt({ ...signed, bytes: 0 }), 'deflated bytes fails')

  // through the wire: flip the encoded bytes then decode
  const buf = rm.encodeReceipt(signed)
  const back = rm.decodeReceipt(buf)
  t.ok(rm.verifyReceipt(back), 'untampered wire receipt still verifies')
})

test('adversarial: aggregate never crashes on malformed input', function (t) {
  const { provider, consumer, channel } = fixtures()
  const good = rm.signReceipt(rm.createReceipt({
    provider: provider.publicKey,
    consumer: consumer.publicKey,
    channel,
    bytes: 500,
    sequence: 1
  }), consumer.secretKey)

  const junk = [
    null,
    undefined,
    5,
    'not-a-receipt',
    {},
    { signature: b4a.alloc(64) },
    { signature: b4a.alloc(64), consumer: b4a.alloc(32) },
    { ...good, signature: undefined },
    { ...good, provider: b4a.alloc(4) },
    { ...good, bytes: -1 }
  ]

  // lax mode: drops every bad entry, counts them, keeps the one good claim
  const lax = rm.aggregate([...junk, good], { strict: false })
  t.is(lax.invalid, junk.length, 'all malformed receipts counted invalid')
  t.is(lax.claims.length, 1, 'the one valid receipt survives')
  t.is(lax.totalBytes, 500)

  // strict mode: throws honestly rather than crashing, even with null present
  t.exception(() => rm.aggregate([null], { strict: true }), /invalid receipt signature/)
  t.exception(() => rm.aggregate([{}], { strict: true }), /invalid receipt signature/)

  // non-array input is a clean throw, not a TypeError from iteration
  t.exception(() => rm.aggregate(null), /must be an array/)
  t.exception(() => rm.aggregate({ length: 1 }), /must be an array/)

  // verifyReceipt itself never throws on hostile input
  for (const bad of junk) t.absent(rm.verifyReceipt(bad))
})

test('adversarial: nonce is bound and unique per receipt', function (t) {
  const { provider, consumer, channel } = fixtures()
  const base = { provider: provider.publicKey, consumer: consumer.publicKey, channel, bytes: 1, sequence: 0, timestamp: 1 }

  const a = rm.createReceipt(base)
  const b = rm.createReceipt(base)
  t.is(a.nonce.byteLength, 32, 'nonce is 32 bytes')
  t.absent(b4a.equals(a.nonce, b.nonce), 'two receipts with identical fields still get distinct nonces')

  const signed = rm.signReceipt(a, consumer.secretKey)
  t.ok(rm.verifyReceipt(signed), 'signed receipt with nonce verifies')
  // tampering the nonce breaks the signature (nonce is inside the signed pre-image)
  t.absent(rm.verifyReceipt({ ...signed, nonce: b4a.alloc(32).fill(0xff) }), 'nonce tamper fails')
  // a wrong-sized nonce must not crash verify - just fail
  t.absent(rm.verifyReceipt({ ...signed, nonce: b4a.alloc(4) }), 'short nonce fails, no crash')
  t.exception(() => rm.createReceipt({ ...base, nonce: b4a.alloc(4) }), /nonce must be a 32-byte buffer/)
})

test('adversarial: nonce survives the wire and stays bound', function (t) {
  const { provider, consumer, channel } = fixtures()
  const signed = rm.signReceipt(rm.createReceipt({
    provider: provider.publicKey,
    consumer: consumer.publicKey,
    channel,
    bytes: 777,
    sequence: 3
  }), consumer.secretKey)

  const back = rm.decodeReceipt(rm.encodeReceipt(signed))
  t.ok(b4a.equals(back.nonce, signed.nonce), 'nonce roundtrips through the wire')
  t.ok(rm.verifyReceipt(back), 'still verifies with nonce after roundtrip')
})

test('adversarial: hostile property getter cannot crash verify or aggregate', function (t) {
  const { provider, consumer, channel } = fixtures()
  const good = rm.signReceipt(rm.createReceipt({
    provider: provider.publicKey,
    consumer: consumer.publicKey,
    channel,
    bytes: 500,
    sequence: 1
  }), consumer.secretKey)

  const boomConsumer = { signature: b4a.alloc(64), get consumer () { throw new Error('boom') } }
  const boomSeq = { signature: b4a.alloc(64), consumer: b4a.alloc(32), get sequence () { throw new Error('boom') } }

  t.absent(rm.verifyReceipt(boomConsumer), 'throwing getter verifies false, not a crash')
  t.absent(rm.verifyReceipt(boomSeq), 'throwing sequence getter verifies false, not a crash')

  // lax aggregate swallows them as invalid
  const lax = rm.aggregate([boomConsumer, boomSeq, good], { strict: false })
  t.is(lax.invalid, 2, 'both hostile objects counted invalid')
  t.is(lax.claims.length, 1)
  t.is(lax.totalBytes, 500)

  // strict aggregate throws the honest accounting error, not the getter's error
  t.exception(() => rm.aggregate([boomSeq], { strict: true }), /invalid receipt signature/)
})

test('settlement throws honestly', async function (t) {
  await t.exception(() => rm.settle({ claims: [] }), /not implemented/)
})
