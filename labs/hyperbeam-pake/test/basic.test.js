const test = require('brittle')
const b4a = require('b4a')

const { CPace, createPakeBeam, topicFromPassphrase, deriveGenerator, constants } = require('..')

test('module loads with expected api surface', function (t) {
  t.is(typeof CPace, 'function')
  t.is(typeof createPakeBeam, 'function')
  t.is(typeof topicFromPassphrase, 'function')
  t.is(typeof deriveGenerator, 'function')
  t.is(constants.MSGBYTES, 32)
  t.is(constants.KEYBYTES, 32)
})

test('cpace roundtrip: same passphrase derives the same key', function (t) {
  const sid = b4a.alloc(16).fill(7)
  const a = new CPace('bright-otter-42', { isInitiator: true, sid })
  const b = new CPace('bright-otter-42', { isInitiator: false, sid })

  const msgA = a.start()
  const msgB = b.start()
  t.is(msgA.byteLength, 32)
  t.is(msgB.byteLength, 32)
  t.unlike(msgA, msgB, 'fresh scalars, distinct messages')

  const k1 = a.finish(msgB)
  const k2 = b.finish(msgA)
  t.is(k1.byteLength, 32)
  t.alike(k1, k2, 'both sides derive the same session key')
})

test('cpace: wrong passphrase completes but derives a different key', function (t) {
  const sid = b4a.alloc(16).fill(7)
  const honest = new CPace('bright-otter-42', { isInitiator: true, sid })
  const mitm = new CPace('wrong-guess-13', { isInitiator: false, sid })

  const msgH = honest.start()
  const msgM = mitm.start()

  const k1 = honest.finish(msgM)
  const k2 = mitm.finish(msgH)
  t.unlike(k1, k2, 'one online guess buys nothing')
})

test('cpace: same passphrase, different sid, different key', function (t) {
  const a = new CPace('pass', { isInitiator: true, sid: b4a.alloc(16).fill(1) })
  const b = new CPace('pass', { isInitiator: false, sid: b4a.alloc(16).fill(2) })
  const msgA = a.start()
  const msgB = b.start()
  t.unlike(a.finish(msgB), b.finish(msgA), 'sid is bound into the key')
})

test('cpace exchanges are unlinkable across runs', function (t) {
  const sid = b4a.alloc(16)
  const run1 = new CPace('pass', { isInitiator: true, sid }).start()
  const run2 = new CPace('pass', { isInitiator: true, sid }).start()
  t.unlike(run1, run2, 'fresh scalar per session — transcript leaks nothing static')
})

test('cpace input validation and state machine', function (t) {
  const sid = b4a.alloc(16)
  t.exception(() => new CPace('', { isInitiator: true }), /non-empty/)
  t.exception(() => new CPace('pass'), /isInitiator/)

  const s = new CPace('pass', { isInitiator: true, sid })
  t.exception(() => s.finish(b4a.alloc(32)), /call start/)
  s.start()
  t.exception(() => s.start(), /already called/)
  t.exception(() => s.finish(b4a.alloc(4)), /32-byte/)
})

test('cpace rejects the identity element (all-zero ristretto encoding)', function (t) {
  const sid = b4a.alloc(16)
  const s = new CPace('pass', { isInitiator: true, sid })
  s.start()
  // The all-zero 32-byte string is the canonical encoding of the ristretto255
  // identity — it decodes, so we must reject it explicitly, not rely on a
  // decode failure.
  t.exception(() => s.finish(b4a.alloc(32)), /identity\/low-order element/)
})

test('cpace rejects a non-canonical / garbage peer element', function (t) {
  const sid = b4a.alloc(16)
  const s = new CPace('pass', { isInitiator: true, sid })
  s.start()
  const garbage = b4a.alloc(32).fill(0xff) // not a valid ristretto255 encoding
  t.exception(() => s.finish(garbage), /non-canonical encoding/)
})

test('cpace determinism: injected fixed rng yields a known ISK (KAT)', function (t) {
  const sid = b4a.alloc(16).fill(0x5a)
  const mkRng = (byte) => (buf) => { for (let i = 0; i < buf.byteLength; i++) buf[i] = (byte + i) & 0xff }
  const a = new CPace('known-answer-pass', { isInitiator: true, sid, rng: mkRng(0x11) })
  const b = new CPace('known-answer-pass', { isInitiator: false, sid, rng: mkRng(0x22) })

  const msgA = a.start()
  const msgB = b.start()
  t.is(b4a.toString(msgA, 'hex'), '38aa2715231076497cff31c2b2a04eed7221337555e33236e7b5da2dbc61e549', 'Ya is deterministic under the injected rng')
  t.is(b4a.toString(msgB, 'hex'), '944ee193f5e5c6aa398a5496174dfe0aeb44b13e2b68162673617c4ae5665902', 'Yb is deterministic under the injected rng')

  const k1 = a.finish(msgB)
  const k2 = b.finish(msgA)
  t.alike(k1, k2, 'both sides agree')
  t.is(b4a.toString(k1, 'hex'), '9a470575cb056cf533eb0b68974b4b7bdc2c411d318841f78bc1e5f87dfca589', 'ISK matches the recorded known answer')
})

test('cpace generator is a valid prime-order element (no cofactor caveat)', function (t) {
  const sid = b4a.alloc(16)
  const g = deriveGenerator(b4a.from('pass'), sid)
  t.is(g.byteLength, 32)
  t.alike(g, deriveGenerator(b4a.from('pass'), sid), 'deterministic in (passphrase, sid)')
  t.unlike(g, deriveGenerator(b4a.from('pass'), b4a.alloc(16).fill(1)), 'sid changes the generator')
  t.unlike(g, deriveGenerator(b4a.from('other'), sid), 'passphrase changes the generator')
})

test('topic derivation is real and key-independent', function (t) {
  const topic = topicFromPassphrase('bright-otter-42')
  t.is(topic.byteLength, 32)
  t.alike(topic, topicFromPassphrase('bright-otter-42'))
  t.unlike(topic, topicFromPassphrase('other'))

  const sid = b4a.alloc(16)
  t.unlike(topic, deriveGenerator(b4a.from('bright-otter-42'), sid), 'separate namespaces')
})

test('wire integration throws honestly', function (t) {
  t.exception(() => createPakeBeam('bright-otter-42'), /not implemented/)
  t.exception(() => createPakeBeam(''), /non-empty/)
})
