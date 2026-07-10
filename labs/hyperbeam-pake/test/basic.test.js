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
  t.exception(() => s.finish(b4a.alloc(32)), /invalid remote/) // all-zero is not a valid point
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
