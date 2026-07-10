# hyperbeam-pake

**Research ID: BEAM-1** (research invention BEAM-E1)

CPace PAKE rendezvous for hyperbeam — a low-entropy human passphrase that resists offline dictionary attacks and first-come-first-served MITM. The showcase win.

## Why

Hyperbeam's passphrase is a shared symmetric secret in the URL/CLI: both sides derive the discovery topic *and* the Noise keypair directly from it, so anyone who observes or guesses the passphrase can MITM by racing to the topic, and any recorded exchange can be ground offline against a dictionary — fatal for human-memorable phrases. The research names PAKE-based rendezvous "the single biggest security upgrade" for hyperbeam: replace passphrase-to-keypair derivation with a balanced PAKE (CPace), so the passphrase only *authenticates* a fresh Diffie-Hellman exchange. An attacker gets exactly one online guess per rendezvous, and the transcript leaks nothing that helps an offline attack.

## API

```js
const { CPace, createPakeBeam, topicFromPassphrase, constants } = require('hyperbeam-pake')

// real today: the CPace exchange itself
const a = new CPace('bright-otter-42', { isInitiator: true, sid })
const b = new CPace('bright-otter-42', { isInitiator: false, sid })
const msgA = a.start() // 32 bytes on the wire, each way
const msgB = b.start()
const k1 = a.finish(msgB)
const k2 = b.finish(msgA) // k1 equals k2 iff passphrases (and sid) match

// real today: rendezvous topic (key-independent namespace)
const topic = topicFromPassphrase('bright-otter-42')

// throws 'not implemented': the wire integration
const beam = createPakeBeam('bright-otter-42')
```

Prototype notes: the group is ed25519 with the cofactor cleared via libsodium's Elligator map (`crypto_core_ed25519_from_uniform`) because `sodium-universal` does not expose ristretto255, which the CPace RFC draft specifies. The session id (`sid`) should come from the rendezvous (e.g. sorted connection nonces). Not audited for side channels — prototype-grade only.

## Acceptance gate

- **Security property (the point):** a MITM racing to the topic without the passphrase must be limited to one online guess per rendezvous, and a recorded transcript must be useless for offline dictionary attack — demonstrated by test: wrong-passphrase exchanges complete but yield non-matching keys, and the transcript (two 32-byte group elements) is independent of the passphrase given fresh scalars.
- **UX parity:** connect latency within ~1 RTT of stock hyperbeam (CPace piggybacks on the messages the rendezvous already exchanges).
- Interop: the upgraded beam must still be a plain Duplex stream (`stdin | beam | stdout` unchanged).

## Status

Skeleton with a real core: the CPace exchange and topic derivation work and are tested (matching and non-matching passphrase cases); `createPakeBeam` throws `not implemented` pending the DHT rendezvous and SecretStream rekey plumbing.
