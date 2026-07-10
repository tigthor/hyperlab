// pq-handshake bench (CRYPTO-1 gate)
//
// Claim: "hybrid handshake first message >1KB (needs fragmentation) and adds
// <1ms CPU vs classical".
// Baseline (baselines.full.json handshake): firstMessageBytes=116,
// latencyMsMedian ~2.2ms for the classical X25519 Noise handshake.
//
// We measure two things directly:
//  1. First-message wire size: the bytes an initiator must put on the wire to
//     start the hybrid handshake (X25519 pk 32 + ML-KEM-768 pk 1184 in the
//     interactive pattern) vs the 32-byte classical X25519 ephemeral.
//  2. Added CPU: the wall time of the hybrid crypto (X25519 keygen+dh +
//     ML-KEM keygen/encapsulate/decapsulate + combine) minus a bare X25519 dh.
//
// This benchmarks the crypto object at handshake cadence; it does NOT run the
// full Noise wire (fragmentation + secret-stream integration are not built).

const path = require('path')
const LAB = path.join(__dirname, '..', '..', 'labs', 'pq-secretstream')
const b4a = require(path.join(LAB, 'node_modules', 'b4a'))
const sodium = require(path.join(LAB, 'node_modules', 'sodium-universal'))
const pq = require(LAB)

const REPS = Number(process.argv[2]) || 2000

function now () {
  return Number(process.hrtime.bigint()) / 1e6
}

function median (xs) {
  const s = xs.slice().sort((a, b) => a - b)
  return s[Math.floor(s.length / 2)]
}

// --- classical baseline: the full two-party X25519 handshake cost ----------
// (both peers keygen an ephemeral, both run one DH) — a like-for-like base so
// the hybrid delta isolates the ML-KEM additions rather than a single DH.
function classicalCpu () {
  const t0 = now()
  const iPk = b4a.alloc(32); const iSk = b4a.alloc(32)
  sodium.randombytes_buf(iSk); sodium.crypto_scalarmult_base(iPk, iSk)
  const rPk = b4a.alloc(32); const rSk = b4a.alloc(32)
  sodium.randombytes_buf(rSk); sodium.crypto_scalarmult_base(rPk, rSk)
  const s1 = b4a.alloc(32); const s2 = b4a.alloc(32)
  sodium.crypto_scalarmult(s1, iSk, rPk)
  sodium.crypto_scalarmult(s2, rSk, iPk)
  return now() - t0
}

// --- ML-KEM-768 triple in isolation: keygen + encapsulate + decapsulate ----
function mlkemCpu () {
  const t0 = now()
  const kp = pq.keygen()
  const enc = pq.encapsulate(kp.publicKey)
  pq.decapsulate(enc.ciphertext, kp.secretKey)
  return now() - t0
}

// --- hybrid: full initiate -> respond -> finalize crypto path ---------------
function hybridCpu () {
  const t0 = now()
  const { state, offer } = pq.initiate({ modes: ['classical', 'hybrid'], requireHybrid: true })
  const r = pq.respond(offer, { modes: ['classical', 'hybrid'], requireHybrid: true })
  const i = pq.finalize(state, r.message)
  const dt = now() - t0
  if (!b4a.equals(i.sessionKey, r.sessionKey)) throw new Error('handshake keys diverged')
  return dt
}

// warm up JITs
for (let n = 0; n < 50; n++) { classicalCpu(); hybridCpu(); mlkemCpu() }

const classical = []
const hybrid = []
const mlkem = []
for (let n = 0; n < REPS; n++) {
  classical.push(classicalCpu())
  hybrid.push(hybridCpu())
  mlkem.push(mlkemCpu())
}

// First-message wire sizes (measured off a real offer/message object)
const { state, offer } = pq.initiate({ modes: ['classical', 'hybrid'] })
const r = pq.respond(offer, { modes: ['classical', 'hybrid'] })
pq.finalize(state, r.message)

const classicalFirstMsg = 32 // X25519 ephemeral only (baseline firstMessageBytes=116 includes Noise framing)
const hybridFirstMsgKeyMaterial = offer.x25519pk.byteLength + offer.mlkemPk.byteLength
const hybridResponseKeyMaterial = r.message.x25519pk.byteLength + r.message.ciphertext.byteLength

const classicalMed = median(classical)
const hybridMed = median(hybrid)
const mlkemMed = median(mlkem)
const addedCpuMed = hybridMed - classicalMed

const TYPICAL_MTU = 1200 // conservative UDP payload budget for a DHT-relayed datagram

const result = {
  name: 'pq-handshake',
  reps: REPS,
  firstMessageKeyMaterialBytes: {
    classical: classicalFirstMsg,
    hybrid: hybridFirstMsgKeyMaterial, // 32 + 1184 = 1216
    responseHybrid: hybridResponseKeyMaterial, // 32 + 1088 = 1120
    note: 'raw key material only; the classical baseline firstMessageBytes=116 additionally carries Noise IK framing'
  },
  needsFragmentation: hybridFirstMsgKeyMaterial > TYPICAL_MTU,
  cpuMs: {
    classicalFullHandshakeMedian: classicalMed,
    hybridFullHandshakeMedian: hybridMed,
    mlkemTripleOnlyMedian: mlkemMed,
    addedMedian: addedCpuMed,
    breakdownNote: 'classicalFull = 2x X25519 keygen + 2x DH; hybridFull adds ML-KEM keygen+encapsulate+decapsulate + 2x combine + 2x deriveSessionKey; added = hybridFull - classicalFull, dominated by the pure-JS noble ML-KEM triple'
  },
  gate: {
    claim: 'hybrid first message >1KB (needs fragmentation) AND added CPU <1ms vs classical',
    firstMsgPast1KB: hybridFirstMsgKeyMaterial > 1024,
    addedCpuUnder1ms: addedCpuMed < 1,
    passes: hybridFirstMsgKeyMaterial > 1024 && addedCpuMed < 1
  }
}

console.log(JSON.stringify(result, null, 2))
