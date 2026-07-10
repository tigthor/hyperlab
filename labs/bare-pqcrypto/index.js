// bare-pqcrypto — ML-KEM (FIPS 203) and ML-DSA (FIPS 204) for Bare and Node.
// (BARE-1, research BARE-E7)
//
// Strategy: WASM/liboqs backend first for iteration speed, constant-time
// native Bare addon later. What is real today: the FIPS 203/204 parameter
// tables and runtime feature detection. All primitive operations throw
// until a backend lands.

const b4a = require('b4a')

// FIPS 203 (final, 2024-08-13) — ML-KEM parameter sizes in bytes
const MLKEM = {
  'ML-KEM-512': { publicKeyBytes: 800, secretKeyBytes: 1632, ciphertextBytes: 768, sharedSecretBytes: 32 },
  'ML-KEM-768': { publicKeyBytes: 1184, secretKeyBytes: 2400, ciphertextBytes: 1088, sharedSecretBytes: 32 },
  'ML-KEM-1024': { publicKeyBytes: 1568, secretKeyBytes: 3168, ciphertextBytes: 1568, sharedSecretBytes: 32 }
}

// FIPS 204 (final, 2024-08-13) — ML-DSA parameter sizes in bytes.
// Note: the research brief quotes 3,293 bytes for the level-3 signature —
// that is the round-3 Dilithium3 figure; final FIPS 204 ML-DSA-65 is 3,309.
const MLDSA = {
  'ML-DSA-44': { publicKeyBytes: 1312, secretKeyBytes: 2560, signatureBytes: 2420 },
  'ML-DSA-65': { publicKeyBytes: 1952, secretKeyBytes: 4032, signatureBytes: 3309 },
  'ML-DSA-87': { publicKeyBytes: 2592, secretKeyBytes: 4896, signatureBytes: 4627 }
}

const DEFAULT_KEM = 'ML-KEM-768'
const DEFAULT_DSA = 'ML-DSA-65'

/**
 * Detect which backends are loadable in the current runtime.
 * `backend` is null until a real implementation ships; consumers must
 * treat that as "PQ unavailable" and fall back to classical-only.
 *
 * @returns {{ wasm: boolean, native: boolean, bare: boolean, backend: string|null }}
 */
function detect () {
  return {
    wasm: typeof WebAssembly !== 'undefined',
    native: hasNativeAddon(),
    bare: typeof Bare !== 'undefined', // eslint-disable-line no-undef
    backend: null // 'wasm-liboqs' | 'bare-native' once implemented
  }
}

function hasNativeAddon () {
  try {
    require.resolve('bare-pqcrypto-native')
    return true
  } catch {
    return false
  }
}

function assertAlgorithm (table, algorithm) {
  if (!Object.hasOwn(table, algorithm)) throw new Error('unknown algorithm: ' + algorithm)
  return table[algorithm]
}

const mlkem = {
  /**
   * Generate an ML-KEM keypair.
   * @param {string} [algorithm='ML-KEM-768']
   * @returns {{ publicKey: Buffer, secretKey: Buffer }}
   */
  keygen (algorithm = DEFAULT_KEM) {
    assertAlgorithm(MLKEM, algorithm)
    throw new Error('not implemented: ' + algorithm + ' keygen (no WASM/native backend yet)')
  },

  /**
   * Encapsulate a fresh shared secret against a public key.
   * @param {Buffer} publicKey
   * @param {string} [algorithm='ML-KEM-768']
   * @returns {{ ciphertext: Buffer, sharedSecret: Buffer }}
   */
  encapsulate (publicKey, algorithm = DEFAULT_KEM) {
    const p = assertAlgorithm(MLKEM, algorithm)
    if (!b4a.isBuffer(publicKey) || publicKey.byteLength !== p.publicKeyBytes) {
      throw new Error(algorithm + ' public key must be ' + p.publicKeyBytes + ' bytes')
    }
    throw new Error('not implemented: ' + algorithm + ' encapsulation (no WASM/native backend yet)')
  },

  /**
   * Decapsulate a ciphertext into the shared secret.
   * @param {Buffer} ciphertext
   * @param {Buffer} secretKey
   * @param {string} [algorithm='ML-KEM-768']
   * @returns {Buffer} 32-byte shared secret
   */
  decapsulate (ciphertext, secretKey, algorithm = DEFAULT_KEM) {
    const p = assertAlgorithm(MLKEM, algorithm)
    if (!b4a.isBuffer(ciphertext) || ciphertext.byteLength !== p.ciphertextBytes) {
      throw new Error(algorithm + ' ciphertext must be ' + p.ciphertextBytes + ' bytes')
    }
    throw new Error('not implemented: ' + algorithm + ' decapsulation (no WASM/native backend yet)')
  }
}

const mldsa = {
  /**
   * Generate an ML-DSA keypair.
   * @param {string} [algorithm='ML-DSA-65']
   * @returns {{ publicKey: Buffer, secretKey: Buffer }}
   */
  keygen (algorithm = DEFAULT_DSA) {
    assertAlgorithm(MLDSA, algorithm)
    throw new Error('not implemented: ' + algorithm + ' keygen (no WASM/native backend yet)')
  },

  /**
   * Sign a message. Beware FIPS 204 rejection sampling: signing latency has
   * ~50% coefficient of variation — batch appends when driving hypercore.
   * @param {Buffer} message
   * @param {Buffer} secretKey
   * @param {string} [algorithm='ML-DSA-65']
   * @returns {Buffer} detached signature
   */
  sign (message, secretKey, algorithm = DEFAULT_DSA) {
    assertAlgorithm(MLDSA, algorithm)
    throw new Error('not implemented: ' + algorithm + ' signing (no WASM/native backend yet)')
  },

  /**
   * Verify a detached signature.
   * @param {Buffer} signature
   * @param {Buffer} message
   * @param {Buffer} publicKey
   * @param {string} [algorithm='ML-DSA-65']
   * @returns {boolean}
   */
  verify (signature, message, publicKey, algorithm = DEFAULT_DSA) {
    const p = assertAlgorithm(MLDSA, algorithm)
    if (!b4a.isBuffer(signature) || signature.byteLength !== p.signatureBytes) {
      throw new Error(algorithm + ' signature must be ' + p.signatureBytes + ' bytes')
    }
    throw new Error('not implemented: ' + algorithm + ' verification (no WASM/native backend yet)')
  }
}

module.exports = {
  detect,
  mlkem,
  mldsa,
  constants: {
    ...MLKEM,
    ...MLDSA,
    DEFAULT_KEM,
    DEFAULT_DSA
  }
}
