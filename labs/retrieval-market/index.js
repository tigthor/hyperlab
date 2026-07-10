// retrieval-market — signed bandwidth/storage micro-receipts, aggregated
// off-chain and (later) settled on an EVM L2. Fixes the uncompensated-relay
// free-rider problem. (INC-1, research HC-E7 / DHT-E5 / SW-E6)
//
// What is real today: the whole off-chain receipt layer — compact-encoding
// wire format, ed25519 sign/verify, and cumulative aggregation. What throws:
// on-chain settlement.
//
// Model: the CONSUMER (downloader / relay user) signs cumulative receipts
// acknowledging bytes served by the PROVIDER on a channel (e.g. a core's
// discovery key or a relay session id). Receipts are state-channel style:
// `bytes` is a running total and only the highest `sequence` per
// (provider, consumer, channel) matters, so losing intermediate receipts
// costs nothing and settlement is O(channels), not O(receipts).

const sodium = require('sodium-universal')
const b4a = require('b4a')
const c = require('compact-encoding')

const VERSION = 1
const NS_RECEIPT = b4a.from('retrieval-market/receipt/v1')

const receiptEncoding = {
  preencode (state, r) {
    c.uint.preencode(state, r.version)
    c.fixed32.preencode(state, r.provider)
    c.fixed32.preencode(state, r.consumer)
    c.fixed32.preencode(state, r.channel)
    c.uint.preencode(state, r.bytes)
    c.uint.preencode(state, r.sequence)
    c.uint.preencode(state, r.timestamp)
  },
  encode (state, r) {
    c.uint.encode(state, r.version)
    c.fixed32.encode(state, r.provider)
    c.fixed32.encode(state, r.consumer)
    c.fixed32.encode(state, r.channel)
    c.uint.encode(state, r.bytes)
    c.uint.encode(state, r.sequence)
    c.uint.encode(state, r.timestamp)
  },
  decode (state) {
    return {
      version: c.uint.decode(state),
      provider: c.fixed32.decode(state),
      consumer: c.fixed32.decode(state),
      channel: c.fixed32.decode(state),
      bytes: c.uint.decode(state),
      sequence: c.uint.decode(state),
      timestamp: c.uint.decode(state)
    }
  }
}

const signedReceiptEncoding = {
  preencode (state, r) {
    receiptEncoding.preencode(state, r)
    c.fixed64.preencode(state, r.signature)
  },
  encode (state, r) {
    receiptEncoding.encode(state, r)
    c.fixed64.encode(state, r.signature)
  },
  decode (state) {
    const r = receiptEncoding.decode(state)
    r.signature = c.fixed64.decode(state)
    return r
  }
}

/**
 * Ed25519 keypair for receipt signing (consumer identity).
 * @param {Buffer} [seed] - optional 32-byte seed for deterministic keys
 * @returns {{ publicKey: Buffer, secretKey: Buffer }}
 */
function keyPair (seed) {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  if (seed) sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  else sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}

/**
 * Build an unsigned receipt, validating every field.
 * @param {{ provider: Buffer, consumer: Buffer, channel: Buffer, bytes: number, sequence: number, timestamp?: number }} opts
 * @returns {object} unsigned receipt
 */
function createReceipt ({ provider, consumer, channel, bytes, sequence, timestamp = Date.now() }) {
  for (const [name, key] of [['provider', provider], ['consumer', consumer], ['channel', channel]]) {
    if (!b4a.isBuffer(key) || key.byteLength !== 32) throw new Error(name + ' must be a 32-byte buffer')
  }
  for (const [name, n] of [['bytes', bytes], ['sequence', sequence], ['timestamp', timestamp]]) {
    if (!Number.isSafeInteger(n) || n < 0) throw new Error(name + ' must be a non-negative safe integer')
  }
  return { version: VERSION, provider, consumer, channel, bytes, sequence, timestamp }
}

function signable (receipt) {
  return b4a.concat([NS_RECEIPT, c.encode(receiptEncoding, receipt)])
}

/**
 * Sign a receipt with the consumer's secret key.
 * @param {object} receipt - from createReceipt
 * @param {Buffer} secretKey - consumer's 64-byte ed25519 secret key
 * @returns {object} signed receipt (receipt + 64-byte signature)
 */
function signReceipt (receipt, secretKey) {
  if (!b4a.isBuffer(secretKey) || secretKey.byteLength !== sodium.crypto_sign_SECRETKEYBYTES) {
    throw new Error('secretKey must be a 64-byte buffer')
  }
  const signature = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, signable(receipt), secretKey)
  return { ...receipt, signature }
}

/**
 * Verify a signed receipt against the consumer key embedded in it.
 * @param {object} signedReceipt
 * @returns {boolean}
 */
function verifyReceipt (signedReceipt) {
  const { signature, ...receipt } = signedReceipt
  if (!b4a.isBuffer(signature) || signature.byteLength !== sodium.crypto_sign_BYTES) return false
  try {
    // A structurally malformed receipt (missing / wrong-typed fields) makes
    // the compact encoding or sodium throw - that is just "not a valid
    // receipt", so it verifies false instead of crashing the caller.
    return sodium.crypto_sign_verify_detached(signature, signable(receipt), receipt.consumer)
  } catch {
    return false
  }
}

/**
 * Encode a signed receipt for the wire / disk.
 * @param {object} signedReceipt
 * @returns {Buffer}
 */
function encodeReceipt (signedReceipt) {
  return c.encode(signedReceiptEncoding, signedReceipt)
}

/**
 * Decode a signed receipt.
 * @param {Buffer} buffer
 * @returns {object} signed receipt
 */
function decodeReceipt (buffer) {
  return c.decode(signedReceiptEncoding, buffer)
}

/**
 * Aggregate signed receipts for settlement: verifies every receipt, keeps
 * only the highest-sequence (cumulative) receipt per
 * (provider, consumer, channel), and totals the claimable bytes.
 *
 * @param {object[]} signedReceipts
 * @param {{ strict?: boolean }} [opts] - strict (default) throws on an invalid
 *   signature; otherwise invalid receipts are dropped and counted
 * @returns {{ claims: object[], totalBytes: number, invalid: number }}
 */
function aggregate (signedReceipts, opts = {}) {
  const strict = opts.strict !== false
  const best = new Map()
  let invalid = 0

  for (const r of signedReceipts) {
    if (!verifyReceipt(r)) {
      if (strict) throw new Error('invalid receipt signature at sequence ' + r.sequence)
      invalid++
      continue
    }
    const key = b4a.toString(r.provider, 'hex') + b4a.toString(r.consumer, 'hex') + b4a.toString(r.channel, 'hex')
    const cur = best.get(key)
    if (!cur || r.sequence > cur.sequence) best.set(key, r)
  }

  const claims = [...best.values()]
  let totalBytes = 0
  for (const r of claims) totalBytes += r.bytes

  return { claims, totalBytes, invalid }
}

/**
 * Settle aggregated claims on an EVM L2 (batch of highest-sequence receipts
 * per channel, verified in the contract, paid out to providers).
 * @param {{ claims: object[] }} aggregated - output of aggregate()
 * @param {{ rpcUrl?: string, contract?: string }} [opts]
 * @returns {Promise<{ txHash: string }>}
 */
async function settle (aggregated, opts = {}) {
  throw new Error('not implemented: EVM L2 settlement (receipt-verifying payout contract + payment channel close)')
}

module.exports = {
  keyPair,
  createReceipt,
  signReceipt,
  verifyReceipt,
  encodeReceipt,
  decodeReceipt,
  aggregate,
  settle,
  receiptEncoding,
  signedReceiptEncoding,
  constants: {
    VERSION,
    SIGNATURE_BYTES: sodium.crypto_sign_BYTES,
    KEY_BYTES: 32
  }
}
