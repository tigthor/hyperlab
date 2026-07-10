// hypercore-raptorq — systematic random-linear fountain coding over GF(256)
// as a hypercore extension message: repair symbols travel alongside the
// existing block/hash messages. (HC-R1, research HC-E3)
//
// HONESTY NOTE. This is NOT literal RFC 6330 RaptorQ. It is a systematic
// *random linear network code* (RLNC-style fountain) over GF(256):
//   - For a group of k source blocks, symbols with esi < k are the source
//     blocks VERBATIM (systematic — no-loss transfer decodes for free).
//   - Symbols with esi >= k are random linear combinations of the k blocks
//     over GF(256); their coefficient vector is derived deterministically
//     from esi (a PRNG seed), so the wire carries no coefficient payload.
//   - A decoder reconstructs the k blocks from ANY k linearly-independent
//     received symbols via Gaussian elimination over GF(256).
// It has the real "any k symbols" fountain property the book needs, but
// decoding is O(k^2 * symbolSize) with no sparse LDPC/HDPC precode and no LT
// peeling — so it does not have RaptorQ's near-linear decode or its
// standardized k+2 overhead bound. See README + StructuredOutput stillStub.

const c = require('compact-encoding')
const b4a = require('b4a')
const gf = require('./gf')
// The real hypercore leaf hash (BLAKE2b with the LEAF domain-separation
// prefix), reached through hypercore's own dependency so the digest we verify
// against is byte-identical to the leaf hash a peer holds in its Merkle tree.
const crypto = require('hypercore/node_modules/hypercore-crypto')

const EXTENSION_NAME = 'hyperlab/raptorq'
const DEFAULT_SYMBOL_SIZE = 1024 // T: bytes per encoding symbol
const DEFAULT_GROUP_SIZE = 16 // K: source blocks per coding group

// Wire format for one encoding symbol. A group is K consecutive hypercore
// blocks; symbols with esi < k are systematic (raw source data), esi >= k
// are repair symbols whose coefficients are derived from esi.
const symbolEncoding = {
  preencode (state, m) {
    c.uint.preencode(state, m.group)
    c.uint.preencode(state, m.esi)
    c.uint.preencode(state, m.k)
    c.buffer.preencode(state, m.symbol)
  },
  encode (state, m) {
    c.uint.encode(state, m.group)
    c.uint.encode(state, m.esi)
    c.uint.encode(state, m.k)
    c.buffer.encode(state, m.symbol)
  },
  decode (state) {
    return {
      group: c.uint.decode(state),
      esi: c.uint.decode(state),
      k: c.uint.decode(state),
      symbol: c.buffer.decode(state)
    }
  }
}

// The hypercore leaf hash of one block: BLAKE2b over the LEAF-typed encoding
// of the block bytes (crypto.data). This is exactly the digest hypercore
// stores at a tree leaf, so a decoded block can be authenticated against the
// hash a peer already holds — a forged/corrupt repair symbol that perturbs
// the reconstruction changes at least one block and is caught here.
function leafHash (block) {
  return crypto.data(block)
}

// Deterministic coefficient vector for a repair symbol, keyed by esi. Both
// encoder and decoder call this, so no coefficients travel on the wire. Each
// coefficient is a splitmix32-style nonlinear hash of (esi, i): Math.imul is
// NOT GF(2)-linear, and folding the column index i in gives every byte its own
// mixing stream. The row is guaranteed non-zero.
//
// A plain xorshift32 PRNG will NOT do here: xorshift steps are all XOR/shift,
// i.e. GF(2)-linear, so an entire k-byte row becomes a fixed linear image of a
// single 32-bit seed. The set of all such rows then spans a space of dimension
// <= 32, which caps the achievable rank at 32 and makes repair-only decode
// impossible for k > 32 (no matter how many repair symbols are generated).
function deriveCoeffs (esi, k) {
  const coeffs = new Uint8Array(k)
  let nonzero = false
  for (let i = 0; i < k; i++) {
    let z = (Math.imul(esi + 1, 0x9e3779b1) ^ Math.imul(i + 1, 0x85ebca6b)) >>> 0
    z = Math.imul(z ^ (z >>> 16), 0x21f0aaad) >>> 0
    z = Math.imul(z ^ (z >>> 15), 0x735a2d97) >>> 0
    z = (z ^ (z >>> 15)) >>> 0
    coeffs[i] = z & 0xff
    if (coeffs[i] !== 0) nonzero = true
  }
  if (!nonzero) coeffs[esi % k] = 1
  return coeffs
}

// The coefficient vector of ANY encoding symbol id. esi < k is systematic
// (unit vector e_esi); esi >= k is a derived random row.
function coeffsFor (esi, k) {
  if (esi < k) {
    const e = new Uint8Array(k)
    e[esi] = 1
    return e
  }
  return deriveCoeffs(esi, k)
}

/**
 * Systematic GF(256) random-linear fountain encoder over one group.
 */
class Encoder {
  /**
   * @param {Buffer[]} blocks - the k source blocks of one group
   * @param {{ symbolSize?: number }} [opts]
   */
  constructor (blocks, opts = {}) {
    if (!Array.isArray(blocks) || blocks.length === 0 || !blocks.every(b4a.isBuffer)) {
      throw new Error('blocks must be a non-empty array of buffers')
    }
    this.k = blocks.length

    let maxLen = opts.symbolSize || 0
    for (const b of blocks) if (b.length > maxLen) maxLen = b.length
    this.symbolSize = maxLen

    // padded copies so every source symbol is exactly symbolSize bytes
    this.lengths = blocks.map(b => b.length)
    this.blocks = blocks.map(b => {
      if (b.length === this.symbolSize) return b
      const padded = b4a.alloc(this.symbolSize)
      b4a.copy(b, padded)
      return padded
    })
  }

  /**
   * The symbolSize-byte encoding symbol for id `esi`.
   * esi < k returns the (padded) source block verbatim; esi >= k returns a
   * random linear combination of all k blocks over GF(256).
   * @param {number} esi
   * @returns {Buffer}
   */
  symbol (esi) {
    if (!Number.isInteger(esi) || esi < 0) throw new Error('esi must be a non-negative integer')
    if (esi < this.k) return b4a.from(this.blocks[esi])

    const coeffs = deriveCoeffs(esi, this.k)
    const out = b4a.alloc(this.symbolSize)
    for (let i = 0; i < this.k; i++) {
      gf.addScaled(out, this.blocks[i], coeffs[i], this.symbolSize)
    }
    return out
  }

  /** Wire message for one symbol id. */
  message (esi, group = 0) {
    return { group, esi, k: this.k, symbol: this.symbol(esi) }
  }

  /** The k systematic wire messages (esi 0..k-1). */
  systematicSymbols (group = 0) {
    const out = new Array(this.k)
    for (let esi = 0; esi < this.k; esi++) out[esi] = this.message(esi, group)
    return out
  }

  /**
   * n repair wire messages starting after the systematic range.
   * @param {number} n
   * @param {number} [group]
   * @param {number} [startEsi]
   * @returns {{ group: number, esi: number, k: number, symbol: Buffer }[]}
   */
  repairSymbols (n, group = 0, startEsi = this.k) {
    if (!Number.isInteger(n) || n < 0) throw new Error('n must be a non-negative integer')
    const out = new Array(n)
    for (let i = 0; i < n; i++) out[i] = this.message(startEsi + i, group)
    return out
  }
}

/**
 * GF(256) fountain decoder: feed any received symbols; once k linearly
 * independent ones are in, reconstruct the k source blocks. Uses online
 * Gauss-Jordan elimination (kept in reduced row echelon form), so decode()
 * is an O(k) read-out once the rank hits k.
 */
class Decoder {
  /**
   * @param {number} k - source symbols in this group
   * @param {{ symbolSize?: number, lengths?: number[] }} [opts]
   */
  constructor (k, opts = {}) {
    if (!Number.isInteger(k) || k <= 0) throw new Error('k must be a positive integer')
    this.k = k
    this.symbolSize = opts.symbolSize || DEFAULT_SYMBOL_SIZE
    this.lengths = opts.lengths || null
    // Optional expected leaf hashes (k of them). When present, decode()
    // authenticates every reconstructed block against its hash and REJECTS
    // the group if any mismatches, so a tampered repair symbol can never
    // silently corrupt output.
    this.hashes = opts.hashes || null
    if (this.hashes && this.hashes.length !== k) {
      throw new Error('hashes must have exactly k entries')
    }
    this.rank = 0
    this.received = 0
    // pivots[col] = { coef: Uint8Array(k), data: Uint8Array(symbolSize) }
    // kept normalized (coef[col] === 1) and reduced against all other pivots
    this.pivots = new Array(k).fill(null)
  }

  /**
   * Feed one received symbol. Returns true once k independent symbols are in
   * (i.e. the group is decodable).
   * @param {{ esi: number, symbol: Buffer }} sym
   * @returns {boolean} decodable
   */
  add (sym) {
    if (!sym || !Number.isInteger(sym.esi) || !b4a.isBuffer(sym.symbol)) {
      throw new Error('symbol must be { esi, symbol }')
    }
    this.received++

    if (sym.symbol.length !== this.symbolSize) {
      if (this.received === 1 && !this._sizeLocked) this.symbolSize = sym.symbol.length
      else if (sym.symbol.length !== this.symbolSize) {
        throw new Error('symbol size ' + sym.symbol.length + ' != ' + this.symbolSize)
      }
    }
    this._sizeLocked = true

    if (this.rank >= this.k) return true

    const coef = coeffsFor(sym.esi, this.k) // Uint8Array(k)
    const data = new Uint8Array(this.symbolSize)
    data.set(sym.symbol)

    // reduce the incoming row against existing pivots
    for (let col = 0; col < this.k; col++) {
      const f = coef[col]
      if (f === 0) continue
      const p = this.pivots[col]
      if (p) {
        gf.addScaled(coef, p.coef, f, this.k)
        gf.addScaled(data, p.data, f, this.symbolSize)
      }
    }

    // find the leading (pivot) column of the reduced row
    let pivotCol = -1
    for (let col = 0; col < this.k; col++) {
      if (coef[col] !== 0) { pivotCol = col; break }
    }
    if (pivotCol === -1) return this.rank >= this.k // linearly dependent, drop

    // normalize so coef[pivotCol] === 1
    const invLead = gf.inv(coef[pivotCol])
    gf.scale(coef, invLead, this.k)
    gf.scale(data, invLead, this.symbolSize)

    // eliminate pivotCol from every existing pivot row (keep full RREF)
    for (let col = 0; col < this.k; col++) {
      const p = this.pivots[col]
      if (!p) continue
      const f = p.coef[pivotCol]
      if (f === 0) continue
      gf.addScaled(p.coef, coef, f, this.k)
      gf.addScaled(p.data, data, f, this.symbolSize)
    }

    this.pivots[pivotCol] = { coef, data }
    this.rank++
    return this.rank >= this.k
  }

  get decodable () {
    return this.rank >= this.k
  }

  /**
   * Reconstruct the k source blocks. Requires rank === k.
   * @returns {Buffer[]}
   */
  decode () {
    if (this.rank < this.k) {
      throw new Error('need k independent symbols before decoding (' + this.rank + '/' + this.k + ')')
    }
    const out = new Array(this.k)
    for (let i = 0; i < this.k; i++) {
      // RREF => pivots[i].coef === e_i, so pivots[i].data is source symbol i
      const data = this.pivots[i].data
      const len = this.lengths ? this.lengths[i] : this.symbolSize
      out[i] = b4a.from(data.subarray(0, len))
    }
    if (this.hashes) this.authenticate(out)
    return out
  }

  /**
   * Authenticate reconstructed blocks against the expected leaf hashes.
   * Throws (rejecting the whole group) on the first mismatch, so a corrupt
   * or forged repair symbol that perturbed the reconstruction is caught
   * rather than returned as silently-wrong data.
   * @param {Buffer[]} blocks
   */
  authenticate (blocks) {
    if (!this.hashes) throw new Error('decoder has no expected hashes to authenticate against')
    for (let i = 0; i < this.k; i++) {
      if (!b4a.equals(leafHash(blocks[i]), this.hashes[i])) {
        throw new Error('block ' + i + ' failed authentication (leaf hash mismatch)')
      }
    }
    return true
  }
}

/**
 * Attach the raptorq extension to a hypercore (or session). Symbols received
 * from peers are handed to `handlers.onsymbol`. This rides hypercore's
 * extension channel, so symbols flow over live replication streams today.
 *
 * @param {import('hypercore')} core
 * @param {{ onsymbol?: (message, peer) => void }} [handlers]
 * @returns {{ extension: object, send: Function, broadcast: Function, destroy: Function }}
 */
function attach (core, handlers = {}) {
  if (!core || typeof core.registerExtension !== 'function') {
    throw new Error('attach expects a hypercore instance')
  }

  const ext = core.registerExtension(EXTENSION_NAME, {
    encoding: symbolEncoding,
    onmessage (message, peer) {
      if (handlers.onsymbol) handlers.onsymbol(message, peer)
    }
  })

  return {
    extension: ext,
    send (symbol, peer) { ext.send(symbol, peer) },
    broadcast (symbol) { ext.broadcast(symbol) },
    destroy () { ext.destroy() }
  }
}

// Convenience wire helpers so consumers without compact-encoding on their
// own dependency path can still frame/parse symbols.
function encodeSymbol (message) {
  return c.encode(symbolEncoding, message)
}

function decodeSymbol (buffer) {
  return c.decode(symbolEncoding, buffer)
}

module.exports = {
  attach,
  Encoder,
  Decoder,
  symbolEncoding,
  encodeSymbol,
  decodeSymbol,
  coeffsFor,
  leafHash,
  gf,
  constants: {
    EXTENSION_NAME,
    DEFAULT_SYMBOL_SIZE,
    DEFAULT_GROUP_SIZE
  }
}
