// hypercore-raptorq — RaptorQ (RFC 6330) fountain-coded replication as a
// hypercore extension message: repair symbols travel alongside the existing
// block/hash messages. (HC-R1, research HC-E3)
//
// What is real today: the wire message codec and the extension plumbing
// (attach/send/broadcast over live hypercore replication). What throws:
// the actual RFC 6330 encoder/decoder.

const c = require('compact-encoding')
const b4a = require('b4a')

const EXTENSION_NAME = 'hyperlab/raptorq'
const DEFAULT_SYMBOL_SIZE = 1024 // T: bytes per encoding symbol
const DEFAULT_GROUP_SIZE = 16 // K: source blocks per coding group

// Wire format for one encoding symbol. A group is K consecutive hypercore
// blocks; symbols with esi < k are systematic (raw source data), esi >= k
// are repair symbols. Any k + epsilon received symbols reconstruct the group
// (k with >99% probability, k+2 with >99.9999% per RFC 6330).
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

/**
 * RFC 6330 systematic RaptorQ encoder over one group of source blocks.
 */
class Encoder {
  /**
   * @param {Buffer[]} blocks - the K source blocks of one group
   * @param {{ symbolSize?: number }} [opts]
   */
  constructor (blocks, opts = {}) {
    if (!Array.isArray(blocks) || blocks.length === 0 || !blocks.every(b4a.isBuffer)) {
      throw new Error('blocks must be a non-empty array of buffers')
    }
    this.blocks = blocks
    this.k = blocks.length
    this.symbolSize = opts.symbolSize || DEFAULT_SYMBOL_SIZE
  }

  /**
   * Produce encoding symbols. esi < k returns the (padded) source symbol,
   * esi >= k requires the LT + LDPC/HDPC precode machinery.
   * @param {number} esi - encoding symbol id
   * @returns {Buffer} symbolSize-byte symbol
   */
  symbol (esi) {
    throw new Error('not implemented: RFC 6330 encoding (GF(256) precode + LT layer)')
  }

  /**
   * Convenience: n repair symbols starting after the systematic range.
   * @param {number} n
   * @returns {{ group: number, esi: number, k: number, symbol: Buffer }[]}
   */
  repairSymbols (n) {
    throw new Error('not implemented: RFC 6330 repair symbol generation')
  }
}

/**
 * RFC 6330 decoder: collect any k + epsilon symbols of a group, then solve.
 */
class Decoder {
  /**
   * @param {number} k - source symbols in this group
   * @param {{ symbolSize?: number }} [opts]
   */
  constructor (k, opts = {}) {
    if (!Number.isInteger(k) || k <= 0) throw new Error('k must be a positive integer')
    this.k = k
    this.symbolSize = opts.symbolSize || DEFAULT_SYMBOL_SIZE
    this.received = new Map() // esi -> symbol
  }

  /**
   * Feed one received symbol. Returns true once enough symbols are buffered
   * that decoding is likely to succeed (>= k).
   * @param {{ esi: number, symbol: Buffer }} sym
   * @returns {boolean} ready to attempt decode
   */
  add (sym) {
    if (!sym || !Number.isInteger(sym.esi) || !b4a.isBuffer(sym.symbol)) {
      throw new Error('symbol must be { esi, symbol }')
    }
    this.received.set(sym.esi, sym.symbol)
    return this.received.size >= this.k
  }

  /**
   * Solve the decoding matrix and return the k source blocks.
   * @returns {Buffer[]}
   */
  decode () {
    if (this.received.size < this.k) {
      throw new Error('need at least k symbols before decoding (' + this.received.size + '/' + this.k + ')')
    }
    throw new Error('not implemented: RFC 6330 decoding (gaussian elimination over GF(256))')
  }
}

/**
 * Attach the raptorq extension to a hypercore (or session). Symbols received
 * from peers are decoded off the wire and handed to `handlers.onsymbol`.
 *
 * This part is real: it rides hypercore's extension channel, so symbols
 * flow over live replication streams today.
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
    send (symbol, peer) {
      ext.send(symbol, peer)
    },
    broadcast (symbol) {
      ext.broadcast(symbol)
    },
    destroy () {
      ext.destroy()
    }
  }
}

module.exports = {
  attach,
  Encoder,
  Decoder,
  symbolEncoding,
  constants: {
    EXTENSION_NAME,
    DEFAULT_SYMBOL_SIZE,
    DEFAULT_GROUP_SIZE
  }
}
