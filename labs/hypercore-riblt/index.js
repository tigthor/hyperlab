// hypercore-riblt — Rateless Invertible Bloom Lookup Table set reconciliation
// (Yang, Gilad, Alizadeh, "Practical Rateless Set Reconciliation", SIGCOMM
// 2024). Reconcile the sets of block indices two peers HOLD for a hypercore by
// streaming rateless coded symbols and peeling the symmetric difference —
// instead of exchanging a full have/want bitfield. (Expansion No. 61)
//
// Elements are 64-bit block indices, carried as BigInt (uint64). Each element
// e has a 64-bit checksum hash(e); that same hash seeds the RandomMapping that
// spreads e across a rateless stream of coded cells with geometrically-thinning
// density, so that decoding the symmetric difference d needs ~1.35*d cells.
//
// This is a faithful port of the paper's reference construction: the
// RandomMapping increment law lastIdx += ceil((lastIdx+1.5)*(2^32/sqrt(r)-1)),
// a CodedSymbol of {count, xorOfElements, xorOfChecksums}, cell-wise
// subtraction of the two encodings so shared elements cancel, and peeling of
// pure (|count|==1, hash(sum)==checksum) cells with cascade.

const c = require('compact-encoding')

const MASK64 = (1n << 64n) - 1n
const MULT = 0xda942042e4dd58b5n // multiplicative PRNG step (paper reference)
const TWO32 = 4294967296 // 2^32, as float

// splitmix64 finalizer — 64-bit avalanche hash of a uint64 element. Doubles as
// the element's checksum AND the seed of its RandomMapping.
function hash64 (x) {
  let z = (x + 0x9e3779b97f4a7c15n) & MASK64
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64
  z = (z ^ (z >> 31n)) & MASK64
  return z
}

// RandomMapping: the infinite, thinning sequence of coded-cell indices an
// element is XORed into. State is { prng (BigInt uint64), lastIdx (int) }; the
// first mapped index is 0 (lastIdx starts at 0) and each nextIndex advances it.
function makeMapping (seed) {
  return { prng: seed & MASK64, lastIdx: 0 }
}

function mapNext (m) {
  const r = (m.prng * MULT) & MASK64
  m.prng = r
  // increment law: expected gap ~= lastIdx, so an element lands in O(log n) of
  // the first n cells with 1/j-ish density — the rateless degree sequence.
  let inc = Math.ceil((m.lastIdx + 1.5) * (TWO32 / Math.sqrt(Number(r) + 1) - 1))
  if (inc < 1) inc = 1 // guard the (prob 2^-64) r=2^64-1 degenerate step
  m.lastIdx += inc
  return m.lastIdx
}

// Coerce an arbitrary iterable of elements to an array of DISTINCT uint64
// BigInts. RIBLT is a SET reconciliation: its cells XOR elements together, so a
// duplicated element XOR-cancels its own twin and silently vanishes from the
// recovered difference (a wrong `success:true`). Deduping at every public
// boundary makes the multiset case well-defined instead of silently wrong.
function toDistinct (iterable) {
  const seen = new Set()
  const out = []
  for (const e of iterable) {
    const v = BigInt(e) & MASK64
    if (seen.has(v)) continue
    seen.add(v)
    out.push(v)
  }
  return out
}

// A CodedSymbol accumulates: a signed count, the XOR of mapped elements, and
// the XOR of their checksums.
function emptyCell () {
  return { count: 0, sum: 0n, checksum: 0n }
}

function cellIsEmpty (cell) {
  return cell.count === 0 && cell.sum === 0n && cell.checksum === 0n
}

// A cell is pure (directly decodable to one element) when it holds exactly one
// element and the element's hash matches the accumulated checksum.
function cellIsPure (cell) {
  return (cell.count === 1 || cell.count === -1) && hash64(cell.sum) === cell.checksum
}

// A CodingWindow holds a set of elements together with their live mappings in a
// min-heap keyed by next mapped cell index. applyUpTo(cell, idx, dir) folds
// every element mapped to `idx` into `cell` with sign `dir` and advances it.
class CodingWindow {
  constructor () {
    this.elements = [] // BigInt uint64
    this.checksums = [] // BigInt uint64
    this.mappings = [] // { prng, lastIdx }
    // binary min-heap of { srcIdx, codedIdx }
    this.heapSrc = []
    this.heapIdx = []
  }

  add (element) {
    this.addWithMapping(element, hash64(element), makeMapping(hash64(element)))
  }

  // Add an element whose mapping may already be advanced (used when the decoder
  // recovers an element after N cells and must keep peeling it from later ones).
  addWithMapping (element, checksum, mapping) {
    const srcIdx = this.elements.length
    this.elements.push(element)
    this.checksums.push(checksum)
    this.mappings.push(mapping)
    this._heapPush(srcIdx, mapping.lastIdx)
  }

  // Fold all elements currently mapped to targetIdx into `cell` with sign dir,
  // advancing each to its next mapped index.
  applyUpTo (cell, targetIdx, dir) {
    while (this.heapSrc.length > 0 && this.heapIdx[0] === targetIdx) {
      const srcIdx = this.heapSrc[0]
      cell.count += dir
      cell.sum ^= this.elements[srcIdx]
      cell.checksum ^= this.checksums[srcIdx]
      const next = mapNext(this.mappings[srcIdx])
      this._heapReplaceTop(srcIdx, next)
    }
    return cell
  }

  _heapPush (srcIdx, codedIdx) {
    let i = this.heapSrc.length
    this.heapSrc.push(srcIdx)
    this.heapIdx.push(codedIdx)
    while (i > 0) {
      const p = (i - 1) >> 1
      if (this.heapIdx[p] <= this.heapIdx[i]) break
      this._swap(i, p)
      i = p
    }
  }

  _heapReplaceTop (srcIdx, codedIdx) {
    this.heapSrc[0] = srcIdx
    this.heapIdx[0] = codedIdx
    this._siftDown(0)
  }

  _siftDown (i) {
    const n = this.heapSrc.length
    for (;;) {
      const l = 2 * i + 1
      const r = 2 * i + 2
      let s = i
      if (l < n && this.heapIdx[l] < this.heapIdx[s]) s = l
      if (r < n && this.heapIdx[r] < this.heapIdx[s]) s = r
      if (s === i) break
      this._swap(i, s)
      i = s
    }
  }

  _swap (a, b) {
    const ts = this.heapSrc[a]; this.heapSrc[a] = this.heapSrc[b]; this.heapSrc[b] = ts
    const ti = this.heapIdx[a]; this.heapIdx[a] = this.heapIdx[b]; this.heapIdx[b] = ti
  }
}

// Encoder: add the elements of a set, then emit a lazy, unbounded stream of
// CodedSymbols. Symbol j = the XOR/sum over all elements mapped to cell j.
class Encoder {
  constructor () {
    this.window = new CodingWindow()
    this.nextIdx = 0
  }

  add (element) {
    this.window.add(BigInt(element))
    return this
  }

  // Produce the next CodedSymbol in the stream.
  produceSymbol () {
    const cell = emptyCell()
    this.window.applyUpTo(cell, this.nextIdx, 1)
    cell.index = this.nextIdx
    this.nextIdx++
    return cell
  }

  // Generator of the next n CodedSymbols.
  * symbols (n) {
    for (let i = 0; i < n; i++) yield this.produceSymbol()
  }
}

// Decoder: seeded with the LOCAL set, it consumes the remote peer's CodedSymbol
// stream. Each incoming cell has the local set subtracted (shared elements
// cancel) and already-recovered elements peeled out; pure cells yield elements
// of the symmetric difference and cascade.
//
// Sign convention: remote (B) contributes +1 per element, local (A) is
// subtracted (-1). So a surviving cell with count == +1 is a B-only element
// (bOnly) and count == -1 is an A-only element (aOnly).
class Decoder {
  constructor (localSet) {
    this.local = new CodingWindow() // our own set, subtracted from every cell
    for (const e of toDistinct(localSet)) this.local.add(e)
    this.remoteRecovered = new CodingWindow() // decoded B-only elements
    this.localRecovered = new CodingWindow() // decoded A-only elements
    this.cs = [] // combined coded symbols received so far
    this.decodable = [] // indices of cs that may be pure
    this.remaining = 0 // count of non-empty cells
    this.aOnly = []
    this.bOnly = []
    // Robustness against desynced / adversarial streams. `failed` latches once
    // the stream is detected as out-of-order/duplicate/dropped, or once the
    // peeling cascade blows a hard work budget (a crafted 'pure' cell can seed a
    // divergent cascade). `work` counts inner peel steps so total work is capped
    // regardless of what a remote injects.
    this.failed = false
    this.work = 0
  }

  // Hard cap on inner peel/cascade steps, proportional to cells actually
  // received. Honest decodes spend ~d*ln(cells) steps (thousands); this budget
  // is far above that yet bounds any adversarial cascade to O(cells).
  _workBudget () {
    return this.cs.length * 64 + 8192
  }

  get cellsUsed () {
    return this.cs.length
  }

  isDecoded () {
    return this.remaining === 0
  }

  // Ingest one remote CodedSymbol.
  addCodedSymbol (remoteCell) {
    if (this.failed) return
    // Truncated stream: the source ran out mid-reconciliation.
    if (remoteCell == null) { this.failed = true; return }
    // Stream-integrity check. Honest encoders emit symbols carrying a strictly
    // increasing index 0,1,2,… — exactly matching the slot we place them in. A
    // duplicated, dropped, or reordered symbol arrives with the wrong index; we
    // fail cleanly rather than XOR it into the wrong slot and misdecode. (Cells
    // that carry no index — e.g. trusted in-process feeds — skip the check.)
    if (remoteCell.index !== undefined && remoteCell.index !== this.cs.length) {
      this.failed = true
      return
    }
    const i = this.cs.length
    const cell = { count: remoteCell.count, sum: remoteCell.sum, checksum: remoteCell.checksum }
    this.local.applyUpTo(cell, i, -1) // subtract local set A
    this.remoteRecovered.applyUpTo(cell, i, -1) // remove decoded B-only (+1 -> gone)
    this.localRecovered.applyUpTo(cell, i, 1) // remove decoded A-only (-1 -> gone)
    this.cs.push(cell)
    if (!cellIsEmpty(cell)) this.remaining++
    if (cellIsPure(cell)) this.decodable.push(i)
    this._tryDecode()
  }

  // Peel every currently-pure cell, cascading as removals expose new pure cells.
  _tryDecode () {
    for (let k = 0; k < this.decodable.length; k++) {
      // Hard-bound the cascade: a crafted cell could otherwise thrash cells
      // in/out of "pure" without ever draining `remaining`. Fail cleanly.
      if (++this.work > this._workBudget()) {
        this.failed = true
        this.decodable.length = 0
        return
      }
      const idx = this.decodable[k]
      const cell = this.cs[idx]
      if (!cellIsPure(cell)) continue // stale entry, already peeled
      const element = cell.sum
      const checksum = cell.checksum
      if (cell.count === 1) {
        // B-only element: record and peel it (remove its +1) from all cells.
        this.bOnly.push(element)
        const m = this._peel(element, checksum, -1)
        this.remoteRecovered.addWithMapping(element, checksum, m)
      } else {
        // count === -1 : A-only element (remove its -1 -> apply +1).
        this.aOnly.push(element)
        const m = this._peel(element, checksum, 1)
        this.localRecovered.addWithMapping(element, checksum, m)
      }
    }
    this.decodable.length = 0
  }

  // Remove element (with sign dir) from every existing cs cell it maps to,
  // queueing any freshly-pure cell. Returns the mapping advanced past cs.length
  // so the element can keep being peeled from cells received later.
  _peel (element, checksum, dir) {
    const m = makeMapping(checksum)
    let idx = 0
    const n = this.cs.length
    for (;;) {
      if (++this.work > this._workBudget()) { this.failed = true; return m }
      if (idx < n) {
        const cell = this.cs[idx]
        const wasEmpty = cellIsEmpty(cell)
        cell.count += dir
        cell.sum ^= element
        cell.checksum ^= checksum
        const nowEmpty = cellIsEmpty(cell)
        if (wasEmpty && !nowEmpty) this.remaining++
        else if (!wasEmpty && nowEmpty) this.remaining--
        if (cellIsPure(cell)) this.decodable.push(idx)
      }
      const next = mapNext(m)
      if (next >= n) return m // advanced past what we hold; stop here
      idx = next
    }
  }

  result () {
    return { aOnly: this.aOnly.slice(), bOnly: this.bOnly.slice(), cellsUsed: this.cs.length }
  }
}

// High-level driver: reconcile a local set against a remote CodedSymbol source.
// `remote` is either an Encoder or a zero-arg function returning the next
// CodedSymbol. Pulls symbols until the difference decodes (rateless) or maxCells
// is hit. Returns { aOnly, bOnly, cellsUsed, success }.
function reconcile (localSet, remote, opts) {
  const options = opts || {}
  const pull = typeof remote === 'function' ? remote : () => remote.produceSymbol()
  const maxCells = options.maxCells || 1 << 24
  const dec = new Decoder(toDistinct(localSet))
  // Pull at least one symbol; keep going while an undecoded difference remains.
  // Every difference element maps to cell 0, so once cell 0 is drained a zero
  // `remaining` reliably means the symmetric difference is fully peeled.
  do {
    if (dec.cellsUsed >= maxCells) break
    const sym = pull()
    // null/undefined = end-of-stream (peer disconnected mid-reconciliation).
    // Treat as truncation and stop, rather than crashing on `sym.count`.
    if (sym == null) break
    dec.addCodedSymbol(sym)
    if (dec.failed) break // desync / adversarial stream detected — bail cleanly
  } while (!dec.isDecoded())
  const success = dec.isDecoded() && !dec.failed
  return { aOnly: dec.aOnly, bOnly: dec.bOnly, cellsUsed: dec.cellsUsed, success }
}

// Test helper: reconcile two concrete sets end to end. setA is local, setB is
// remote; drives the streaming to completion. Returns the symmetric difference
// (aOnly = A\B, bOnly = B\A) and cellsUsed.
function reconcileSets (setA, setB, opts) {
  const enc = new Encoder()
  for (const e of toDistinct(setB)) enc.add(e)
  const out = reconcile(toDistinct(setA), enc, opts)
  return out
}

// compact-encoding codec for one CodedSymbol on the wire: an unsigned varint
// stream INDEX (so the decoder can detect dropped/duplicated/reordered cells),
// a signed varint count (zig-zag), then two fixed 8-byte big-endian uint64s
// (element XOR, checksum XOR). ~13-21 bytes/cell: the index and count varints
// grow for early, high-count cells at large N (see honestNote).
const codedSymbolEncoding = {
  preencode (state, s) {
    c.uint.preencode(state, s.index || 0)
    c.int.preencode(state, s.count)
    c.biguint64.preencode(state, s.sum)
    c.biguint64.preencode(state, s.checksum)
  },
  encode (state, s) {
    c.uint.encode(state, s.index || 0)
    c.int.encode(state, s.count)
    c.biguint64.encode(state, s.sum)
    c.biguint64.encode(state, s.checksum)
  },
  decode (state) {
    return {
      index: c.uint.decode(state),
      count: c.int.decode(state),
      sum: c.biguint64.decode(state),
      checksum: c.biguint64.decode(state)
    }
  }
}

// Honest disclosure of the size/robustness tradeoffs, kept in code so the claim
// and the test move together.
const honestNote = `RIBLT set reconciliation — honest disclosure:

Wire size: a coded cell is index-varint + count-varint + 16 bytes of XORs. At a
realistic N=1e6 peer the early, low-index cells each carry huge |count| (cell 0
XORs the whole set), so counts need multi-byte varints and the measured mean is
~19 B/cell — NOT the ~17 B/cell an under-populated 5000-element encoder reports.

Loss regime: RIBLT costs ~1.35*d cells * ~19 B. A raw have/want bitfield costs
N/8 bytes. RIBLT only wins while d << N; the crossover is d ~= N/(8*1.35*19) ~=
0.5% of N. At d >= ~1% of N the bitfield is smaller — send the bitfield instead.

Baseline caveat: hypercore does not exchange a raw N/8 bitfield; it exchanges a
RUN-LENGTH-COMPRESSED bitfield, which for clustered availability is far smaller
than N/8. So the N/8 comparison is an UPPER BOUND on RIBLT's real-world win.

Failure rate: rateless decoding essentially never fails for honest random sets,
but 0/250 trials only bounds the failure probability to ~1.2e-2 (rule of three).
The gate now runs enough trials to actually bound it below 1e-3.`

module.exports = {
  Encoder,
  Decoder,
  CodingWindow,
  reconcile,
  reconcileSets,
  hash64,
  makeMapping,
  mapNext,
  cellIsPure,
  codedSymbolEncoding,
  toDistinct,
  honestNote
}
