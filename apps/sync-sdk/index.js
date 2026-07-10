const { EventEmitter } = require('events')
const Corestore = require('corestore')
const Autobase = require('autobase')
const Hyperbee = require('hyperbee')
const Hyperswarm = require('hyperswarm')
const b4a = require('b4a')

// SyncDB — "Firebase for P2P".
//
// A local-first, multi-writer key/value store. Autobase linearizes the
// oplog from every writer into a single deterministic order; a Hyperbee
// ("autobee") view is rebuilt from that order and is byte-identical on
// every peer once they have replicated the same set of nodes.
//
// Conflict policy: LAST-WRITER-WINS per key. Every 'put' op carries a
// causal position in the linearized log; the apply function replays ops
// in linearized order, so the final write to a key in that order is the
// value that survives. Because the linearization is deterministic and
// shared, all converged peers agree on the same winner (not wall-clock
// based — it is the causal order the linearizer produces).
class SyncDB extends EventEmitter {
  constructor (opts = {}) {
    super()

    this.store = opts.corestore || new Corestore(opts.storage)
    this._ownsStore = !opts.corestore

    this.bootstrap = opts.bootstrap || null // testnet bootstrap nodes for internal swarm
    this.swarm = opts.swarm || null // may be injected by tests
    this._ownsSwarm = false
    this._joinSwarm = opts.join !== false // set false to replicate only over injected connections
    this.discovery = null

    const key = opts.key || null // remote autobase key to bootstrap from (invite peer)

    this.base = new Autobase(this.store.namespace('sync'), key, {
      valueEncoding: 'json',
      open (viewStore) {
        return new Hyperbee(viewStore.get({ name: 'sync' }), {
          keyEncoding: 'utf-8',
          valueEncoding: 'json',
          extension: false
        })
      },
      async apply (nodes, view, host) {
        const b = view.batch({ update: false })
        for (const node of nodes) {
          const op = node.value
          if (!op) continue
          if (op.type === 'addWriter') {
            await b.flush()
            await host.addWriter(b4a.from(op.key, 'hex'))
            continue
          }
          if (op.type === 'put') {
            await b.put(op.key, { value: op.value, seq: node.length, from: b4a.toString(node.from.key, 'hex') })
          } else if (op.type === 'del') {
            await b.del(op.key)
          }
        }
        await b.flush()
      }
    })

    this.base.on('update', () => {
      if (!this.base._closing) this.emit('update')
    })
  }

  async ready () {
    await this.base.ready()

    if (this._joinSwarm) {
      if (!this.swarm) {
        this.swarm = new Hyperswarm({ bootstrap: this.bootstrap })
        this._ownsSwarm = true
      }
      this.swarm.on('connection', (conn) => {
        this.store.replicate(conn)
      })
      this.discovery = this.swarm.join(this.base.discoveryKey, { server: true, client: true })
      await this.discovery.flushed()
    }

    return this
  }

  // Replicate over a caller-provided duplex/socket (bypasses the swarm).
  replicate (connOrInitiator, opts) {
    return this.store.replicate(connOrInitiator, opts)
  }

  get key () { return this.base.key }
  get discoveryKey () { return this.base.discoveryKey }
  get writable () { return this.base.writable }

  // The local writer key. A peer shares this string with an existing
  // writer, who calls addWriter(writerKey) to grant write access.
  get writerKey () { return b4a.toString(this.base.local.key, 'hex') }

  async set (key, value) {
    await this.base.append({ type: 'put', key, value })
  }

  async del (key) {
    await this.base.append({ type: 'del', key })
  }

  async get (key) {
    await this.base.update()
    const node = await this.base.view.get(key)
    if (!node || !node.value) return null
    return node.value.value
  }

  createReadStream (range, opts) {
    return this.base.view.createReadStream(range, opts)
  }

  async update () {
    await this.base.update()
  }

  // Grant write access to a remote writer key (hex). Only a current
  // writer may do this; the op is linearized like any other.
  async addWriter (writerKeyHex) {
    await this.base.append({ type: 'addWriter', key: writerKeyHex })
  }

  async close () {
    if (this.discovery) {
      try { await this.discovery.destroy() } catch {}
    }
    if (this.swarm && this._ownsSwarm) {
      await this.swarm.destroy()
    }
    await this.base.close()
    if (this._ownsStore) await this.store.close()
  }
}

module.exports = SyncDB
