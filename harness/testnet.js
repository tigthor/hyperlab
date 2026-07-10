const createUpstreamTestnet = require('hyperdht/testnet')

// Thin wrapper around hyperdht's in-process testnet.
//
// Upstream already accepts a teardown *function* via opts.teardown
// (e.g. t.teardown). Convenience added here: opts.teardown may also be
// a brittle test object, in which case its teardown method is used.
module.exports = async function createTestnet (size = 10, opts = {}) {
  if (
    opts &&
    opts.teardown &&
    typeof opts.teardown !== 'function' &&
    typeof opts.teardown.teardown === 'function'
  ) {
    opts = { ...opts, teardown: opts.teardown.teardown.bind(opts.teardown) }
  }

  return createUpstreamTestnet(size, opts)
}
