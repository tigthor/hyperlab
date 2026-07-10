// Minimal Node/Bare parity smoke: append one block to a real hypercore in a
// tmp dir and read it back. Runs under both runtimes:
//   node harness/smoke-bare.js
//   bare harness/smoke-bare.js
//
// No node:-prefixed imports, b4a instead of Buffer. Hypercore v11 storage
// (hypercore-storage / RocksDB) creates missing directories itself, so the
// happy path needs no fs/os at all — platform modules are only used for
// best-effort cleanup and tmp-dir placement. Under Bare those come from
// bare-fs/bare-os (the same mapping holepunch modules declare in their
// package.json 'imports' maps); if they are not resolvable we fall back to a
// dir next to this script and skip cleanup (CI runners are ephemeral).

const b4a = require('b4a')
const Hypercore = require('hypercore')

const isBare = typeof Bare !== 'undefined'

const fs = tryRequire(isBare ? 'bare-fs' : 'fs')
const os = tryRequire(isBare ? 'bare-os' : 'os')

const base = os ? os.tmpdir() : __dirname
const dir = base + '/hyperlab-smoke-' + Date.now() + '-' + Math.random().toString(16).slice(2)

main().then(
  function () {
    console.log('OK')
  },
  function (err) {
    console.error('SMOKE FAILED: ' + (err && err.stack ? err.stack : err))
    if (isBare) Bare.exitCode = 1
    else process.exitCode = 1
  }
)

async function main () {
  const core = new Hypercore(dir)
  await core.ready()

  const block = b4a.from('hello from ' + (isBare ? 'bare' : 'node'))
  await core.append(block)

  if (core.length !== 1) throw new Error('unexpected core length: ' + core.length)

  const read = await core.get(0)
  if (!b4a.isBuffer(read) || !b4a.equals(read, block)) {
    throw new Error('block read back does not match appended block')
  }

  await core.close()

  if (fs && fs.rmSync) {
    try {
      fs.rmSync(dir, { recursive: true, force: true })
    } catch {}
  }
}

function tryRequire (name) {
  try {
    return require(name)
  } catch {
    return null
  }
}
