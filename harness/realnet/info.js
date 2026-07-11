#!/usr/bin/env node
// realnet/info — probe this machine's view of the real public DHT.
//
// Boots a real hyperdht node, waits for full bootstrap, and reports the
// facts that decide whether direct connections from here can work at all:
// external host:port, firewalled state, and whether the NAT randomizes
// ports (randomized === symmetric-ish NAT => holepunching to another
// randomized NAT will fail and a relay is required).
//
//   node harness/realnet/info.js [--json]

const DHT = require('hyperdht')

async function main () {
  const json = process.argv.includes('--json')
  const t0 = Date.now()
  const node = new DHT()

  await node.ready()
  const readyMs = Date.now() - t0

  await node.fullyBootstrapped()
  const bootstrappedMs = Date.now() - t0

  // one real lookup round-trip to prove the routing table is live
  const topic = require('crypto').randomBytes(32)
  const q0 = Date.now()
  let responses = 0
  try {
    const stream = node.findPeer(topic)
    for await (const _ of stream) responses++ // eslint-disable-line no-unused-vars
  } catch {}
  const lookupMs = Date.now() - q0

  const report = {
    ok: true,
    readyMs,
    bootstrappedMs,
    lookupMs,
    lookupResponses: responses,
    host: node.host,
    port: node.port,
    firewalled: node.firewalled,
    randomized: node.randomized, // true => port-randomizing (symmetric-ish) NAT
    ephemeral: node.ephemeral,
    online: node.online
  }

  if (json) {
    console.log(JSON.stringify(report))
  } else {
    console.log('realnet probe — public DHT')
    console.log('  bootstrapped:      ' + bootstrappedMs + ' ms (ready ' + readyMs + ' ms)')
    console.log('  lookup round:      ' + lookupMs + ' ms (' + responses + ' closest-node replies)')
    console.log('  external address:  ' + report.host + ':' + report.port)
    console.log('  firewalled:        ' + report.firewalled)
    console.log('  port-randomizing:  ' + report.randomized + (report.randomized ? '  (symmetric NAT — direct connects to another such NAT will need a relay)' : ''))
  }

  await node.destroy()
}

main().catch(err => {
  console.error(JSON.stringify({ ok: false, error: err.message }))
  process.exit(1)
})
