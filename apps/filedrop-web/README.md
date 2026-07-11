# filedrop-web

filedrop in the browser: a one-page landing + drag-drop web app, served by a
gateway that relays the real DHT over a websocket (`@hyperswarm/dht-relay`).

```bash
pnpm build          # bundle web/dist (esbuild)
node gateway.js     # serve http://localhost:8080 + ws /relay on the real DHT
```

Drop a file → the page prints a four-word passphrase → anyone runs
`filedrop receive <passphrase>` (CLI) or opens `/app`, types it, and receives —
browser↔CLI in either direction, across the real public DHT.

## Trust model

The gateway terminates the dht-relay transport (custodial mode — non-custodial
announces don't work against hyperdht 6.33), so by itself it could read the
relayed noise stream. That is why the filedrop protocol seals **every**
post-CPace frame with a key derived from the passphrase (see
`filedrop/protocol.js` SecretChannel): the passphrase never reaches the
gateway, so the gateway relays ciphertext it cannot open, and chunk hashes and
receipts are verified in the page. A malicious gateway is a denial of service,
not a leak. Run your own with one command; nothing about the page trusts OUR
gateway specifically.

Browser-compat notes (all verified end-to-end in a real Chromium against the
public DHT, 2026-07-11 — see docs/):

- sodium-universal maps to sodium-javascript in the browser, which lacks
  `crypto_pwhash` and the xchacha AEAD. The topic KDF therefore uses
  `@noble/hashes` argon2id (byte-identical to libsodium, regression-tested in
  hyperbeam-pake) and the SecretChannel uses `@noble/ciphers`
  xchacha20poly1305 — the same pure-JS code paths under Node and browser.
- dht-relay 0.4.3 crashed the whole gateway when any relayed stream errored at
  teardown (destroy codec encoded an undefined alias);
  `patches/@hyperswarm__dht-relay@0.4.3.patch` fixes it.

## What about sync in the browser?

The transport half works today: `test/relay.test.js` replicates a SyncDB over
a hyperswarm running on the relayed DHT. The blocker is storage — corestore 7
requires hypercore-storage (rocksdb-native), which has no browser build and no
in-memory fallback. Until upstream grows a browser storage backend, sync stays
Node/Bare/desktop; the web story for it ends at the transport layer.
