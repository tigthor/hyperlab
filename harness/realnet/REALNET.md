# realnet — proving filedrop + sync on the real public DHT

Everything else in this repo runs on the in-process testnet. This directory is
the rig that runs both apps **for real**: separate OS processes / separate
machines, rendezvous through the actual public hyperdht, real NATs in the way.

## What is proven (measured 2026-07-11)

Environment: macOS host on an **iPhone-hotspot uplink** (carrier NAT +
hotspot NAT, port-consistent: `randomized=false`), and a Linux container in a
colima VM on the same host (docker bridge + gvproxy user-mode NAT, which the
DHT observes as **port-randomizing / symmetric**: `randomized=true`,
`port=0`). Two genuinely distinct kernels and network stacks; rendezvous and
signalling always through the real public DHT. All raw JSON in `results/`.

| case | trials | result | connect (med) | path taken |
|---|---|---|---|---|
| filedrop, 2 processes, direct | 3 | **3/3** | 1.4 s | direct-lan |
| filedrop, 2 processes, forced relay | 2 | **2/2** | 3.8 s | **relayed** |
| sync serve/join + writer grant, 2 processes | 2 | **2/2** | 6.6 s (converge 6.7 s) | direct-lan |
| filedrop Mac → container (recv behind symmetric NAT) | 1 | **ok** | 1.7 s | direct-lan (container dialed out) |
| filedrop container → Mac (**server** behind symmetric NAT) | 1 | **ok** | 2.8 s | **direct-wan** (public-mapping punch, 41.186.…:3289) |
| sync Mac serve ↔ container join, full multi-writer loop | 1 | **ok** | 5.1 s / converge 6.9 s / loop 41.7 s | direct-lan |
| filedrop container ↔ Mac, holepunch+LAN disabled | 1 | **ok** | 3.6 s | **relayed** (blind-relay on Mac) |

Direct-connect success rate in this environment: **7/7 attempts** where a
direct path was allowed; **relay fallback carried real file bytes 3/3** when
punching was impossible or disabled. Throughput: ~8.6 MiB/s direct-LAN,
~0.7 MiB/s across the NAT-hairpin WAN path, ~1.6–8.8 MiB/s relayed
(relay co-located). DHT bootstrap dominates latency: 5–8 s on this uplink
before any connect starts.

### The symmetric-NAT relay gap — closed

Stock behaviour: two port-randomizing NATs cannot holepunch and the
connection **fails**; nothing falls back. What changed:

- `filedrop` (lib + CLI) and `SyncDB` now accept a blind-relay key
  (`--relay <64-hex>` / `FILEDROP_RELAY` env / `relayThrough` opt). hyperdht
  races direct holepunch vs relay and upgrades to direct when the punch wins,
  so passing a relay never makes things worse.
- `relay.js` here runs the relay itself: any reachable node (a $5 VPS is
  ideal; even a firewalled home node works since both sides dial out to it).
- filedrop additionally grew a relay-only **privacy mode**
  (`holepunch: false`, `shareLocalAddress/localConnection: false`): the peer
  only ever sees the relay's address, never yours.

## The rig

```
info.js         probe: bootstrap time, external addr, firewalled, randomized
relay.js        run a blind-relay node (prints key + every address it serves on)
drop-send.js    instrumented filedrop sender  -> one JSON result line
drop-recv.js    instrumented filedrop receiver -> one JSON result line
sync-serve.js   SyncDB side A: seed keys, grant writers (stdin or --grant-file)
sync-join.js    SyncDB side B: converge, get granted, write ack back
trial.js        N repeated two-process trials + aggregation -> results/*.json
```

Every script speaks the real public DHT (no `--bootstrap` flag given), emits
human progress on stderr and machine-readable JSON on stdout, and classifies
the winning path (`direct-lan` / `direct-wan` / `relayed`) by comparing the
UDX stream's remote address against the relay's advertised address list —
sampled *after* transfer, since hyperdht upgrades relay → direct mid-stream.

## Reproduce

Single machine, two processes, N trials:

```bash
node harness/realnet/trial.js drop --n 5 --size 4194304          # direct
node harness/realnet/trial.js drop --n 3 --mode force-relay      # relay-only
node harness/realnet/trial.js sync --n 3 --keys 50               # sync + writer loop
```

Two machines (the real thing):

```bash
# machine A
node harness/realnet/drop-send.js ./payload.bin
# -> prints a passphrase

# machine B
node harness/realnet/drop-recv.js <passphrase> ./out
```

```bash
# machine A                                   # machine B
node harness/realnet/sync-serve.js            node harness/realnet/sync-join.js <key>
# paste B's printed writer key into A's terminal; A grants, B acks, both exit 0
```

Symmetric-NAT insurance (run the relay anywhere reachable, ideally a VPS):

```bash
node harness/realnet/relay.js                 # prints <relay-key>
# then add to both sides:
--relay <relay-key>                           # drop-send/drop-recv/sync-*
filedrop send ./file --relay <relay-key>      # or FILEDROP_RELAY=<key>
```

A second stack on one physical box (how the container numbers above were made):

```bash
docker run -d --name hyperlab-peer node:22-bookworm sleep infinity
tar --exclude=node_modules --exclude=.git -czf /tmp/hl.tgz .
docker cp /tmp/hl.tgz hyperlab-peer:/ && docker exec hyperlab-peer bash -c \
  'mkdir /hyperlab && tar xzf /hl.tgz -C /hyperlab && cd /hyperlab && corepack enable && pnpm install'
docker exec hyperlab-peer node /hyperlab/harness/realnet/info.js
```

## Honest limits

- The two "machines" above share one physical uplink. The container's NAT is
  real and adversarial (symmetric), and one connection genuinely traversed
  the public mapping (`direct-wan`), but a two-homes / two-ISPs run is the
  remaining datapoint. The commands above are exactly that runbook; record a
  row per trial into the table.
- Both-sides-symmetric requires a reachable relay; that relay is
  self-hosted, not public infrastructure.
- Bootstrap (~5–8 s here) is the UX long pole, not the transfer itself.
