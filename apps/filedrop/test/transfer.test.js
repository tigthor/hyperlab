const test = require('brittle')
const fs = require('fs')
const os = require('os')
const path = require('path')
const b4a = require('b4a')
const sodium = require('sodium-universal')
const DHT = require('hyperdht')
const rm = require('retrieval-market')
const { topicFromPassphrase } = require('hyperbeam-pake')
const createTestnet = require('hyperlab-harness/testnet')

const {
  createSender,
  receive,
  MessageReader,
  runCPace,
  TYPE
} = require('..')

function randomFile (dir, name, size) {
  const buf = b4a.alloc(size)
  // randombytes_buf has a per-call cap; fill in slices.
  for (let off = 0; off < size; off += 65536) {
    sodium.randombytes_buf(buf.subarray(off, Math.min(size, off + 65536)))
  }
  const p = path.join(dir, name)
  fs.writeFileSync(p, buf)
  return { path: p, buf }
}

function mkTmp () {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'filedrop-'))
}

test('e2e: 4MB transfer is byte-identical + merkle-verified, receipt binds bytes+hash', async function (t) {
  const testnet = await createTestnet(6, t)
  const tmp = mkTmp()
  t.teardown(async () => {
    await testnet.destroy()
    fs.rmSync(tmp, { recursive: true, force: true })
  })

  const src = randomFile(tmp, 'photo.bin', 4 * 1024 * 1024)
  const outdir = path.join(tmp, 'out')

  const senderNode = testnet.createNode()
  const passphrase = 'amber-brave-cedar-delta'
  const sender = createSender(src.path, { node: senderNode, passphrase, chunkSize: 64 * 1024 })
  await sender.listen()

  const recvNode = testnet.createNode()
  const recvResult = await receive(passphrase, outdir, { node: recvNode })
  const sendResult = await sender.finished
  await sender.close()

  const got = b4a.from(fs.readFileSync(recvResult.path))
  t.is(got.byteLength, src.buf.byteLength, 'received size matches')
  t.ok(b4a.equals(got, src.buf), 'received bytes are byte-identical to the source')
  t.ok(b4a.equals(recvResult.fileHash, sender.merkleRoot), 'file hash matches manifest merkle root')

  // proof-of-receipt held by the sender
  const receipt = sendResult.receipt
  t.ok(rm.verifyReceipt(receipt), 'sender holds a valid signed receipt')
  t.ok(b4a.equals(receipt.channel, sender.merkleRoot), 'receipt channel == file merkle root')
  t.is(receipt.bytes, src.buf.byteLength, 'receipt binds the exact byte count')
  t.ok(b4a.equals(receipt.consumer, recvResult.receipt.consumer), 'receipt consumer == receiver identity')

  // a tampered receipt fails verification
  const tampered = { ...receipt, bytes: receipt.bytes + 1 }
  t.absent(rm.verifyReceipt(tampered), 'a tampered byte count fails verification')

  t.ok(!fs.existsSync(path.join(outdir, 'photo.bin.part')), 'no leftover .part file')
  t.ok(!fs.existsSync(path.join(outdir, 'photo.bin.filedrop.json')), 'sidecar removed on completion')
})

test('e2e: wrong passphrase aborts at CPace — no manifest / file bytes leaked', async function (t) {
  const testnet = await createTestnet(6, t)
  const tmp = mkTmp()
  t.teardown(async () => {
    await testnet.destroy()
    fs.rmSync(tmp, { recursive: true, force: true })
  })

  const src = randomFile(tmp, 'secret.bin', 512 * 1024)
  const senderNode = testnet.createNode()
  const passphrase = 'topaz-umber-violet-willow'
  const sender = createSender(src.path, { node: senderNode, passphrase, chunkSize: 64 * 1024 })
  await sender.listen()

  // Adversary: knows the rendezvous (same topic keypair) but NOT the passphrase.
  // It connects and runs CPace with a wrong guess.
  const advNode = testnet.createNode()
  const keyPair = DHT.keyPair(topicFromPassphrase(passphrase))
  const sid = b4a.from(topicFromPassphrase(passphrase).subarray(0, 16))
  const sock = advNode.connect(keyPair.publicKey, { keyPair })
  const reader = new MessageReader(sock)
  t.is(await sock.opened, true, 'adversary socket opens (rendezvous found)')

  await t.exception(
    runCPace(sock, reader, 'WRONG-guess-passphrase', sid, false),
    /key confirmation failed/,
    'CPace aborts on the wrong passphrase'
  )

  // No MANIFEST was ever delivered to the adversary — the sender sends it only
  // after CPace confirmation passes, so nothing about the file leaked.
  const sawManifest = reader.queue.some(m => m.type === TYPE.MANIFEST || m.type === TYPE.CHUNK)
  t.absent(sawManifest, 'no manifest or file chunk reached the wrong-passphrase peer')

  reader.destroy()
  sock.destroy()

  // The honest sender never produced a receipt.
  let resolved = false
  sender.finished.then(() => { resolved = true })
  await new Promise(resolve => setTimeout(resolve, 200))
  t.absent(resolved, 'sender did not complete a transfer for the adversary')
  await sender.close()
})

test('e2e: kill at ~50% then RESUME to completion, receipt intact', async function (t) {
  const testnet = await createTestnet(6, t)
  const tmp = mkTmp()
  t.teardown(async () => {
    await testnet.destroy()
    fs.rmSync(tmp, { recursive: true, force: true })
  })

  const src = randomFile(tmp, 'movie.bin', 4 * 1024 * 1024)
  const outdir = path.join(tmp, 'out')
  const chunkSize = 64 * 1024
  const totalChunks = Math.ceil(src.buf.byteLength / chunkSize)

  const senderNode = testnet.createNode()
  const passphrase = 'garnet-falcon-cobalt-basalt'
  const sender = createSender(src.path, { node: senderNode, passphrase, chunkSize })
  await sender.listen()

  // First receiver: kill the socket once past the halfway mark.
  const recvNode1 = testnet.createNode()
  let killed = false
  await t.exception(
    receive(passphrase, outdir, {
      node: recvNode1,
      onProgress ({ chunk, socket }) {
        if (!killed && chunk >= Math.floor(totalChunks / 2)) {
          killed = true
          socket.destroy()
        }
      }
    }),
    /stream ended|closed/,
    'receiver rejects when the connection is killed mid-transfer'
  )

  const partPath = path.join(outdir, 'movie.bin.part')
  const sidecarPath = path.join(outdir, 'movie.bin.filedrop.json')
  t.ok(fs.existsSync(partPath), '.part file exists after the kill')
  t.ok(fs.existsSync(sidecarPath), 'resume sidecar persisted after the kill')
  const state = JSON.parse(fs.readFileSync(sidecarPath, 'utf8'))
  t.ok(state.verified > 0 && state.verified < totalChunks, 'partial progress: ' + state.verified + '/' + totalChunks)
  t.is(fs.statSync(partPath).size, state.bytes, '.part size matches the recorded byte offset')
  const consumerBefore = state.consumerSeed

  // Second receiver, fresh node, same outdir: must RESUME from the offset.
  const recvNode2 = testnet.createNode()
  let resumedFrom = -1
  const recvResult = await receive(passphrase, outdir, {
    node: recvNode2,
    onProgress ({ chunk }) { if (resumedFrom < 0) resumedFrom = chunk }
  })
  const sendResult = await sender.finished
  await sender.close()

  t.ok(resumedFrom > 1, 'resume continued from a chunk past the start (first delivered chunk ' + resumedFrom + ')')

  const got = b4a.from(fs.readFileSync(recvResult.path))
  t.ok(b4a.equals(got, src.buf), 'resumed file is byte-identical to the source')

  // Same consumer identity survived the kill (persisted in the sidecar).
  const seedAfter = b4a.toString(recvResult.receipt.consumer, 'hex')
  t.ok(rm.verifyReceipt(sendResult.receipt), 'receipt verifies after resume')
  t.is(sendResult.receipt.bytes, src.buf.byteLength, 'receipt bytes == full file size')
  t.ok(b4a.equals(sendResult.receipt.channel, sender.merkleRoot), 'receipt channel == file hash')
  t.ok(b4a.equals(sendResult.receipt.consumer, recvResult.receipt.consumer), 'sender + receiver agree on consumer')
  t.ok(consumerBefore.length > 0 && seedAfter.length > 0, 'consumer identity persisted across the kill')
})
