#!/usr/bin/env node
// filedrop CLI — serverless encrypted file transfer over the real DHT.
//
//   filedrop send <file>              print a passphrase, wait for a receiver
//   filedrop receive <pass> [dir]     connect and pull the file into dir (cwd)

const DHT = require('hyperdht')
const { createSender, receive } = require('.')

function fmtBytes (n) {
  const u = ['B', 'KiB', 'MiB', 'GiB']
  let i = 0
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++ }
  return n.toFixed(i === 0 ? 0 : 1) + ' ' + u[i]
}

function progressBar (frac) {
  const w = 24
  const filled = Math.round(frac * w)
  return '[' + '#'.repeat(filled) + '-'.repeat(w - filled) + ']'
}

async function cmdSend (file) {
  if (!file) fail('usage: filedrop send <file>')
  const node = new DHT()
  let sender
  const start = Date.now()
  let lastLine = 0
  try {
    sender = createSender(file, {
      node,
      onProgress ({ chunk, totalChunks }) {
        const now = Date.now()
        if (now - lastLine < 80 && chunk !== totalChunks) return
        lastLine = now
        const frac = chunk / totalChunks
        process.stderr.write('\r  ' + progressBar(frac) + ' ' + Math.round(frac * 100) + '%  sending   ')
      }
    })
    const total = sender.totalChunks
    process.stderr.write('\nfiledrop — sending ' + file + ' (' + fmtBytes(sender.size) + ', ' + total + ' chunks)\n')
    process.stderr.write('\n  passphrase:  ' + sender.passphrase + '\n')
    process.stderr.write('\n  on the other machine run:\n    filedrop receive ' + sender.passphrase + '\n\n')

    await sender.listen()
    process.stderr.write('  waiting for a receiver...\n')

    const result = await sender.finished
    const secs = (Date.now() - start) / 1000
    process.stderr.write('\r  ' + progressBar(1) + ' 100%  transfer complete\n')
    process.stderr.write('\n  receipt verified: receiver signed for ' + fmtBytes(result.bytes) +
      ' of file-hash ' + result.fileHash.toString('hex').slice(0, 16) + '...\n')
    process.stderr.write('  average throughput: ' + fmtBytes(result.bytes / secs) + '/s\n\n')
  } finally {
    if (sender) await sender.close().catch(() => {})
    await node.destroy()
  }
}

async function cmdReceive (passphrase, dir) {
  if (!passphrase) fail('usage: filedrop receive <passphrase> [dir]')
  const outdir = dir || process.cwd()
  const node = new DHT()
  const start = Date.now()
  try {
    process.stderr.write('\nfiledrop — connecting with passphrase "' + passphrase + '"...\n\n')
    let lastLine = 0
    const result = await receive(passphrase, outdir, {
      node,
      onProgress ({ chunk, totalChunks, bytes }) {
        const now = Date.now()
        if (now - lastLine < 80 && chunk !== totalChunks) return
        lastLine = now
        const frac = chunk / totalChunks
        const secs = (now - start) / 1000 || 1
        process.stderr.write('\r  ' + progressBar(frac) + ' ' +
          Math.round(frac * 100) + '%  ' + fmtBytes(bytes) +
          '  ' + fmtBytes(bytes / secs) + '/s   ')
      }
    })
    process.stderr.write('\n\n  saved: ' + result.path + '\n')
    process.stderr.write('  signed a receipt for ' + fmtBytes(result.bytes) + '. done.\n\n')
  } finally {
    await node.destroy()
  }
}

function fail (msg) {
  process.stderr.write('error: ' + msg + '\n')
  process.exit(1)
}

async function main () {
  const [cmd, a, b] = process.argv.slice(2)
  if (cmd === 'send') await cmdSend(a)
  else if (cmd === 'receive') await cmdReceive(a, b)
  else fail('usage: filedrop <send <file> | receive <pass> [dir]>')
}

main().then(() => process.exit(0)).catch(err => fail(err.message))
