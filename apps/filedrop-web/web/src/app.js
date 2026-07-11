// filedrop web app — send + receive in the browser over a dht-relay gateway.
// All crypto (CPace gate, ISK-sealed frames, per-chunk verification) runs in
// this page; the gateway only relays ciphertext.

const DHT = require('@hyperswarm/dht-relay')
const Stream = require('@hyperswarm/dht-relay/ws')
const b4a = require('b4a')
const filedrop = require('filedrop/browser')

const $ = (sel) => document.querySelector(sel)

let nodePromise = null

function getNode () {
  if (nodePromise) return nodePromise
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const ws = new WebSocket(proto + '://' + location.host + '/relay')
  const node = new DHT(new Stream(true, ws))
  nodePromise = node.ready().then(() => node)
  return nodePromise
}

function setStatus (el, text, kind) {
  el.textContent = text
  el.dataset.kind = kind || 'info'
}

// ---------------------------------------------------------------------------
// chunk grid — one cell per chunk (bucketed above 256), fills as verified
// ---------------------------------------------------------------------------

function makeGrid (container, totalChunks) {
  container.innerHTML = ''
  const cells = Math.min(totalChunks, 256)
  const perCell = totalChunks / cells
  const els = []
  for (let i = 0; i < cells; i++) {
    const d = document.createElement('span')
    d.className = 'cell'
    container.appendChild(d)
    els.push(d)
  }
  container.hidden = false
  return {
    update (chunk) {
      const done = Math.floor(chunk / perCell)
      for (let i = 0; i < done && i < cells; i++) els[i].classList.add('on')
    },
    finish () {
      for (const el of els) el.classList.add('on', 'ok')
    }
  }
}

function fmtBytes (n) {
  const u = ['B', 'KiB', 'MiB', 'GiB']
  let i = 0
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++ }
  return n.toFixed(i === 0 ? 0 : 1) + ' ' + u[i]
}

// ---------------------------------------------------------------------------
// send
// ---------------------------------------------------------------------------

async function startSend (file) {
  const drop = $('#drop')
  const status = $('#send-status')
  const passWrap = $('#pass-wrap')
  const passEl = $('#passphrase')
  const gridEl = $('#send-grid')
  const meta = $('#send-meta')

  drop.classList.add('locked')
  meta.textContent = file.name + ' · ' + fmtBytes(file.size)
  setStatus(status, 'reading file…')

  const data = new Uint8Array(await file.arrayBuffer())

  setStatus(status, 'connecting to the DHT through the gateway…')
  const node = await getNode()

  const sender = filedrop.createSender(node, {
    name: file.name,
    data,
    onConnection () {
      setStatus(status, 'receiver connected — authenticating (CPace)…')
    },
    onProgress ({ chunk, totalChunks }) {
      if (!startSend.grid) startSend.grid = makeGrid(gridEl, totalChunks)
      startSend.grid.update(chunk)
      setStatus(status, 'sending chunk ' + chunk + ' / ' + totalChunks)
    }
  })

  passEl.textContent = sender.passphrase
  passWrap.hidden = false
  $('#send-hint').hidden = false

  await sender.listen()
  setStatus(status, 'listening on the DHT — waiting for a receiver. keep this page open.')

  const result = await sender.finished
  if (startSend.grid) startSend.grid.finish()
  setStatus(status, 'verified — receiver signed for ' + fmtBytes(result.bytes) +
    ' (receipt ' + b4a.toString(result.fileHash, 'hex').slice(0, 12) + '…)', 'ok')
  $('#send-hint').textContent = 'transfer complete. the passphrase is now spent — drop another file to send again.'
  await sender.close().catch(() => {})
}

// ---------------------------------------------------------------------------
// receive
// ---------------------------------------------------------------------------

async function startReceive (passphrase) {
  const status = $('#recv-status')
  const gridEl = $('#recv-grid')
  const saveWrap = $('#save-wrap')
  const btn = $('#recv-btn')

  btn.disabled = true
  setStatus(status, 'connecting to the DHT through the gateway…')

  let grid = null
  try {
    const node = await getNode()
    setStatus(status, 'finding the sender + authenticating (CPace)…')

    const result = await filedrop.receive(node, passphrase, {
      onProgress ({ chunk, totalChunks, bytes, name }) {
        if (!grid) grid = makeGrid(gridEl, totalChunks)
        grid.update(chunk)
        setStatus(status, name + ' — chunk ' + chunk + ' / ' + totalChunks + ' verified (' + fmtBytes(bytes) + ')')
      }
    })

    if (grid) grid.finish()
    setStatus(status, 'verified — ' + result.name + ' (' + fmtBytes(result.bytes) + ') · receipt signed', 'ok')

    const blob = new Blob([result.data])
    const a = $('#save-link')
    a.href = URL.createObjectURL(blob)
    a.download = result.name
    a.textContent = 'save ' + result.name
    saveWrap.hidden = false
  } catch (err) {
    const wrong = /confirmation failed/i.test(err.message)
    setStatus(status,
      wrong ? 'wrong passphrase — nothing was transferred.' : 'failed: ' + err.message,
      'err')
  } finally {
    btn.disabled = false
  }
}

// ---------------------------------------------------------------------------
// wire the page
// ---------------------------------------------------------------------------

function init () {
  const drop = $('#drop')
  if (drop) {
    const input = $('#file-input')
    drop.addEventListener('click', () => { if (!drop.classList.contains('locked')) input.click() })
    input.addEventListener('change', () => { if (input.files[0]) startSend(input.files[0]) })
    drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over') })
    drop.addEventListener('dragleave', () => drop.classList.remove('over'))
    drop.addEventListener('drop', (e) => {
      e.preventDefault()
      drop.classList.remove('over')
      if (!drop.classList.contains('locked') && e.dataTransfer.files[0]) startSend(e.dataTransfer.files[0])
    })
    document.addEventListener('paste', (e) => {
      const f = e.clipboardData && e.clipboardData.files && e.clipboardData.files[0]
      if (f && !drop.classList.contains('locked')) startSend(f)
    })
  }

  const recvForm = $('#recv-form')
  if (recvForm) {
    recvForm.addEventListener('submit', (e) => {
      e.preventDefault()
      const pass = $('#pass-input').value.trim().toLowerCase().replace(/\s+/g, '-')
      if (pass) startReceive(pass)
    })
    const params = new URLSearchParams(location.search)
    if (params.get('p')) {
      $('#pass-input').value = params.get('p')
      startReceive(params.get('p'))
    }
  }

  const copyBtn = $('#copy-pass')
  if (copyBtn) {
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText($('#passphrase').textContent)
        copyBtn.textContent = 'copied'
        setTimeout(() => { copyBtn.textContent = 'copy' }, 1500)
      } catch {}
    })
  }
  const linkBtn = $('#copy-link')
  if (linkBtn) {
    linkBtn.addEventListener('click', async () => {
      const url = location.origin + '/app?p=' + encodeURIComponent($('#passphrase').textContent)
      try {
        await navigator.clipboard.writeText(url)
        linkBtn.textContent = 'copied'
        setTimeout(() => { linkBtn.textContent = 'copy link' }, 1500)
      } catch {}
    })
  }
}

init()
