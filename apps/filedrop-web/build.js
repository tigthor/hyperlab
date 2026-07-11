// build the browser bundle + copy static pages into web/dist
const esbuild = require('esbuild')
const fs = require('fs')
const path = require('path')

const here = __dirname
const dist = path.join(here, 'web', 'dist')

async function main () {
  fs.mkdirSync(dist, { recursive: true })

  await esbuild.build({
    entryPoints: [path.join(here, 'web', 'src', 'app.js')],
    bundle: true,
    minify: true,
    platform: 'browser',
    format: 'iife',
    outfile: path.join(dist, 'app.bundle.js'),
    define: {
      global: 'globalThis',
      'process.env.NODE_ENV': '"production"'
    },
    logLevel: 'info'
  })

  for (const f of fs.readdirSync(path.join(here, 'web', 'static'))) {
    fs.copyFileSync(path.join(here, 'web', 'static', f), path.join(dist, f))
  }
  console.log('built web/dist')
}

main().catch((err) => { console.error(err); process.exit(1) })
