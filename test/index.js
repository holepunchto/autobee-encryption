const { test } = require('brittle')
const crypto = require('hypercore-crypto')
const { AutobeeEncryption } = require('../index.js')

test('setSystemEncryption and getSystemEncryption roundtrip', async (t) => {
  const bootstrap = crypto.randomBytes(32)
  const encryptionKey = crypto.randomBytes(32)
  const context = ctx()

  let installed = null
  const core = {
    manifest: { version: 2 },
    ready() {},
    setEncryption(e) {
      installed = e
    }
  }
  await AutobeeEncryption.setSystemEncryption(bootstrap, encryptionKey, core)

  const readSide = AutobeeEncryption.getSystemEncryption(bootstrap, encryptionKey)

  const writeKeys = await installed.get(0, context)
  const readKeys = await readSide.get(0, context)

  t.alike(
    writeKeys.block,
    readKeys.block,
    'setSystemEncryption and getSystemEncryption must derive the same key for the system core'
  )
})

function ctx({ key = crypto.randomBytes(32), version = 2, userData = null } = {}) {
  return { key, manifest: { version, userData } }
}
