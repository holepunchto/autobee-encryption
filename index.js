const HypercoreEncryption = require('hypercore/lib/default-encryption.js')
const sodium = require('sodium-universal')
const crypto = require('hypercore-crypto')
const c = require('compact-encoding')
const b4a = require('b4a')

const ManifestData = {
  preencode(state, m) {
    c.uint.preencode(state, m.version)
    state.end++ // max flag is 2 so always one byte

    if (m.legacyBlocks) c.uint.preencode(state, m.legacyBlocks)
    if (m.namespace) c.fixed32.preencode(state, m.namespace)
  },
  encode(state, m) {
    const flags = (m.legacyBlocks ? 1 : 0) | (m.namespace ? 2 : 0)

    c.uint.encode(state, m.version)
    c.uint.encode(state, flags)

    if (m.legacyBlocks) c.uint.encode(state, m.legacyBlocks)
    if (m.namespace) c.fixed32.encode(state, m.namespace)
  },
  decode(state) {
    const r0 = c.uint.decode(state)
    const flags = c.uint.decode(state)

    return {
      version: r0,
      legacyBlocks: (flags & 1) !== 0 ? c.uint.decode(state) : 0,
      namespace: (flags & 2) !== 0 ? c.fixed32.decode(state) : null
    }
  }
}

const [, NS_VIEW_BLOCK_KEY, NS_HASH_KEY] = crypto.namespace('autobase', 4)

const [GENESIS_ENTROPY] = crypto.namespace('autobase/entropy', 2)

const nonce = b4a.alloc(sodium.crypto_stream_NONCEBYTES)
const hash = nonce.subarray(0, sodium.crypto_generichash_BYTES_MIN)

class AutobeeEncryption {
  static PADDING = 8

  constructor(auto) {
    this.auto = auto

    this.compat = null
    this.keys = null
    this.keysById = new Map()
  }

  get id() {
    return this.keys ? this.keys.id : 0
  }

  padding() {
    return AutobeeEncryption.PADDING
  }

  isCompat(ctx) {
    return ctx.manifest.version <= 1
  }

  load(keys) {
    if (this.keys === null) this.keys = keys
  }

  async update(ctx) {
    if (!this.keys) this.keys = await this.get(0, ctx)
  }

  async get(id, ctx) {
    if (this.keysById.has(id)) return this.keysById.get(id)

    const keys = await this.getKeys(id, ctx)
    this.keysById.set(id, keys)

    return keys
  }

  async getKeys(id, ctx) {
    if (!this.auto.encryptionKey) return null

    const entropy = GENESIS_ENTROPY
    const block = this.blockKey(entropy, ctx)
    const hash = crypto.hash([NS_HASH_KEY, block])

    return {
      id,
      block,
      hash
    }
  }

  blockKey(entropy, ctx) {
    return getBlockKey(this.auto.key, this.auto.encryptionKey, entropy, ctx.key)
  }

  async _ensureCompat(ctx) {
    if (!this.compat) this.compat = this.compatKeys(ctx)
  }

  compatKeys() {
    throw new Error('Compatibility method is not specified')
  }

  async encrypt(index, block, fork, ctx) {
    if (this.isCompat(ctx, index)) {
      this._ensureCompat(ctx)
      return HypercoreEncryption.encrypt(
        index,
        block,
        fork,
        this.compat.block,
        this.compat.blinding
      )
    }

    await this.update(ctx)

    encryptBlock(index, block, this.keys.id, this.keys.block, this.keys.hash)
  }

  async decrypt(index, block, ctx) {
    if (this.isCompat(ctx, index)) {
      this._ensureCompat(ctx)
      return HypercoreEncryption.decrypt(index, block, this.compat.block)
    }

    const padding = block.subarray(0, AutobeeEncryption.PADDING)
    block = block.subarray(AutobeeEncryption.PADDING)

    const type = padding[0]
    switch (type) {
      case 0:
        return block // unencrypted

      case 1:
        break

      default:
        throw new Error('Unrecognised encryption type')
    }

    const id = c.uint32.decode({ start: 4, end: 8, buffer: padding })

    const keys = await this.get(id, ctx)

    c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)
    nonce.set(padding, 8, 16)

    // Decrypt the block using the full nonce
    decrypt(block, nonce, keys.block)
  }

  static encryptAnchor(block, bootstrap, encryptionKey, namespace) {
    const entropy = GENESIS_ENTROPY

    const blockKey = getBlockKey(bootstrap, encryptionKey, entropy, namespace)
    const hashKey = crypto.hash([NS_HASH_KEY, block])

    encryptBlock(0, block, 0, blockKey, hashKey)
  }

  static async setSystemEncryption(bootstrap, encryptionKey, core, opts) {
    await core.ready()
    if (core.manifest.version === 1) {
      const key = getCompatBlockKey(bootstrap, encryptionKey, '_system')
      core.setEncryptionKey(key, { block: true })
      return
    }

    const info = {
      key: bootstrap,
      encryptionKey
    }

    return core.setEncryption(new ViewEncryption(info, 'system'))
  }
}

class ViewEncryption extends AutobeeEncryption {
  constructor(auto, name) {
    super(auto)
    this.name = name
  }

  compatKeys() {
    const block = getCompatBlockKey(this.auto.key, this.auto.encryptionKey, this.name)
    return {
      block,
      blinding: crypto.hash(block)
    }
  }

  blockKey(entropy) {
    return getCompatBlockKey(this.auto.key, entropy, this.name)
  }
}

class WriterEncryption extends AutobeeEncryption {
  compatKeys(ctx) {
    return HypercoreEncryption.deriveKeys(this.auto.encryptionKey, ctx.key)
  }

  blockKey(entropy, ctx) {
    // used for anchors
    if (ctx.manifest.userData) {
      const userData = c.decode(ManifestData, ctx.manifest.userData)
      if (userData.namespace !== null) {
        const b = getBlockKey(this.auto.key, this.auto.encryptionKey, entropy, userData.namespace)
        return b
      }
    }

    return getBlockKey(this.auto.key, this.auto.encryptionKey, entropy, ctx.key)
  }
}

module.exports = {
  AutobeeEncryption,
  WriterEncryption,
  ViewEncryption
}

function encrypt(block, nonce, key) {
  sodium.crypto_stream_xor(block, block, nonce, key)
}

function decrypt(block, nonce, key) {
  return encrypt(block, nonce, key) // symmetric
}

function getBlockKey(bootstrap, encryptionKey, entropy, hypercoreKey) {
  return (
    encryptionKey &&
    crypto.hash([NS_VIEW_BLOCK_KEY, bootstrap, encryptionKey, entropy, hypercoreKey])
  )
}

function getCompatBlockKey(bootstrap, encryptionKey, name) {
  if (typeof name === 'string') return getCompatBlockKey(bootstrap, encryptionKey, b4a.from(name))
  return encryptionKey && crypto.hash([NS_VIEW_BLOCK_KEY, bootstrap, encryptionKey, name])
}

function blockhash(block, padding, hashKey) {
  sodium.crypto_generichash(hash, block, hashKey)
  padding.set(hash.subarray(0, 8)) // copy first 8 bytes of hash
  hash.fill(0) // clear nonce buffer
}

function encryptBlock(index, block, id, blockKey, hashKey) {
  const padding = block.subarray(0, AutobeeEncryption.PADDING)
  block = block.subarray(AutobeeEncryption.PADDING)

  blockhash(block, padding, hashKey)
  c.uint32.encode({ start: 4, end: 8, buffer: padding }, id)

  c.uint64.encode({ start: 0, end: 8, buffer: nonce }, index)

  padding[0] = 1 // version in plaintext

  nonce.set(padding, 8, 16)

  // The combination of index, key id, fork id and block hash is very likely
  // to be unique for a given Hypercore and therefore our nonce is suitable
  encrypt(block, nonce, blockKey)
}
