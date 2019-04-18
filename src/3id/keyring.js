const { HDNode } = require('ethers').utils
const nacl = require('tweetnacl')
nacl.util = require('tweetnacl-util')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')
const SimpleSigner = require('did-jwt').SimpleSigner
const { sha256 } = require('../utils/index')

// TODO - this path needs to be updated for real 3ids
const BASE_PATH = "m/7696500'/0'/0'"

class Keyring {
  constructor (seed) {
    this._seed = seed
    let baseNode
    if (this._seed.startsWith('xprv')) {
      baseNode = HDNode.fromExtendedKey(this._seed)
    } else {
      baseNode = HDNode.fromSeed(this._seed).derivePath(BASE_PATH)
    }

    this.signingKey = baseNode.derivePath("0")
    this.managementKey = baseNode.derivePath("1")
    const tmpEncKey = Buffer.from(baseNode.derivePath("2").privateKey.slice(2), 'hex')
    this.asymEncryptionKey = nacl.box.keyPair.fromSecretKey(new Uint8Array(tmpEncKey))
    this.symEncryptionKey = new Uint8Array(Buffer.from(baseNode.derivePath("3").privateKey.slice(2), 'hex'))
  }

  asymEncrypt (msg, toPublic, nonce) {
    nonce = nonce || randomNonce()
    toPublic = nacl.util.decodeBase64(toPublic)
    if (typeof msg === 'string') {
      msg = nacl.util.decodeUTF8(msg)
    }
    const ciphertext = nacl.box(msg, nonce, toPublic, this.asymEncryptionKey.secretKey)
    return {
      nonce: nacl.util.encodeBase64(nonce),
      ciphertext: nacl.util.encodeBase64(ciphertext)
    }
  }

  asymDecrypt (ciphertext, fromPublic, nonce, toBuffer) {
    fromPublic = nacl.util.decodeBase64(fromPublic)
    ciphertext = nacl.util.decodeBase64(ciphertext)
    nonce = nacl.util.decodeBase64(nonce)
    const cleartext = nacl.box.open(ciphertext, nonce, fromPublic, this.asymEncryptionKey.secretKey)
    if (toBuffer) {
      return cleartext ? Buffer.from(cleartext) : null
    }
    return cleartext ? nacl.util.encodeUTF8(cleartext) : null
  }

  symEncrypt (msg, nonce) {
    return symEncryptBase(msg, this.symEncryptionKey, nonce)
  }

  symDecrypt (ciphertext, nonce, toBuffer) {
    return symDecryptBase(ciphertext, this.symEncryptionKey, nonce, toBuffer)
  }

  getJWTSigner () {
    return SimpleSigner(this.signingKey.privateKey.slice(2))
  }

  getDBKey () {
    return ec.keyFromPrivate(this.signingKey.privateKey.slice(2))
  }

  getDBSalt () {
    return sha256(this.signingKey.derivePath('0').privateKey.slice(2))
  }

  getPublicKeys () {
    return {
      signingKey: this.signingKey.publicKey.slice(2),
      managementKey: this.managementKey.publicKey.slice(2),
      asymEncryptionKey: nacl.util.encodeBase64(this.asymEncryptionKey.publicKey)
    }
  }

  serialize () {
    return this._seed
  }
}

const randomNonce = () => {
  return nacl.randomBytes(24)
}

const symEncryptBase = (msg, symKey, nonce) => {
  nonce = nonce || randomNonce()
  if (typeof msg === 'string') {
    msg = nacl.util.decodeUTF8(msg)
  }
  const ciphertext = nacl.secretbox(msg, nonce, symKey)
  return {
    nonce: nacl.util.encodeBase64(nonce),
    ciphertext: nacl.util.encodeBase64(ciphertext)
  }
}

const symDecryptBase = (ciphertext, symKey, nonce, toBuffer) => {
  ciphertext = nacl.util.decodeBase64(ciphertext)
  nonce = nacl.util.decodeBase64(nonce)
  const cleartext = nacl.secretbox.open(ciphertext, nonce, symKey)
  if (toBuffer) {
    return cleartext ? Buffer.from(cleartext) : null
  }
  return cleartext ? nacl.util.encodeUTF8(cleartext) : null
}

module.exports = Keyring
