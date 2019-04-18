const { HDNode } = require('ethers').utils
const { caller } = require('postmsg-rpc')
const didJWT = require('did-jwt')
const IpfsMini = require('ipfs-mini')
const localstorage = require('store')
const utils = require('../utils/index')
const Keyring = require('./keyring')
const config = require('../config.js')

const STORAGE_KEY = 'serialized3id_'
const MUPORT_IPFS = { host: config.muport_ipfs_host, port: config.muport_ipfs_port, protocol: config.muport_ipfs_protocol}

let iframeLoadedPromise, authenticateApp

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  const iframe = document.createElement('iframe')
  iframe.setAttribute("src", config.account_frame_url)
  iframe.style = 'width:640px; height:480px; border:0; border:none !important'
  const contain = document.createElement('div')
  contain.align = 'center'
  // TODO - make this styling more nice
  contain.style = 'display: none; z-index: 999; position: absolute; top: 0px; left: 0px; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.6);'
  contain.appendChild(iframe);

  document.body.appendChild(contain)

  iframeLoadedPromise = new Promise((resolve, reject) => {
    iframe.onload = () => { resolve() }
  })

  const postMessage = iframe.contentWindow.postMessage.bind(iframe.contentWindow)
  authenticateApp = async spaces => {
    contain.style.display = 'block'
    const auth = caller('auth', { postMessage })
    let keys
    try {
      keys = await auth(spaces)
    } catch (e) {
      contain.style.display = 'none'
      throw new Error('3Box: User denied access:\n ' + e.message)
    }
    contain.style.display = 'none'
    return keys
  }
}

class ThreeId {
  constructor (serializedState, ipfs, opts) {
    this._ethereum = opts.ethereum
    this._ipfs = ipfs
    this._keyrings = {}
    this._init3id(serializedState, opts)
    if (this.managementAddress) {
      localstorage.set(STORAGE_KEY + this.managementAddress, this.serializeState())
    }
  }

  async signJWT (payload) {
    const settings = {
      signer: this._mainKeyring.getJWTSigner(),
      issuer: this.getDid()
    }
    return didJWT.createJWT(payload, settings)
  }

  getDid () {
    return this._muportDID
  }

  serializeState () {
    if (!this.managementAddress) throw new Error('serializing state only supported with eth access')
    let stateObj = {
      managementAddress: this.managementAddress,
      seed: this._mainKeyring.serialize(),
      spaceSeeds: {},
    }
    Object.keys(this._keyrings).map(name => {
      stateObj.spaceSeeds[name] = this._keyrings[name].serialize()
    })
    return JSON.stringify(stateObj)
  }

  _init3id (serializedState) {
    const state = JSON.parse(serializedState)
    // TODO remove toLowerCase() in future, should be sanitized elsewhere
    //      this forces existing state to correct state so that address <->
    //      rootstore relation holds
    if (state.managementAddress) {
      this.managementAddress = state.managementAddress.toLowerCase()
    }
    if (state.main) {
      // main and spaces is used by account.3box.io
      // they contain xprv instead of seeds,
      // which the keyring can handle
      state.seed = state.main
      state.spaceSeeds = state.spaces
    }
    this._mainKeyring = new Keyring(state.seed)
    Object.keys(state.spaceSeeds).map(name => {
      this._keyrings[name] = new Keyring(state.spaceSeeds[name])
    })
  }

  async _initMuport (muportIpfs) {
    let keys = this._mainKeyring.getPublicKeys()
    const doc = createMuportDocument(
      keys.signingKey,
      this.managementAddress ? this.managementAddress : keys.managementKey,
      keys.asymEncryptionKey
    )
    let docHash = (await this._ipfs.files.add(Buffer.from(JSON.stringify(doc))))[0].hash
    this._muportDID = 'did:muport:' + docHash
    this.muportFingerprint = utils.sha256Multihash(this._muportDID)
    const publishToInfura = async () => {
      const ipfsMini = new IpfsMini(muportIpfs)
      ipfsMini.addJSON(doc, (err, res) => {
        if (err) console.error(err)
      })
    }
    publishToInfura()
  }

  getKeyringBySpaceName (name) {
    const split = name.split('.')
    if (split[0] === this.muportFingerprint) {
      return this._mainKeyring
    } else {
      return this._keyrings[split[2]]
    }
  }

  async initKeyringByName (name) {
    if (!this._keyrings[name]) {
      if (this.managementAddress) {
        const sig = await utils.openSpaceConsent(this.managementAddress, this._ethereum, name)
        const entropy = '0x' + utils.sha256(sig.slice(2))
        const seed = HDNode.mnemonicToSeed(HDNode.entropyToMnemonic(entropy))
        this._keyrings[name] = new Keyring(seed)
        localstorage.set(STORAGE_KEY + this.managementAddress, this.serializeState())
      } else {
        const keys = await authenticateApp([name])
        const key = keys.spaces[name]
        this._keyrings[name] = new Keyring(key)
      }
      return true
    } else {
      return false
    }
  }

  logout() {
    localstorage.remove(STORAGE_KEY + this.managementAddress)
  }

  static isLoggedIn (address) {
    return Boolean(localstorage.get(STORAGE_KEY + address.toLowerCase()))
  }

  static async getIdFromEthAddress (address, ipfs, opts = {}) {
    const normalizedAddress = address.toLowerCase()
    let serialized3id = localstorage.get(STORAGE_KEY + normalizedAddress)
    if (serialized3id) {
      if (opts.consentCallback) opts.consentCallback(false)
    } else {
      const sig = await utils.openBoxConsent(normalizedAddress, ethereum)
      if (opts.consentCallback) opts.consentCallback(true)
      const entropy = '0x' + utils.sha256(sig.slice(2))
      const mnemonic = HDNode.entropyToMnemonic(entropy)
      const seed = HDNode.mnemonicToSeed(mnemonic)
      serialized3id = JSON.stringify({
        managementAddress: normalizedAddress,
        seed,
        spaceSeeds: {}
      })
    }
    const _3id = new ThreeId(serialized3id, ipfs, opts)
    await _3id._initMuport(opts.muportIpfs || MUPORT_IPFS)
    return _3id
  }

  static async getIdFromAuth(spaces, ipfs, opts = {}) {
    await iframeLoadedPromise
    const keys = await authenticateApp(spaces)
    let serialized3id = JSON.stringify(keys)
    const _3id = new ThreeId(serialized3id, ipfs, opts)
    await _3id._initMuport(opts.muportIpfs || MUPORT_IPFS)
    return _3id
  }
}

const createMuportDocument = (signingKey, managementKey, asymEncryptionKey) => {
  return {
    version: 1,
    signingKey,
    managementKey,
    asymEncryptionKey
  }
}

module.exports = ThreeId
