/* global describe, it */

const assert = require('assert')
const bitcoinSecp256r1 = require('../')
const bip39 = require('bip39')

const fixtures = require('./testData.json')

const path = fixtures.path
const mnemonic = fixtures.mnemonic
const expectedSeed = fixtures.expectedSeed
const expectedRootKey = fixtures.expectedRootKey

const expectedPrivateKey = '86c82c2d32256df8ef2092903ffd493ee69c90ae375ede0f13df6b7d12848312'

const expectedWIF = 'L1ji6SHaWhGBPSj7qdvzPBR5fhuP9rAfzxmdDwAg33S32XLaBNbN'

describe('bitcoinSecp256r1', function () {
  it('mnemonic', function () {
    const actualSeed = bip39.mnemonicToSeed(mnemonic)
    assert.equal(actualSeed.toString('hex'), expectedSeed, 'seed must match expected')

    const rootNode = bitcoinSecp256r1.HDNode.fromSeedBuffer(actualSeed, bitcoinSecp256r1.bitcoin)
    assert.equal(rootNode.toBase58(), expectedRootKey, 'RootKey must match expected')

    const actualPathNode = rootNode.derivePath(path)
    const actualPathNodeChild0 = actualPathNode.derive(0)
    const actualPrivateKey = actualPathNodeChild0.keyPair.d.toBuffer(32).toString('hex')
    assert.equal(actualPrivateKey, expectedPrivateKey, 'private key must match expected')

    const actualWIF = actualPathNodeChild0.keyPair.toWIF()
    assert.equal(actualWIF, expectedWIF, 'WIF must match expected')
  })
})

const expectedSlip100RootKey = 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35'
const expectedSlip100PrivateKey = 'edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea'
// const expectedSlip100WIF = '';

describe('slip-0010-secp256r1', function () {
  it('mnemonic', function () {
    const actualSeed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex')

    const rootNode = bitcoinSecp256r1.HDNode.fromSeedBuffer(actualSeed, bitcoinSecp256r1.bitcoin)
    assert.equal(rootNode.keyPair.d.toBuffer(32).toString('hex'), expectedSlip100RootKey, 'RootKey must match expected')

    const actualPathNode = rootNode.deriveHardened(0)
    assert.equal(actualPathNode.keyPair.d.toBuffer(32).toString('hex'), expectedSlip100PrivateKey, 'M_PrivateKey must match expected')
  })
})
