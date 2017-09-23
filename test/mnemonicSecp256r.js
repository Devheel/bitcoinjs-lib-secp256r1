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

const expectedSlip100RootKey = '612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2'
const expectedSlip100PrivateKey = '6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c'
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
