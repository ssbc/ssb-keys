import * as ssbkeys from '..'
import * as tape from 'tape'
import * as crypto from 'crypto'
const path = '/tmp/ssb-keys_' + Date.now()

tape('create and load async', function (t) {
  console.log(ssbkeys)
  ssbkeys.create(path, function (err, k1) {
    if (err) throw err
    ssbkeys.load(path, function (err, k2) {
      if (err) throw err
      t.equal(k1.id.toString(), k2.id.toString())
      t.equal(k1.private.toString(), k2.private.toString())
      t.equal(k1.public.toString(), k2.public.toString())
      t.end()
    })
  })
})

tape('create and load sync', function (t) {
  var k1 = ssbkeys.createSync(path + '1')
  var k2 = ssbkeys.loadSync(path + '1')
  t.equal(k1.id.toString(), k2.id.toString())
  t.equal(k1.private.toString(), k2.private.toString())
  t.equal(k1.public.toString(), k2.public.toString())
  t.end()
})

tape('sign and verify a javascript object', function (t) {

  var obj = require('../package.json')
  var hmac_key = crypto.randomBytes(32)
  var hmac_key2 = crypto.randomBytes(32)
  console.log(obj)

  var keys = ssbkeys.generate()
  var sig = ssbkeys.signObj(keys.private, hmac_key, obj)
  console.log(sig)
  t.ok(sig)
  //verify must be passed the key to correctly verify
  t.notOk(ssbkeys.verifyObj(keys, sig))
  t.ok(ssbkeys.verifyObj(keys, hmac_key, sig))
  //a different hmac_key fails to verify
  t.notOk(ssbkeys.verifyObj(keys, hmac_key2, sig))
  t.end()

})

//allow sign and verify to also take a separate key
//so that we can create signatures that cannot be used in other places.
//(i.e. testnet) avoiding chosen protocol attacks.
tape('sign and verify a hmaced object javascript object', function (t) {

  var obj = require('../package.json')

  console.log(obj)

  var keys = ssbkeys.generate()
  var sig = ssbkeys.signObj(keys.private, obj)
  console.log(sig)
  t.ok(sig)
  t.ok(ssbkeys.verifyObj(keys, sig))
  t.end()

})

tape('seeded keys, ed25519', function (t) {

  var seed = crypto.randomBytes(32)
  var k1 = ssbkeys.generate('ed25519', seed)
  var k2 = ssbkeys.generate('ed25519', seed)

  t.deepEqual(k1, k2)

  t.end()

})

tape('ed25519 id === "@" ++ pubkey', function (t) {

  var keys = ssbkeys.generate('ed25519')
  t.equal(keys.id, '@' + keys.public)

  t.end()

})
