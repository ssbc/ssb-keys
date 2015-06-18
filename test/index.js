var tape = require('tape')
var ssbkeys = require('../')
var crypto = require('crypto')
var path = require('path').join(__dirname, 'keyfile')

tape('create and load async', function (t) {
  try { require('fs').unlinkSync(path) } catch(e) {}
  ssbkeys.create(path, function(err, k1) {
    if (err) throw err
    ssbkeys.load(path, function(err, k2) {
      if (err) throw err
      t.equal(k1.id.toString('hex'), k2.id.toString('hex'))
      t.equal(k1.private.toString('hex'), k2.private.toString('hex'))
      t.equal(k1.public.toString('hex'), k2.public.toString('hex'))
      t.end()
    })
  })
})

tape('create and load sync', function (t) {
  try { require('fs').unlinkSync(path) } catch(e) {}
  var k1 = ssbkeys.createSync(path)
  var k2 = ssbkeys.loadSync(path)
  t.equal(k1.id.toString('hex'), k2.id.toString('hex'))
  t.equal(k1.private.toString('hex'), k2.private.toString('hex'))
  t.equal(k1.public.toString('hex'), k2.public.toString('hex'))
  t.end()
})


tape('sign and verify', function (t) {

  var keys = ssbkeys.generate()
  var msg = ssbkeys.hash("HELLO THERE?")
  var sig = ssbkeys.sign(keys, msg)
  console.log('public', keys.public)
  console.log('sig', sig)
  t.ok(sig)
  t.equal(ssbkeys.getTag(sig), 'blake2s.ed25519')
  t.ok(ssbkeys.verify(keys, sig, msg))

  t.end()

})

tape('sign and verify, call with keys directly', function (t) {

  var keys = ssbkeys.generate()
  var msg = ssbkeys.hash("HELLO THERE?")
  var sig = ssbkeys.sign(keys.private, msg)
  console.log('public', keys.public)
  console.log('sig', sig)
  t.ok(sig)
  t.equal(ssbkeys.getTag(sig), 'blake2s.ed25519')
  t.ok(ssbkeys.verify(keys.public, sig, msg))

  t.end()

})

tape('sign and verify a javascript object', function (t) {

  var obj = require('../package.json')

  console.log(obj)

  var keys = ssbkeys.generate()
  var sig = ssbkeys.signObj(keys.private, obj)
  console.log(sig)
  t.ok(sig)
  t.ok(ssbkeys.verifyObj(keys, sig, obj))
  t.end()

})

tape('test legacy curve: k256', function (t) {
  var keys = ssbkeys.generate('k256')

  var msg = ssbkeys.hash("LEGACY SYSTEMS")
  var sig = ssbkeys.sign(keys, msg)

  console.log('public', keys.public)
  console.log('sig', sig)

  t.ok(sig)
  t.equal(ssbkeys.getTag(sig), 'blake2s.k256')
  t.ok(ssbkeys.verify(keys, sig, msg))

  t.end()
})

tape('create and load async, legacy', function (t) {
  try { require('fs').unlinkSync(path) } catch(e) {}
  ssbkeys.create(path, 'k256', function(err, k1) {
    if (err) throw err
    ssbkeys.load(path, function(err, k2) {
      if (err) throw err

      t.equal(k2.curve, 'k256')
      t.equal(k1.id, k2.id)
      t.equal(k1.private, k2.private)
      t.equal(k1.public, k2.public)

      t.end()
    })
  })
})

tape('create and load sync, legacy', function (t) {
  try { require('fs').unlinkSync(path) } catch(e) {}
  var k1 = ssbkeys.createSync(path, 'k256', true)
  var k2 = ssbkeys.loadSync(path)

  console.log(k2)

  t.equal(k2.curve, 'k256')
  t.equal(k1.id, k2.id)
  t.equal(k1.private, k2.private)
  t.equal(k1.public, k2.public)

  t.end()
})

tape('seeded keys, ed25519', function (t) {

  var seed = crypto.randomBytes(32)
  var k1 = ssbkeys.generate('ed25519', seed)
  var k2 = ssbkeys.generate('ed25519', seed)

  t.deepEqual(k1, k2)

  t.end()

})

tape('seeded keys, k256', function (t) {

  var seed = crypto.randomBytes(32)
  var k1 = ssbkeys.generate('k256', seed)
  var k2 = ssbkeys.generate('k256', seed)

  t.deepEqual(k1, k2)

  t.end()

})
