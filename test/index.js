var tape = require('tape')
var ssbkeys = require('../')

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
  t.ok(ssbkeys.verify(keys, sig, msg))

  t.end()

})
