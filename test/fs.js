var tape = require('tape')
var ssbkeys = require('../')
var crypto = require('crypto')
var path = require('path')
var os = require('os')
var fs = require('fs')

const keyPath = path.join(os.tmpdir(), `ssb-keys-${Date.now()}`)
console.log(keyPath)

tape('create and load presigil-legacy async', function (t) {

  var keys = ssbkeys.generate('ed25519')
  keys.id = keys.id.substring(1)
  fs.writeFileSync(keyPath, JSON.stringify(keys))

  var k2 = ssbkeys.loadSync(keyPath)
  t.equal(k2.id, '@' + keys.id)
  t.end()

})

tape('create and load presigil-legacy', function (t) {

  var keys = ssbkeys.generate('ed25519')
  keys.id = keys.id.substring(1)
  fs.writeFileSync(keyPath, JSON.stringify(keys))

  ssbkeys.load(keyPath, function (err, k2) {
    if(err) throw err
    t.equal(k2.id, '@' + keys.id)
    t.end()
  })

})

tape('prevent clobbering existing keys', function (t) {

  fs.writeFileSync(keyPath, 'this file intentionally left blank', 'utf8')
  t.throws(function () {
    ssbkeys.createSync(keyPath)
  })
  ssbkeys.create(keyPath, function (err) {
    t.ok(err)
    fs.unlinkSync(keyPath)
    t.end()
  })

})
