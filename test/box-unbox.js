var tape = require('tape')
var ssbkeys = require('../')

tape('box, unbox', function (t) {

  var alice = ssbkeys.generate()
  var bob = ssbkeys.generate()

  var boxed = ssbkeys.box({okay: true}, [bob.public, alice.public])
  console.log('boxed')
  var msg = ssbkeys.unbox(boxed, alice.private)
  t.deepEqual(msg, {okay: true})
  t.end()
})

tape('return undefined for invalid content', function (t) {

  var alice = ssbkeys.generate()
  var bob = ssbkeys.generate()

  var msg = ssbkeys.unbox('this is invalid content', alice.private)
  t.equal(msg, undefined)
  t.end()
})
