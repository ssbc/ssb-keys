var tape = require('tape')
var ssbkeys = require('..')

tape('secretBox, secretUnbox', function (t) {

  var key = Buffer.from('somewhere-over-the-rainbow-way-up-high')

  var boxed = ssbkeys.secretBox({okay: true}, key)
  console.log('boxed')
  var msg = ssbkeys.secretUnbox(boxed, key)
  t.deepEqual(msg, {okay: true})
  t.end()
})
