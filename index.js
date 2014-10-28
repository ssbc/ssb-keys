var fs       = require('fs')
var crypto   = require('crypto')
var ecc      = require('eccjs')
var k256     = ecc.curves.k256
var Blake2s  = require('blake2s')

function bsum (value) {
  return new Blake2s().update(value).digest()
}

exports.load = function(namefile) {
  try {
    function empty(v) { return !!v }
    var privateKeyStr = fs.readFileSync(namefile, 'ascii').replace(/\s*\#[^\n]*/g, '').split('\n').filter(empty).join('')
    var privateKey = new Buffer(privateKeyStr, 'hex')
    var k = ecc.restore(k256, privateKey)
    k.id = bsum(k.public)
    return k
  } catch (e) {
    return null
  }
} 

exports.createKeys = function(namefile, cb) {
  var privateKey = crypto.randomBytes(32)
  var k          = ecc.restore(k256, privateKey)
  var id         = bsum(k.public)

  var contents = [
  '# this is your SECRET name.',
  '# this name gives you magical powers.',
  '# with it you can mark your messages so that your friends can verify',
  '# that they really did come from you.',
  '#',
  '# if any one learns this name, they can use it to destroy your identity',
  '# NEVER show this to anyone!!!',
  '',
  k.private.toString('hex'),
  '',
  '# WARNING! It\'s vital that you DO NOT edit OR share your secret name',
  '# instead, share your public name',
  '# your public name: ' + id.toString('hex')
  ].join('\n')

  fs.writeFile(namefile, contents, function(err) {
    if (err) return cb(err)
    k.id = id
    cb(null, k)
  })
}