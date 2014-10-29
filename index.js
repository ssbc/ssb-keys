var fs       = require('fs')
var crypto   = require('crypto')
var ecc      = require('eccjs')
var k256     = ecc.curves.k256
var Blake2s  = require('blake2s')

function bsum (value) {
  return new Blake2s().update(value).digest()
}
function empty(v) { return !!v }

function constructKeys() {
  var privateKey = crypto.randomBytes(32)
  var k          = ecc.restore(k256, privateKey)
  k.id           = bsum(k.public)
  k.keyfile      = [
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
  '# your public name: ' + k.id.toString('hex')
  ].join('\n')
  return k
}

function reconstructKeys(privateKeyStr) {
  privateKeyStr = privateKeyStr.replace(/\s*\#[^\n]*/g, '').split('\n').filter(empty).join('')
  var privateKey = new Buffer(privateKeyStr, 'hex')
  var k = ecc.restore(k256, privateKey)
  k.id = bsum(k.public)
  return k
}

exports.load = function(namefile, cb) {
  fs.readFile(namefile, 'ascii', function(err, privateKeyStr) {
    if (err) return cb(err)
    try { cb(null, reconstructKeys(privateKeyStr)) }
    catch (e) { cb(err) }
  })
}

exports.loadSync = function(namefile) {
  return reconstructKeys(fs.readFileSync(namefile, 'ascii'))
}

exports.create = function(namefile, cb) {
  var k = constructKeys()
  fs.writeFile(namefile, k.keyfile, function(err) {
    if (err) return cb(err)
    delete k.keyfile
    cb(null, k)
  })
}

exports.createSync = function(namefile) {
  var k = constructKeys()
  fs.writeFileSync(namefile, k.keyfile)
  delete k.keyfile
  return k
}