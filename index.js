var deepEqual  = require('deep-equal')

var crypto     = require('crypto')
var createHmac = require('hmac')

var sodium     = require('chloride')
var ssbref     = require('ssb-ref')

var pb         = require('private-box')

var u          = require('./util')

var isBuffer = Buffer.isBuffer

function isString (s) {
  return 'string' === typeof s
}
//UTILS


function hasSigil (s) {
  return /^(@|%|&)/.test(s)
}

function clone (obj) {
  var _obj = {}
  for(var k in obj) {
    if(Object.hasOwnProperty.call(obj, k))
      _obj[k] = obj[k]
  }
  return _obj
}

function hash (data, enc) {
  data = (
    'string' === typeof data && enc == null
  ? new Buffer(data, 'binary')
  : new Buffer(data, enc)
  )
  return crypto.createHash('sha256').update(data).digest('base64')+'.sha256'
}

var isLink = ssbref.isLink
var isFeedId = ssbref.isFeedId

exports.hash = hash

function isObject (o) {
  return 'object' === typeof o
}

function isFunction (f) {
  return 'function' === typeof f
}

function isString(s) {
  return 'string' === typeof s
}

//crazy hack to make electron not crash
function base64ToBuffer(s) {
  var l = s.length * 6 / 8
  if(s[s.length - 2] == '=')
    l = l - 2
  else
  if(s[s.length - 1] == '=')
    l = l - 1

  var b = new Buffer(l)
  b.write(s, 'base64')
  return b
}

function toBuffer(buf) {
  if(buf == null) return buf
  if(Buffer.isBuffer(buf)) throw new Error('already a buffer')
  var i = buf.indexOf('.')
  var start = (hasSigil(buf)) ? 1 : 0
  return base64ToBuffer(buf.substring(start, ~i ? i : buf.length))
}

//function toUint8(buf) {
//  return new Uint8Array(toBuffer(buf))
//}


var curves = {}
curves.ed25519 = require('./sodium')
try { curves.k256 = require('./eccjs') }
catch (_) {}

function getCurve(keys) {
  var curve = keys.curve

  if(!keys.curve && isString(keys.public))
    keys = keys.public

  if(!curve && isString(keys))
    curve = getTag(keys)

  if(!curves[curve]) {
    throw new Error(
      'unkown curve:' + curve +
      ' expected: '+Object.keys(curves)
    )
  }

  return curve
}

//this should return a key pair:
// {curve: curve, public: Buffer, private: Buffer}

exports.generate = function (curve, seed) {
  curve = curve || 'ed25519'

  if(!curves[curve])
    throw new Error('unknown curve:'+curve)

  return u.keysToJSON(curves[curve].generate(seed), curve)
}

//import functions for loading/saving keys from storage
var FS = require('./fs')(exports.generate)
for(var key in FS) exports[key] = FS[key]

//takes a public key and a hash and returns a signature.
//(a signature must be a node buffer)

exports.sign = function (keys, msg) {
  if(isString(msg))
    msg = new Buffer(msg)
  if(!isBuffer(msg))
    throw new Error('msg should be buffer')
  var curve = getCurve(keys)

  return curves[curve]
    .sign(toBuffer(keys.private || keys), msg)
    .toString('base64')+'.sig.'+curve

}

//takes a public key, signature, and a hash
//and returns true if the signature was valid.
exports.verify = function (keys, sig, msg) {
  if(isObject(sig))
    throw new Error('signature should be base64 string, did you mean verifyObj(public, signed_obj)')
  return curves[getCurve(keys)].verify(
    toBuffer(keys.public || keys),
    toBuffer(sig),
    isBuffer(msg) ? msg : new Buffer(msg)
  )
}

// OTHER CRYTPO FUNCTIONS

exports.hmac = function (data, key) {
  return createHmac(createHash, 64, key)
    .update(data).digest('base64')+'.sha256.hmac'
}

exports.signObj = function (keys, obj) {
  var _obj = clone(obj)
  var b = new Buffer(JSON.stringify(_obj, null, 2))
  _obj.signature = exports.sign(keys, b)
  return _obj
}

exports.verifyObj = function (keys, obj) {
  obj = clone(obj)
  var sig = obj.signature
  delete obj.signature
  var b = new Buffer(JSON.stringify(obj, null, 2))
  return exports.verify(keys, sig, b)
}

exports.box = function (msg, recipients) {
  msg = new Buffer(JSON.stringify(msg))

  recipients = recipients.map(function (keys) {
    var public = keys.public || keys
    return sodium.crypto_sign_ed25519_pk_to_curve25519(toBuffer(public))
  })

  //it's since the nonce is 24 bytes (a multiple of 3)
  //it's possible to concatenate the base64 strings
  //and still have a valid base64 string.
  return pb.multibox(msg, recipients).toString('base64')+'.box'
}

exports.unbox = function (boxed, keys) {
  boxed = toBuffer(boxed)
  var sk = sodium.crypto_sign_ed25519_sk_to_curve25519(toBuffer(keys.private || keys))

  var msg = pb.multibox_open(boxed, sk)
  if(msg) return JSON.parse(''+msg)
}




