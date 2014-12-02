'use strict';

var crypto   = require('crypto')
var ecc      = require('eccjs')
var Blake2s  = require('blake2s')
var curve    = ecc.curves.k256
var createHmac = require('hmac')
var deepEqual = require('deep-equal')

function clone (obj) {
  var _obj = {}
  for(var k in obj) {
    if(Object.hasOwnProperty.call(obj, k))
      _obj[k] = obj[k]
  }
  return _obj
}

function hash (data, enc) {
  return new Blake2s().update(data, enc).digest('base64') + '.blake2s'
}


function isHash (data) {
  return isString(data) && /^[A-Za-z0-9\/+]{43}=\.blake2s$/.test(data)
}

exports.isHash = isHash
exports.hash = hash

function isString(s) {
  return 'string' === typeof s
}

function toBuffer(buf) {
  if(buf === null) return buf
  return new Buffer(buf.substring(0, buf.indexOf('.')), 'base64')
}

exports.toBuffer = toBuffer

function keysToBase64 (keys) {
  var pub = tag(keys.public, 'k256')
  return {
    public: pub,
    private: tag(keys.private, 'k256'),
    id: hash(pub)
  }
}

exports.keysToBase64 = keysToBase64

function hashToBuffer(hash) {
  if(!isHash(hash)) throw new Error('sign expects a hash')
  return toBuffer(hash)
}

function keysToBuffer(key) {
  return isString(key) ? toBuffer(key) : {
    public: toBuffer(key.public),
    private: toBuffer(key.private)
  }
}

function tag (key, tag) {
  return key.toString('base64')+'.' + tag.replace(/^\./, '')
}

// this should return a key pair:
// {public: Buffer, private: Buffer}
exports.generate = function () {
  return keysToBase64(ecc.restore(curve, crypto.randomBytes(32)))
}

//takes a public key and a hash and returns a signature.
//(a signature must be a node buffer)
exports.sign = function (keys, hash) {
  var hashTag = hash.substring(hash.indexOf('.'))
  return tag(
    ecc.sign(curve, keysToBuffer(keys), hashToBuffer(hash)),
    hashTag + '.k256'
  )
}

//takes a public key, signature, and a hash
//and returns true if the signature was valid.
exports.verify = function (pub, sig, hash) {
  return ecc.verify(curve, keysToBuffer(pub), toBuffer(sig), hashToBuffer(hash))
}

function createHash() {
  return new Blake2s()
}

exports.hmac = function (data, key) {
  return createHmac(createHash, 64, key)
    .update(data).digest('base64')+'.blake2s.hmac'
}

exports.signObj = function (keys, obj) {
  var _obj = clone(obj)
  var str = JSON.stringify(_obj, null, 2)
  var h = hash(str, 'utf8')
  _obj.signature = exports.sign(keys, h)
  return _obj
}

exports.verifyObj = function (keys, obj) {
  obj = clone(obj)
  var sig = obj.signature
  delete obj.signature
  var str = JSON.stringify(obj, null, 2)
  var h = hash(str, 'utf8')
  return exports.verify(keys, sig, h)
}

exports.signObjHmac = function (secret, obj) {
  obj = clone(obj)
  var str = JSON.stringify(obj, null, 2)
  obj.hmac = exports.hmac(str, secret)
  return obj
}

exports.verifyObjHmac = function (secret, obj) {
  obj = clone(obj)
  var hmac = obj.hmac
  delete obj.hmac
  var str = JSON.stringify(obj, null, 2)
  var _hmac = exports.hmac(str, secret)
  return deepEqual(hmac, _hmac)
}