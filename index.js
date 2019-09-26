'use strict'
var sodium     = require('chloride')
var pb         = require('private-box')
var u          = require('./util')
var isBuffer = Buffer.isBuffer

//UTILS

function clone (obj) {
  var _obj = {}
  for(var k in obj) {
    if(Object.hasOwnProperty.call(obj, k))
      _obj[k] = obj[k]
  }
  return _obj
}

var hmac = sodium.crypto_auth

exports.hash = u.hash

exports.getFeedType = u.getFeedType
exports.getTag = u.getFeedType // deprecated

function isObject (o) {
  return 'object' === typeof o
}

function isString(s) {
  return 'string' === typeof s
}

const feedTypes = {
  ed25519: require('./sodium'),
  'ed25519.test': require('./sodium')
}

exports.use = (name, object) => {
  if (typeof name !== 'string' || name.length === 0) {
    throw new Error(`Invalid name: "${name}", expected string with non-zero length`)
  }

  const requiredMethods = [
    'generate',
    'sign',
    'verify'
  ]

  const isNotObject = typeof object !== 'object'
  const isInvalidObject = isNotObject || requiredMethods.some(methodName => 
    typeof object[methodName] !== 'function'
  )

  if (isInvalidObject) {
    const expectedMethods = requiredMethods.join(', ')
    console.log(object)
    throw new Error(`Invalid object. Missing required methods, expected: ${expectedMethods}`)
  }

  if (feedTypes[name] != null) {
    throw new Error(`Duplicate feed type: "${name}"`)
  }

  feedTypes[name] = object
}

function getFeedType(keys) {
  let { feedType } = keys
  feedType = feedType || keys.curve

  if(!feedType && isString(keys.public))
    keys = keys.public

  if(!feedType && isString(keys))
    feedType = u.getFeedType(keys)

  if(!feedTypes[feedType]) {
    throw new Error(`unkown feed type: "${feedType}", expected: "${Object.keys(feedTypes)}"`)
  }

  return feedType
}

//this should return a key pair:
// { feedType: string, curve: string, public: Buffer, private: Buffer}
exports.generate = function (feedType, seed) {
  feedType = feedType || 'ed25519'

  if(feedTypes[feedType] == null)
    throw new Error(`unknown feed type: "${feedType}"`)

  return u.keysToJSON(feedTypes[feedType].generate(seed), feedType)
}

//import functions for loading/saving keys from storage
var storage = require('./storage')(exports.generate)
exports.load = storage.load
exports.loadSync = storage.loadSync
exports.create = storage.create
exports.createSync = storage.createSync


exports.loadOrCreate = function (filename, cb) {
  exports.load(filename, function (err, keys) {
    if(!err) return cb(null, keys)
    exports.create(filename, cb)
  })
}

exports.loadOrCreateSync = function (filename) {
  try {
    return exports.loadSync(filename)
  } catch (err) {
    return exports.createSync(filename)
  }
}


//takes a public key and a hash and returns a signature.
//(a signature must be a node buffer)

function sign (keys, msg) {
  if(isString(msg))
    msg = Buffer.from(msg)
  if(!isBuffer(msg))
    throw new Error('msg should be buffer')
  var feedType = getFeedType(keys)

  const prefix = feedTypes[feedType]
    .sign(u.toBuffer(keys.private || keys), msg)
    .toString('base64')
  const suffix = `.sig.${feedType}`

  return prefix + suffix

}

//takes a public key, signature, and a hash
//and returns true if the signature was valid.
function verify (keys, sig, msg) {
  if(isObject(sig))
    throw new Error('signature should be base64 string, did you mean verifyObj(public, signed_obj)')
  return feedTypes[getFeedType(keys)].verify(
    u.toBuffer(keys.public || keys),
    u.toBuffer(sig),
    isBuffer(msg) ? msg : Buffer.from(msg)
  )
}

// OTHER CRYTPO FUNCTIONS

exports.signObj = function (keys, hmac_key, obj) {
  if(!obj) obj = hmac_key, hmac_key = null
  var _obj = clone(obj)
  var b = Buffer.from(JSON.stringify(_obj, null, 2))
  if(hmac_key) b = hmac(b, u.toBuffer(hmac_key))
  _obj.signature = sign(keys, b)
  return _obj
}

exports.verifyObj = function (keys, hmac_key, obj) {
  if(!obj) obj = hmac_key, hmac_key = null
  obj = clone(obj)
  var sig = obj.signature
  delete obj.signature
  var b = Buffer.from(JSON.stringify(obj, null, 2))
  if(hmac_key) b = hmac(b, u.toBuffer(hmac_key))
  return verify(keys, sig, b)
}

exports.box = function (msg, recipients) {
  msg = Buffer.from(JSON.stringify(msg))

  recipients = recipients.map(function (keys) {
    return sodium.crypto_sign_ed25519_pk_to_curve25519(u.toBuffer(keys.public || keys))
  })

  return pb.multibox(msg, recipients).toString('base64')+'.box'
}

exports.unboxKey = function (boxed, keys) {
  boxed = u.toBuffer(boxed)
  var sk = sodium.crypto_sign_ed25519_sk_to_curve25519(u.toBuffer(keys.private || keys))
  return pb.multibox_open_key(boxed, sk)
}

exports.unboxBody = function (boxed, key) {
  if(!key) return null
  boxed = u.toBuffer(boxed)
  key = u.toBuffer(key)
  var msg = pb.multibox_open_body(boxed, key)
  try {
    return JSON.parse(''+msg)
  } catch (_) {
    return undefined
  }
}

exports.unbox = function (boxed, keys) {
  boxed = u.toBuffer(boxed)

  var sk = keys._exchangeKey || sodium.crypto_sign_ed25519_sk_to_curve25519(u.toBuffer(keys.private || keys))
  if(keys.private) keys._exchangeKey = sk //if keys is an object, cache the curve key.
  try {
    var msg = pb.multibox_open(boxed, sk)
    return JSON.parse(''+msg)
  } catch (_) {
    return undefined
  }
}

exports.secretBox = function secretBox (data, key) {
  if(!data) return
  var ptxt = Buffer.from(JSON.stringify(data))
  return sodium.crypto_secretbox_easy(ptxt, key.slice(0, 24), key)
}

exports.secretUnbox = function secretUnbox (ctxt, key) {
  var ptxt = sodium.crypto_secretbox_open_easy(ctxt, key.slice(0, 24), key)
  if(!ptxt) return
  return JSON.parse(ptxt.toString())
}
