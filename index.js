var fs         = require('fs')
var mkdirp     = require('mkdirp')
var path       = require('path')
var deepEqual  = require('deep-equal')

var crypto     = require('crypto')
var createHmac = require('hmac')

var ecc        = require('./eccjs')
var sodium     = require('sodium').api
var ssbref     = require('ssb-ref')

var pb         = require('private-box')

var isBuffer = Buffer.isBuffer

function isString (s) {
  return 'string' === typeof s
}
//UTILS

function clone (obj) {
  var _obj = {}
  for(var k in obj) {
    if(Object.hasOwnProperty.call(obj, k))
      _obj[k] = obj[k]
  }
  return _obj
}

function hash (data, enc) {
  return crypto.createHash('sha256').update(data,enc).digest('base64')+'.sha256'
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

function hasSigil (s) {
  return /^(@|%|&)/.test(s)
}

function empty(v) { return !!v }

function toBuffer(buf) {
  if(buf == null) return buf
  if(Buffer.isBuffer(buf)) throw new Error('already a buffer')
  var i = buf.indexOf('.')
  var start = (hasSigil(buf)) ? 1 : 0
  return new Buffer(buf.substring(start, ~i ? i : buf.length), 'base64')
}

function toUint8(buf) {
  return new Uint8Array(toBuffer(buf))
}

function getTag (string) {
  var i = string.indexOf('.')
  return string.substring(i+1)
}

exports.getTag = getTag

function tag (key, tag) {
  if(!tag) throw new Error('no tag for:' + key.toString('base64'))
  return key.toString('base64')+'.' + tag.replace(/^\./, '')
}

function keysToJSON(keys, curve) {
  curve = (keys.curve || curve)

  var pub = tag(keys.public.toString('base64'), curve)
  return {
    curve: curve,
    public: pub,
    private: keys.private ? tag(keys.private.toString('base64'), curve) : undefined,
    id: '@'+(curve === 'ed25519' ? pub : hash(pub))
  }
}

//(DE)SERIALIZE KEYS

function constructKeys(keys, legacy) {
  if(!keys) throw new Error('*must* pass in keys') 

  return [
  '# this is your SECRET name.',
  '# this name gives you magical powers.',
  '# with it you can mark your messages so that your friends can verify',
  '# that they really did come from you.',
  '#',
  '# if any one learns this name, they can use it to destroy your identity',
  '# NEVER show this to anyone!!!',
  '',
  legacy ? keys.private : JSON.stringify(keys, null, 2),
  '',
  '# WARNING! It\'s vital that you DO NOT edit OR share your secret name',
  '# instead, share your public name',
  '# your public name: ' + keys.id
  ].join('\n')
}

function reconstructKeys(keyfile) {
  var private = keyfile
    .replace(/\s*\#[^\n]*/g, '')
    .split('\n').filter(empty).join('')

  //if the key is in JSON format, we are good.
  try {
    return JSON.parse(private)
  } catch (_) {}

  //else, reconstruct legacy curve...

  var curve = getTag(private)

  if(curve !== 'k256')
    throw new Error('expected legacy curve (k256) but found:' + curve)

  return keysToJSON(ecc.restore(toBuffer(private)), 'k256')
}

var toNameFile = exports.toNameFile = function (namefile) {
  if(isObject(namefile))
    return path.join(namefile.path, 'secret')
  return namefile
}

exports.load = function(namefile, cb) {
  namefile = toNameFile(namefile)
  fs.readFile(namefile, 'ascii', function(err, privateKeyStr) {
    if (err) return cb(err)
    try { cb(null, reconstructKeys(privateKeyStr)) }
    catch (e) { cb(err) }
  })
}

exports.loadSync = function(namefile) {
  namefile = toNameFile(namefile)
  return reconstructKeys(fs.readFileSync(namefile, 'ascii'))
}

exports.create = function(namefile, curve, legacy, cb) {
  if(isFunction(legacy))
    cb = legacy, legacy = null
  if(isFunction(curve))
    cb = curve, curve = null

  namefile = toNameFile(namefile)
  var keys = exports.generate(curve)
  var keyfile = constructKeys(keys, legacy)
  mkdirp(path.dirname(namefile), function (err) {
    if(err) return cb(err)
    fs.writeFile(namefile, keyfile, function(err) {
      if (err) return cb(err)
      cb(null, keys)
    })
  })
}

exports.createSync = function(namefile, curve, legacy) {
  namefile = toNameFile(namefile)
  var keys = exports.generate(curve)
  var keyfile = constructKeys(keys, legacy)
  mkdirp.sync(path.dirname(namefile))
  fs.writeFileSync(namefile, keyfile)
  return keys
}

exports.loadOrCreate = function (namefile, cb) {
  namefile = toNameFile(namefile)
  exports.load(namefile, function (err, keys) {
    if(!err) return cb(null, keys)
    exports.create(namefile, cb)
  })
}

exports.loadOrCreateSync = function (namefile) {
  namefile = toNameFile(namefile)
  try {
    return exports.loadSync(namefile)
  } catch (err) {
    return exports.createSync(namefile)
  }
}


// DIGITAL SIGNATURES

var curves = {
  ed25519 : require('./sodium'),
  k256    : ecc //LEGACY
}

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

  return keysToJSON(curves[curve].generate(seed), curve)
}

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
