var fs         = require('fs')
var mkdirp     = require('mkdirp')
var path       = require('path')
var deepEqual  = require('deep-equal')

var crypto     = require('crypto')
var createHmac = require('hmac')
var Blake2s    = require('blake2s')

var ecc        = require('./eccjs')

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
  return new Blake2s().update(data, enc).digest('base64') + '.blake2s'
}

function isHash (data) {
  return isString(data) && /^[A-Za-z0-9\/+]{43}=\.blake2s$/.test(data)
}

function isObject (o) {
  return 'object' === typeof o
}

function isFunction (f) {
  return 'function' === typeof f
}

exports.isHash = isHash
exports.hash = hash

function isString(s) {
  return 'string' === typeof s
}

function empty(v) { return !!v }

function toBuffer(buf) {
  if(buf == null) return buf
  if(Buffer.isBuffer(buf)) throw new Error('already a buffer')
  var i = buf.indexOf('.')
  return new Buffer(buf.substring(0, ~i ? i : buf.length), 'base64')
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
    id: hash(pub)
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
  ed25519 : require('./browser-sodium'),
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

exports.sign = function (keys, hash) {
  if(isObject(hash))
    throw new Error('hash should be base64 string, did you mean signObj(private, unsigned_obj)')
  var hashTag = hash.substring(hash.indexOf('.'))
  var curve = getCurve(keys)

  return curves[curve]
    .sign(toBuffer(keys.private || keys), toBuffer(hash))
    .toString('base64')+'.blake2s.'+curve

}

//takes a public key, signature, and a hash
//and returns true if the signature was valid.
exports.verify = function (keys, sig, hash) {
  if(isObject(sig))
    throw new Error('signature should be base64 string, did you mean verifyObj(public, signed_obj)')
  return curves[getCurve(keys)].verify(
    toBuffer(keys.public || keys),
    toBuffer(sig),
    toBuffer(hash)
  )
}

// OTHER CRYTPO FUNCTIONS

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

//TODO: remove these (use asymmetric auth for everything)

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

exports.createAuth = function (keys, role) {
  return exports.signObj(keys, {
    role: role || 'client',
    ts: Date.now(),
    public: keys.public
  })
}

