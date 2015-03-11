var fs       = require('fs')
var crypto   = require('crypto')
var ecc      = require('eccjs')
var k256     = ecc.curves.k256
var Blake2s  = require('blake2s')
var mkdirp   = require('mkdirp')
var path     = require('path')
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

function isObject (o) {
  return 'object' === typeof o
}

exports.isHash = isHash
exports.hash = hash

function isString(s) {
  return 'string' === typeof s
}

function empty(v) { return !!v }

function constructKeys() {
  var privateKey = crypto.randomBytes(32)
  var k          = keysToBase64(ecc.restore(k256, privateKey))
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


function toBuffer(buf) {
  if(buf == null) return buf
  return new Buffer(buf.substring(0, buf.indexOf('.')), 'base64')
}

function keysToBase64 (keys) {
  var pub = tag(keys.public, 'k256')
  return {
    public: pub,
    private: tag(keys.private, 'k256'),
    id: hash(pub)
  }
}

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

function reconstructKeys(privateKeyStr) {
  privateKeyStr = privateKeyStr
    .replace(/\s*\#[^\n]*/g, '')
    .split('\n').filter(empty).join('')

  var privateKey = (
      !/\./.test(privateKeyStr)
    ? new Buffer(privateKeyStr, 'hex')
    : toBuffer(privateKeyStr)
  )

  return keysToBase64(ecc.restore(k256, privateKey))
}

function tag (key, tag) {
  return key.toString('base64')+'.' + tag.replace(/^\./, '')
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

exports.create = function(namefile, cb) {
  namefile = toNameFile(namefile)
  var k = constructKeys()
  mkdirp(path.dirname(namefile), function (err) {
    if(err) return cb(err)
    fs.writeFile(namefile, k.keyfile, function(err) {
      if (err) return cb(err)
      delete k.keyfile
      cb(null, k)
    })
  })
}

exports.createSync = function(namefile) {
  namefile = toNameFile(namefile)
  var k = constructKeys()
  mkdirp.sync(path.dirname(namefile))
  fs.writeFileSync(namefile, k.keyfile)
  delete k.keyfile
  return k
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

//this should return a key pair:
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

exports.createAuth = function (keys, role) {
  return ssbKeys.signObj(keys, {
    role: role || 'client',
    ts: Date.now(),
    public: keys.public
  })
}

exports.createFeed = function (ssb, keys) {
  return require('./feed')(ssb, keys, exports)
}
