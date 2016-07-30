var cl     = require('chloride')

exports.hash = function (data, enc) {
  data = (
    'string' === typeof data && enc == null
  ? new Buffer(data, 'binary')
  : new Buffer(data, enc)
  )
  return cl.crypto_hash_sha256(data).toString('base64')+'.sha256'
}

exports.hasSigil = function hasSigil (s) {
  return /^(@|%|&)/.test(s)
}

function tag (key, tag) {
  if(!tag) throw new Error('no tag for:' + key.toString('base64'))
  return key.toString('base64')+'.' + tag.replace(/^\./, '')
}

exports.keysToJSON = function keysToJSON(keys, curve) {
  curve = (keys.curve || curve)

  var pub = tag(keys.public.toString('base64'), curve)
  return {
    curve: curve,
    public: pub,
    private: keys.private ? tag(keys.private.toString('base64'), curve) : undefined,
    id: '@'+(curve === 'ed25519' ? pub : exports.hash(pub))
  }
}

exports.getTag = function getTag (string) {
  var i = string.indexOf('.')
  return string.substring(i+1)
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

exports.toBuffer = function (buf) {
  if(buf == null) return buf
  if(Buffer.isBuffer(buf)) throw new Error('already a buffer')
  var i = buf.indexOf('.')
  var start = (exports.hasSigil(buf)) ? 1 : 0
  return new Buffer(buf.substring(start, ~i ? i : buf.length), 'base64')
//  return base64ToBuffer()
}

//function toUint8(buf) {
//  return new Uint8Array(toBuffer(buf))
//}




