
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
    id: '@'+(curve === 'ed25519' ? pub : hash(pub))
  }
}

exports.getTag = function getTag (string) {
  var i = string.indexOf('.')
  return string.substring(i+1)
}





