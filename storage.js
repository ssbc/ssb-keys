'use strict'
var fs         = require('fs')
var mkdirp     = require('mkdirp')
var path       = require('path')
var u          = require('./util')

function isObject (o) {
  return 'object' === typeof o
}

function isFunction (f) {
  return 'function' === typeof f
}

function empty(v) { return !!v }

function toFile (filename) {
  if(isObject(filename))
    return path.join(filename.path, 'secret')
  return filename
}

module.exports = function (generate) {

  if(!fs || !fs.readFile)
    return require('./local-storage')(generate)

  var exports = {}

  //(DE)SERIALIZE KEYS

  function constructKeys(keys, legacy) {
    if(!keys) throw new Error('*must* pass in keys')

    return `# WARNING: Never show this to anyone.
# WARNING: Never edit it or use it on multiple devices at once.
#
# This is your SECRET, it gives you magical powers. With your secret you can
# sign your messages so that your friends can verify that the messages came
# from you. If anyone learns your secret, they can use it to impersonate you.
#
# If you use this secret on more than one device you will create a fork and
# your friends will stop replicating your content.
#
${legacy ? keys.private : JSON.stringify(keys, null, 2)}
#
# The only part of this file that's safe to share is your public name:
#
#   ${keys.id}`
  }

  function reconstructKeys(keyfile) {
    var privateKey = keyfile
      .replace(/\s*\#[^\n]*/g, '')
      .split('\n').filter(empty).join('')

    //if the key is in JSON format, we are good.
    try {
      var keys = JSON.parse(privateKey)
      if(!u.hasSigil(keys.id)) keys.id = '@' + keys.public
      return keys
    } catch (_) { console.error(_.stack) }
  }

  exports.load = function(filename, cb) {
    filename = toFile(filename, 'secret')
    fs.readFile(filename, 'ascii', function(err, privateKeyStr) {
      if (err) return cb(err)
      var keys
      try { keys = reconstructKeys(privateKeyStr) }
      catch (err) { return cb(err) }
      cb(null, keys)
    })
  }

  exports.loadSync = function(filename) {
    filename = toFile(filename)
    return reconstructKeys(fs.readFileSync(filename, 'ascii'))
  }

  exports.create = function(filename, curve, legacy, cb) {
    if(isFunction(legacy))
      cb = legacy, legacy = null
    if(isFunction(curve))
      cb = curve, curve = null

    filename = toFile(filename)
    var keys = generate(curve)
    var keyfile = constructKeys(keys, legacy)
    mkdirp(path.dirname(filename), function (err) {
      if(err) return cb(err)
      fs.writeFile(filename, keyfile, {mode: 0x100, flag: 'wx'}, function(err) {
        if (err) return cb(err)
        cb(null, keys)
      })
    })
  }

  exports.createSync = function(filename, curve, legacy) {
    filename = toFile(filename)
    var keys = generate(curve)
    var keyfile = constructKeys(keys, legacy)
    mkdirp.sync(path.dirname(filename))
    fs.writeFileSync(filename, keyfile, {mode: 0x100, flag: 'wx'})
    return keys
  }

  return exports
}



