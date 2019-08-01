'use strict'

function isFunction (f) {
  return 'function' == typeof f
}

module.exports = function (generate) {

  function create (filename, feedType, legacy) {
    var keys = generate(feedType, legacy)
    localStorage[filename] = JSON.stringify(keys)
    return keys
  }

  function load (filename) {
    return JSON.parse(localStorage[filename])
  }

  return {
    createSync: create,
    create: function(filename, feedType, legacy, cb) {
      if(isFunction(legacy))
        cb = legacy, legacy = null
      if(isFunction(feedType))
        cb = feedType, feedType = null
      cb(null, create(filename, feedType, legacy))
    },
    loadSync: load,
    load: function (filename, cb) {
      cb(null, load(filename))
    }
  }

}


