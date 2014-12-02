'use strict';

var defaults = require('./defaults.js')
var savekey = require('./savekey')

function combine (a, b) {
  Object.keys(b).forEach(function (key) {
    a[key] = b[key]
  })

  return a
}

module.exports = combine(defaults, savekey)