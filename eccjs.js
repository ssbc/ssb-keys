

var ecc = require('eccjs')
var crypto = require('crypto')

var curve = ecc.curves.k256

module.exports = {

  curves: ['k256'],

  generate: function () {
    //we use eccjs.restore here, instead of eccjs.generate
    //because we trust node's random generator much more than
    //sjcl's (via crypto-browserify's polyfil this uses
    //webcrypto's random generator in the browser)

    var keys = ecc.restore(curve, crypto.randomBytes(32))

    return {
      curve: 'k256',
      public: keys.public,
      private: keys.private
    }
  },

  sign: function (private, message) {
    return ecc.sign(curve, private, message)
  },

  verify: function (public, sig, message) {
    return ecc.verify(curve, public, sig, message)
  },

  restore: function (seed) {
    return ecc.restore(curve, seed)
  }

}
