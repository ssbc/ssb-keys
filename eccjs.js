

var eccjs = require('eccjs')

module.exports = {

  curves: ['k256'],

  generate: function () {
    var keys = ecc.generate(crypto.randomBytes(32))
    return {
      curve: 'k256',
      public: keys.public,
      private: keys.private
    }
  },

  sign: function (private, message) {
    return ecc.sign(private, message)
  },

  verify: function (public, sig, message) {
    return ecc.verify(public, sig, message)
  }

}
