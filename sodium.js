
var sodium = require('sodium').api
var crypto = require('crypto')

module.exports = {

  curves: ['ed25519'],

  generate: function () {
    var keys = sodium.crypto_sign_keypair(crypto.randomBytes(32))
    return {
      curve: 'ed25519',
      public: keys.publicKey,

      //so that this works with either sodium
      //or libsodium-wrappers (in browser)
      private: keys.privateKey || keys.secretKey
    }
  },

  sign: function (private, message) {
    return sodium.crypto_sign_detached(message, private)
  },

  verify: function (public, sig, message) {
    return sodium.crypto_sign_verify_detached(sig, message, public)
  }

}
